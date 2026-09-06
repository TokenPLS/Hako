package hako

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/TokenPLS/Hako/log"
	"github.com/TokenPLS/Hako/tunnel/statistic"
)

// The polling driver for the threshold machine. All decisions live in memory_threshold.go; this
// file only supplies the clock, the readings, the logging and the action.
//
// Firing now defaults to acting, as upstream's does. It began as opt-in -- report-only -- because
// the action is closing every tracked connection and the thresholds had never run against a real
// device's memory behaviour in this codebase (an earlier version shed on every OS notification
// and freed almost nothing while killing every app's session). Report-only existed to produce the
// numbers that would justify turning it on, and three rounds of device evidence produced them:
// nineteen triggers, three jetsam kills, zero sheds -- the machine saw every death coming and was
// allowed to do nothing. The report-only branch remains for observability and tests.

var (
	// pressureThresholdStartMu serializes whole monitor replacements
	// (stop old, join it, install new). pressureThresholdMu alone guards the
	// data; without this outer lock two concurrent re-arms could double-close
	// the same stop channel or leave two loops alive. Order: startMu, then
	// pressureThresholdMu; never the reverse.
	pressureThresholdStartMu sync.Mutex

	pressureThresholdMu      sync.Mutex
	pressureThresholdMachine *pressureMachine
	pressureThresholdWake    chan struct{}
	pressureThresholdStop    chan struct{}
	pressureThresholdExited  chan struct{}

	// pressureThresholdShedEnabled gates the action. Read atomically because the poll loop and
	// Setup touch it from different goroutines.
	pressureThresholdShedEnabled atomic.Bool

	// Counters for the diagnostics surface. The point of report-only mode is that these are the
	// evidence: how often the machine WOULD have acted, and how often it predicted rather than
	// reacted.
	pressureThresholdTriggerCount   atomic.Uint64
	pressureThresholdPredictedCount atomic.Uint64
	pressureThresholdShedCount      atomic.Uint64
	pressureThresholdStateGauge     atomic.Uint32

	// Injectable for tests; the real driver reads the live process.
	pressureThresholdSample = livePressureSample
	pressureThresholdShed   = closeTrackedConnectionsForPressure
)

func livePressureSample() pressureSample {
	sample := pressureSample{}
	if footprint := MemoryFootprint(); footprint > 0 {
		sample.usage = uint64(footprint)
	}
	// Strictly positive: a 0 from os_proc_available_memory means "no limit", not "nothing left".
	// See availableMemory's documentation.
	if available := availableMemory(); available > 0 {
		sample.available = uint64(available)
		sample.availableKnown = true
	}
	return sample
}

func closeTrackedConnectionsForPressure() int {
	closed := 0
	statistic.DefaultManager.Range(func(tracker statistic.Tracker) bool {
		_ = tracker.Close()
		closed++
		return true
	})
	return closed
}

// startPressureThresholdMonitor arms the poller. Safe to call more than once; a second call
// replaces the machine, which is what a re-Setup wants.
func startPressureThresholdMonitor(softLimit int64, shedEnabled bool) {
	pressureThresholdStartMu.Lock()
	defer pressureThresholdStartMu.Unlock()

	pressureThresholdMu.Lock()
	priorStop, priorExited := pressureThresholdStop, pressureThresholdExited
	pressureThresholdMu.Unlock()
	if priorStop != nil {
		close(priorStop)
		// Join the old loop before installing the new machine. Without the
		// wait, a timer or a captured wake that raced the stop lets the old
		// loop take one more step -- reading the new shed flag, double-writing
		// the gauges, possibly shedding twice. The wait happens outside the
		// mutex: the old loop's step needs pressureThresholdMu to finish.
		<-priorExited
	}
	pressureThresholdMu.Lock()
	mode := resolveThresholdMode(softLimit, availableMemory())
	limit := uint64(0)
	if softLimit > 0 {
		limit = uint64(softLimit)
	}
	pressureThresholdMachine = newPressureMachine(mode, limit)
	pressureThresholdWake = make(chan struct{}, 1)
	pressureThresholdStop = make(chan struct{})
	pressureThresholdExited = make(chan struct{})
	wake, stop, machine, exited := pressureThresholdWake, pressureThresholdStop, pressureThresholdMachine, pressureThresholdExited
	pressureThresholdShedEnabled.Store(shedEnabled)
	pressureThresholdMu.Unlock()

	if mode == thresholdModeNone {
		// No loop runs for an idle machine, so the join channel must already
		// read as exited or the next replacement would wait forever.
		close(pressureThresholdExited)
		log.Infoln("[Memory] threshold monitor idle: neither a soft limit nor an available-memory reading")
		return
	}
	log.Infoln("[Memory] threshold monitor armed (mode=%s limit=%d shed=%v)", mode, limit, shedEnabled)

	go runPressureThresholdLoop(machine, wake, stop, exited)
}

func runPressureThresholdLoop(machine *pressureMachine, wake <-chan struct{}, stop <-chan struct{}, exited chan<- struct{}) {
	defer close(exited)
	timer := time.NewTimer(pressureMaxInterval)
	defer timer.Stop()
	for {
		select {
		case <-stop:
			return
		case <-wake:
		case <-timer.C:
		}
		interval := stepPressureThreshold(machine)
		if !timer.Stop() {
			// Drain a fire that raced the Stop, otherwise the next wait returns immediately.
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(interval)
	}
}

// stepPressureThreshold is one poll, split out so tests drive it without a timer.
func stepPressureThreshold(machine *pressureMachine) time.Duration {
	pressureThresholdMu.Lock()
	decision := machine.step(pressureThresholdSample(), time.Now())
	pressureThresholdMu.Unlock()

	pressureThresholdStateGauge.Store(uint32(decision.state))
	if !decision.triggered {
		return decision.interval
	}

	pressureThresholdTriggerCount.Add(1)
	if decision.predicted {
		pressureThresholdPredictedCount.Add(1)
	}

	if !pressureThresholdShedEnabled.Load() {
		log.Warnln(
			"[Memory] threshold %s (report only, predicted=%v): connections kept. This is the "+
				"count that decides whether shedding is worth enabling",
			decision.state, decision.predicted)
		return decision.interval
	}

	closed := pressureThresholdShed()
	pressureThresholdShedCount.Add(1)
	log.Warnln("[Memory] threshold %s (predicted=%v): closed %d tracked connection(s)",
		decision.state, decision.predicted, closed)
	return decision.interval
}

// notifyPressureThreshold is called from the OS pressure notification. It is upstream's
// notifyPressure: force fast polling, take a fresh growth baseline, poll now.
func notifyPressureThreshold() {
	pressureThresholdMu.Lock()
	machine, wake := pressureThresholdMachine, pressureThresholdWake
	if machine != nil {
		machine.notifyPressure()
	}
	pressureThresholdMu.Unlock()

	if wake == nil {
		return
	}
	select {
	case wake <- struct{}{}:
	default:
		// A poll is already pending; the flags are set and it will see them.
	}
}

// pressureThresholdDiagnostics is the evidence report-only mode exists to produce.
func pressureThresholdDiagnostics() map[string]any {
	return map[string]any{
		"memoryThresholdState":          pressureState(pressureThresholdStateGauge.Load()).String(),
		"memoryThresholdTriggerCount":   pressureThresholdTriggerCount.Load(),
		"memoryThresholdPredictedCount": pressureThresholdPredictedCount.Load(),
		"memoryThresholdShedCount":      pressureThresholdShedCount.Load(),
		"memoryThresholdShedEnabled":    pressureThresholdShedEnabled.Load(),
	}
}
