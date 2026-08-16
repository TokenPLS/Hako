package hako

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/tunnel/statistic"
)

// The driver's job is to turn decisions into actions, so what matters here is the gate: with
// shedding off, a trigger must record evidence and touch nothing; with it on, the same trigger
// must actually close connections.
//
// Report-only is the default on purpose and against upstream, which acts by default. The action
// closes every tracked connection, and the last time this tree shed on pressure the measured
// outcome was that it freed almost nothing while killing every app's session. These counters are
// what a device run produces to justify turning it on.

type pressureProbeTracker struct {
	statistic.Tracker
	id     string
	closed atomic.Int64
}

func (p *pressureProbeTracker) Close() error { p.closed.Add(1); return nil }
func (p *pressureProbeTracker) ID() string   { return p.id }

func joinPressureProbe(t *testing.T, id string) *pressureProbeTracker {
	t.Helper()
	probe := &pressureProbeTracker{id: id}
	statistic.DefaultManager.Join(probe)
	t.Cleanup(func() { statistic.DefaultManager.Leave(probe) })
	return probe
}

// withThresholdMachine installs a machine and a fixed sample, restoring the package state after.
//
// Two disciplines here, both learned from a deterministic -race failure:
// every swap of pressureThresholdSample happens under pressureThresholdMu,
// because the live poll loop reads the hook under that mutex
// (stepPressureThreshold) -- a bare assignment races it; and any monitor
// goroutine a previous test armed (Setup -> startPressureThresholdMonitor
// leaves its loop running past the test that started it) is stopped first, so
// a stray stepper can neither race the swap nor bump the shared trigger
// counters mid-assertion.
func withThresholdMachine(t *testing.T, mode thresholdMode, limit uint64, sample pressureSample, shed bool) *pressureMachine {
	t.Helper()

	machine := newPressureMachine(mode, limit)
	pressureThresholdMu.Lock()
	if pressureThresholdStop != nil {
		close(pressureThresholdStop)
		pressureThresholdStop = nil
	}
	priorMachine := pressureThresholdMachine
	priorSample := pressureThresholdSample
	priorShed := pressureThresholdShedEnabled.Load()
	pressureThresholdMachine = machine
	pressureThresholdSample = func() pressureSample { return sample }
	pressureThresholdShedEnabled.Store(shed)
	pressureThresholdMu.Unlock()

	t.Cleanup(func() {
		pressureThresholdMu.Lock()
		pressureThresholdMachine = priorMachine
		pressureThresholdSample = priorSample
		pressureThresholdMu.Unlock()
		pressureThresholdShedEnabled.Store(priorShed)
	})
	return machine
}

// setPressureSampleForTest swaps the sample hook under the same mutex the poll
// loop reads it under. Tests must use this instead of assigning the package
// variable directly.
func setPressureSampleForTest(sample func() pressureSample) {
	pressureThresholdMu.Lock()
	pressureThresholdSample = sample
	pressureThresholdMu.Unlock()
}

func TestReportOnlyRecordsTheTriggerAndKeepsConnections(t *testing.T) {
	thresholds := computeLimitThresholds(testLimit, pressureSafetyMargin)
	machine := withThresholdMachine(t, thresholdModeLimit, testLimit,
		atUsage(thresholds.trigger+1), false)
	probe := joinPressureProbe(t, "pressure-threshold-report-only")

	beforeTriggers := pressureThresholdTriggerCount.Load()
	beforeSheds := pressureThresholdShedCount.Load()

	interval := stepPressureThreshold(machine)

	if got := pressureThresholdTriggerCount.Load() - beforeTriggers; got != 1 {
		t.Fatalf("trigger count rose by %d, want 1; without the count a report-only run produces "+
			"no evidence at all", got)
	}
	if got := pressureThresholdShedCount.Load() - beforeSheds; got != 0 {
		t.Fatalf("shed count rose by %d in report-only mode", got)
	}
	if closed := probe.closed.Load(); closed != 0 {
		t.Fatalf("report-only mode closed %d connection(s)", closed)
	}
	if interval != pressureMinInterval {
		t.Fatalf("interval after a trigger = %v, want the fast rate", interval)
	}
}

func TestEnablingShedActuallyClosesConnections(t *testing.T) {
	thresholds := computeLimitThresholds(testLimit, pressureSafetyMargin)
	machine := withThresholdMachine(t, thresholdModeLimit, testLimit,
		atUsage(thresholds.trigger+1), true)
	probe := joinPressureProbe(t, "pressure-threshold-shed-on")

	beforeSheds := pressureThresholdShedCount.Load()
	stepPressureThreshold(machine)

	if got := pressureThresholdShedCount.Load() - beforeSheds; got != 1 {
		t.Fatalf("shed count rose by %d, want 1", got)
	}
	if closed := probe.closed.Load(); closed != 1 {
		t.Fatalf("the probe was closed %d time(s), want 1. If this is 0 the action is wired to "+
			"nothing and the whole option is decoration", closed)
	}
}

// TestSustainedEpisodeShedsOnceNotPerPoll is the reason the hysteresis exists, checked through the
// driver rather than the state machine: a busy process hovering near its budget must not have
// every connection closed ten times a second.
func TestSustainedEpisodeShedsOnceNotPerPoll(t *testing.T) {
	thresholds := computeLimitThresholds(testLimit, pressureSafetyMargin)
	machine := withThresholdMachine(t, thresholdModeLimit, testLimit,
		atUsage(thresholds.trigger+1), true)
	probe := joinPressureProbe(t, "pressure-threshold-sustained")

	for i := 0; i < 8; i++ {
		stepPressureThreshold(machine)
	}

	if closed := probe.closed.Load(); closed != 1 {
		t.Fatalf("eight polls of a sustained episode closed the probe %d time(s), want 1; the "+
			"trigger has to be the edge into the state, not the state", closed)
	}
}

// TestPredictedTriggersAreCountedSeparately: the two reasons need telling apart in a device
// report, because a prediction firing often means the thresholds are wrong, while a threshold
// crossing firing often means the budget is genuinely too small.
func TestPredictedTriggersAreCountedSeparately(t *testing.T) {
	machine := withThresholdMachine(t, thresholdModeLimit, testLimit, atUsage(20<<20), false)

	beforePredicted := pressureThresholdPredictedCount.Load()

	// Baseline poll well below every threshold.
	machine.notifyPressure()
	stepPressureThreshold(machine)

	// Now a reading that only a growth rate can explain.
	setPressureSampleForTest(func() pressureSample { return atUsage(39 << 20) })
	// The machine measures elapsed time from its own baseline, so give it some.
	time.Sleep(2 * pressureMinInterval)
	stepPressureThreshold(machine)

	if got := pressureThresholdPredictedCount.Load() - beforePredicted; got != 1 {
		t.Fatalf("predicted count rose by %d, want 1", got)
	}
}

// TestNotifyPressureWithNoMachineIsSafe: the OS notification can arrive before Setup arms the
// machine, or after a re-Setup replaced it. A nil dereference there would take down the extension
// during a memory episode, which is the worst possible moment.
func TestNotifyPressureWithNoMachineIsSafe(t *testing.T) {
	pressureThresholdMu.Lock()
	priorMachine, priorWake := pressureThresholdMachine, pressureThresholdWake
	pressureThresholdMachine, pressureThresholdWake = nil, nil
	pressureThresholdMu.Unlock()
	t.Cleanup(func() {
		pressureThresholdMu.Lock()
		pressureThresholdMachine, pressureThresholdWake = priorMachine, priorWake
		pressureThresholdMu.Unlock()
	})

	notifyPressureThreshold() // must not panic
}

// TestDiagnosticsExposeTheEvidence: report-only mode is worthless if the counts cannot be read off
// a device.
func TestDiagnosticsExposeTheEvidence(t *testing.T) {
	report := pressureThresholdDiagnostics()
	for _, key := range []string{
		"memoryThresholdState",
		"memoryThresholdTriggerCount",
		"memoryThresholdPredictedCount",
		"memoryThresholdShedCount",
		"memoryThresholdShedEnabled",
	} {
		if _, present := report[key]; !present {
			t.Fatalf("diagnostics omit %q; a report-only run would produce no readable evidence", key)
		}
	}
}
