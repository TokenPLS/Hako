package hako

import (
	"fmt"
	"time"
)

// The memory pressure threshold machine, ported from sing-box's service/oomkiller.
//
// Upstream splits memory handling in two, and the split is the design. The XNU pressure
// notification does NOT act: it logs, writes a throttled OOM draft, and pokes this machine into
// fast-poll mode with a fresh growth baseline (timer_darwin.go notifyPressure). A device-wide
// notification says nothing about who is holding the memory, so acting on it kills every app's
// sessions to reclaim, typically, nothing.
//
// This machine is what acts, on its own measurements. It polls, keeps a three-state hysteresis
// (normal / armed / triggered) with a SEPARATE resume threshold so it cannot flap at a boundary,
// scales its own poll interval, and predicts: if the footprint is growing fast enough to reach
// the limit before the next poll, it triggers early rather than watching the process get killed.
//
// Every constant and comparison here matches upstream. The one deliberate difference is that
// firing is opt-in -- see shedOnTrigger in the driver -- because a machine that closes every
// connection should be observed on real devices before it is allowed to act.
//
// What upstream does on trigger is NetworkManager.ResetNetwork, whose first statement is
// connectionManager.CloseAll (route/network.go). So "sing-box never sheds" was wrong; it never
// sheds from the notification.

// Upstream's values, from service/oomkiller/timer.go.
const (
	pressureMinInterval   = 100 * time.Millisecond
	pressureArmedInterval = time.Second
	pressureMaxInterval   = 10 * time.Second

	// pressureSafetyMargin is the unit the limit thresholds are built from: trigger one margin
	// below the limit, armed two, resume four.
	pressureSafetyMargin = 5 * 1024 * 1024

	// Headroom margins for the available mode. Both sides of that comparison are per-process --
	// os_proc_available_memory reports OUR remaining headroom, not the machine's free memory --
	// which is why the margin scales off our own footprint between these bounds.
	pressureAvailableMarginMin = 32 * 1024 * 1024
	pressureAvailableMarginMax = 128 * 1024 * 1024
)

type pressureState uint8

const (
	pressureStateNormal pressureState = iota
	pressureStateArmed
	pressureStateTriggered
)

func (s pressureState) String() string {
	switch s {
	case pressureStateNormal:
		return "normal"
	case pressureStateArmed:
		return "armed"
	case pressureStateTriggered:
		return "triggered"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(s))
	}
}

// thresholdMode mirrors upstream's policyMode. resolvePolicyMode there keys on
// C.IsIos && UnderNetworkExtension() for the Network Extension regime and falls through to the
// available-headroom mode otherwise, which is why a macOS provider is NOT on the iOS budget.
type thresholdMode uint8

const (
	// thresholdModeNone: nothing measurable to threshold on. The machine stays idle rather
	// than guessing.
	thresholdModeNone thresholdMode = iota
	// thresholdModeLimit: a configured soft limit exists, so threshold on our own footprint.
	thresholdModeLimit
	// thresholdModeAvailable: no configured limit, but the platform reports a positive
	// per-process headroom, so threshold on that.
	thresholdModeAvailable
)

func (m thresholdMode) String() string {
	switch m {
	case thresholdModeLimit:
		return "limit"
	case thresholdModeAvailable:
		return "available"
	default:
		return "none"
	}
}

// pressureSample is one reading. usage is this process's physical footprint -- the number iOS
// jetsam actually counts -- and available is this process's remaining headroom, which is only
// positive where the platform imposes a limit.
type pressureSample struct {
	usage          uint64
	available      uint64
	availableKnown bool
}

type pressureThresholds struct {
	trigger uint64
	armed   uint64
	resume  uint64
}

// resolveThresholdMode mirrors resolvePolicyMode: a configured limit wins, otherwise fall back to
// the platform's headroom reading, otherwise do nothing.
//
// The available reading must be strictly POSITIVE. os_proc_available_memory() returns 0 for a
// process with no memory limit, which is every ordinary macOS process, and treating that as
// "zero bytes free" would fire the trigger permanently. So an unlimited process resolves to
// thresholdModeNone, which is the right answer: there is no budget to threshold against.
//
// In practice that means this machine is meaningful on iOS and iPadOS, where a Network Extension
// carries a jetsam-derived budget, and correctly idle on macOS, which has no such budget at all.
// Upstream has the same property for the same reason -- its darwin memory.Available() is the same
// per-process call -- it just never notices because its OOM killer is an opt-in service.
func resolveThresholdMode(softLimit int64, available int64) thresholdMode {
	if softLimit > 0 {
		return thresholdModeLimit
	}
	if available > 0 {
		return thresholdModeAvailable
	}
	return thresholdModeNone
}

// computeLimitThresholds is upstream's function of the same name.
//
// min() against the limit matters on a small budget: without it a 4 MiB limit against a 5 MiB
// margin would underflow to an enormous trigger threshold that never fires.
func computeLimitThresholds(limit, safetyMargin uint64) pressureThresholds {
	triggerMargin := min(safetyMargin, limit)
	armedMargin := min(triggerMargin*2, limit)
	resumeMargin := min(triggerMargin*4, limit)
	return pressureThresholds{
		trigger: limit - triggerMargin,
		armed:   limit - armedMargin,
		resume:  limit - resumeMargin,
	}
}

// computeAvailableThresholds is upstream's availableThresholds. The comparisons that use it are
// INVERTED relative to the limit mode -- less available memory is worse -- which is why the two
// modes cannot share a comparison helper.
func computeAvailableThresholds(sample pressureSample) pressureThresholds {
	var triggerMargin uint64
	switch {
	case sample.usage == 0:
		triggerMargin = pressureAvailableMarginMin
	default:
		triggerMargin = max(pressureAvailableMarginMin, min(sample.usage/4, pressureAvailableMarginMax))
	}
	return pressureThresholds{
		trigger: triggerMargin,
		armed:   triggerMargin * 2,
		resume:  triggerMargin * 4,
	}
}

// nextPressureState is upstream's function of the same name: the hysteresis itself.
//
// The triggered branch is the whole point. Once triggered, the machine stays triggered until the
// reading clears the RESUME threshold -- four margins away, not one -- so a footprint hovering at
// the trigger line cannot oscillate and shed repeatedly.
func nextPressureState(current pressureState, shouldTrigger, shouldArm, shouldStayTriggered bool) pressureState {
	if current == pressureStateTriggered {
		if shouldStayTriggered {
			return pressureStateTriggered
		}
		return pressureStateNormal
	}
	if shouldTrigger {
		return pressureStateTriggered
	}
	if shouldArm {
		return pressureStateArmed
	}
	return pressureStateNormal
}

// pressureMachine holds the polling state. It is deliberately free of clocks, samplers and
// logging so the whole decision surface is testable without a device: step() takes the reading
// and the time and returns what to do.
type pressureMachine struct {
	mode  thresholdMode
	limit uint64

	state            pressureState
	currentInterval  time.Duration
	forceMinInterval bool

	// triggeredExitFloor is the usage below which the triggered state ends,
	// set at each edge into triggered. For a threshold-crossing trigger it is
	// the resume threshold, upstream's own hysteresis. A PREDICTED trigger
	// can fire at any usage, including below the resume threshold; without a
	// floor pinned at that usage the very next poll un-latches the state and
	// the predictor re-fires -- trigger, normal, trigger, at poll rate --
	// which is exactly the once-per-episode promise broken from a second
	// direction.
	triggeredExitFloor uint64

	pendingBaseline bool
	baseline        pressureSample
	baselineAt      time.Time
}

// pressureDecision is what one step concluded.
type pressureDecision struct {
	state    pressureState
	interval time.Duration
	// triggered is true only on the EDGE into triggered, so a sustained episode acts once
	// rather than on every poll.
	triggered bool
	// predicted distinguishes "we crossed the threshold" from "we are about to", because the
	// second one is the interesting log line and the one worth measuring on a device.
	predicted bool
}

func newPressureMachine(mode thresholdMode, limit uint64) *pressureMachine {
	return &pressureMachine{mode: mode, limit: limit}
}

// notifyPressure is what the OS notification does: wake into fast polling and take a fresh
// growth baseline. It never decides anything by itself -- upstream's notifyPressure ends by
// calling poll(), and the caller here does the same.
func (m *pressureMachine) notifyPressure() {
	m.forceMinInterval = true
	m.pendingBaseline = true
}

// step advances the machine by one reading.
func (m *pressureMachine) step(sample pressureSample, now time.Time) pressureDecision {
	if m.mode == thresholdModeNone {
		return pressureDecision{state: pressureStateNormal, interval: pressureMaxInterval}
	}

	if m.pendingBaseline {
		m.baseline = sample
		m.baselineAt = now
		m.pendingBaseline = false
	}

	previous := m.state
	m.state = m.nextState(sample)
	if m.state == pressureStateNormal {
		m.forceMinInterval = false
		// A stale baseline would keep producing growth rates from an episode that ended.
		if !m.baselineAt.IsZero() && now.Sub(m.baselineAt) > pressureMaxInterval {
			m.baselineAt = time.Time{}
		}
	}

	decision := pressureDecision{
		triggered: previous != pressureStateTriggered && m.state == pressureStateTriggered,
	}
	if decision.triggered {
		m.triggeredExitFloor = 0 // a threshold crossing latches on the plain resume line
	}

	// The predictor, upstream's rate-triggered branch. Only meaningful against a known limit:
	// there is no "time to limit" when the threshold is the machine's free memory.
	// m.state != triggered keeps the promise the decision documents: triggered fires on the
	// EDGE only. Without it a sustained growing episode re-enters here every poll -- the
	// machine is already triggered, the edge flag is false, the rate is still positive --
	// and re-raises the flag at up to ten sheds a second.
	if !decision.triggered && m.state != pressureStateTriggered && m.mode == thresholdModeLimit && m.limit > 0 &&
		!m.baselineAt.IsZero() && sample.usage > m.baseline.usage && sample.usage < m.limit {
		elapsed := now.Sub(m.baselineAt)
		if elapsed >= pressureMinInterval/2 {
			growth := sample.usage - m.baseline.usage
			ratePerSecond := float64(growth) / elapsed.Seconds()
			if ratePerSecond > 0 {
				headroom := m.limit - sample.usage
				// Upstream truncates to whole seconds here (Duration(float64) * Second),
				// which makes the predictor slightly conservative: any time-to-limit under
				// one second reads as zero and fires. Kept as-is rather than "fixed",
				// because firing early is the safe direction and divergence is not.
				timeToLimit := time.Duration(float64(headroom)/ratePerSecond) * time.Second
				if timeToLimit < pressureMinInterval {
					m.state = pressureStateTriggered
					decision.triggered = true
					decision.predicted = true
					// Latch below the usage that predicted the death, or the
					// resume line, whichever is lower: the episode is over
					// when the growth actually reversed, not one poll later.
					m.triggeredExitFloor = sample.usage
				}
			}
		}
	}

	decision.state = m.state
	decision.interval = m.intervalForState()
	return decision
}

// nextState applies the thresholds for the active mode.
func (m *pressureMachine) nextState(sample pressureSample) pressureState {
	switch m.mode {
	case thresholdModeLimit:
		thresholds := computeLimitThresholds(m.limit, pressureSafetyMargin)
		stayFloor := thresholds.resume
		if m.state == pressureStateTriggered && m.triggeredExitFloor > 0 && m.triggeredExitFloor < stayFloor {
			stayFloor = m.triggeredExitFloor
		}
		return nextPressureState(m.state,
			sample.usage >= thresholds.trigger,
			sample.usage >= thresholds.armed,
			sample.usage >= stayFloor,
		)
	case thresholdModeAvailable:
		if !sample.availableKnown {
			return pressureStateNormal
		}
		thresholds := computeAvailableThresholds(sample)
		return nextPressureState(m.state,
			sample.available <= thresholds.trigger,
			sample.available <= thresholds.armed,
			sample.available <= thresholds.resume,
		)
	default:
		return pressureStateNormal
	}
}

// intervalForState is upstream's function of the same name: fast while it matters, backing off
// to a tenth of a poll per second when nothing is happening.
func (m *pressureMachine) intervalForState() time.Duration {
	switch {
	case m.forceMinInterval || m.state == pressureStateTriggered:
		m.currentInterval = pressureMinInterval
	case m.state == pressureStateArmed:
		m.currentInterval = pressureArmedInterval
	default:
		if m.currentInterval == 0 {
			m.currentInterval = pressureMaxInterval
		} else {
			m.currentInterval = min(m.currentInterval*2, pressureMaxInterval)
		}
	}
	return m.currentInterval
}
