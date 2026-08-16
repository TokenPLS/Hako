package hako

import (
	"testing"
	"time"
)

// The threshold machine is worth testing for three behaviours, and each one is a defect if it is
// missing rather than a nicety:
//
//   - the hysteresis must not flap. A footprint hovering at the trigger line, which is exactly
//     what a busy process near its budget looks like, must shed once and not once per poll.
//   - the predictor must fire before the limit. Reaching the limit on iOS is a jetsam kill, so a
//     machine that only reacts after the fact is the same as no machine.
//   - the edge must be an edge. A sustained episode has to act once; upstream reports the
//     transition into triggered, not the state.
//
// Everything is driven through step(sample, now) with an explicit clock, so none of this needs a
// device or a real timer.

const testLimit = 50 << 20 // the iOS Network Extension budget these numbers come from

func atUsage(usage uint64) pressureSample {
	return pressureSample{usage: usage}
}

func atAvailable(usage, available uint64) pressureSample {
	return pressureSample{usage: usage, available: available, availableKnown: true}
}

func TestLimitThresholdsAreOrderedAndClampToSmallLimits(t *testing.T) {
	thresholds := computeLimitThresholds(testLimit, pressureSafetyMargin)
	if !(thresholds.resume < thresholds.armed && thresholds.armed < thresholds.trigger) {
		t.Fatalf("thresholds out of order: resume=%d armed=%d trigger=%d; hysteresis needs resume "+
			"strictly below trigger or it cannot stop flapping",
			thresholds.resume, thresholds.armed, thresholds.trigger)
	}
	if thresholds.trigger != testLimit-pressureSafetyMargin {
		t.Fatalf("trigger = %d, want one margin below the limit", thresholds.trigger)
	}

	// A limit smaller than the margin must not underflow into an unreachable threshold.
	tiny := computeLimitThresholds(4<<20, pressureSafetyMargin)
	if tiny.trigger > 4<<20 {
		t.Fatalf("trigger = %d for a 4 MiB limit; the margin underflowed and the machine would "+
			"never fire", tiny.trigger)
	}
}

func TestHysteresisDoesNotFlapAtTheTriggerLine(t *testing.T) {
	machine := newPressureMachine(thresholdModeLimit, testLimit)
	thresholds := computeLimitThresholds(testLimit, pressureSafetyMargin)
	now := time.Unix(1_800_000_000, 0)

	// Cross the trigger line: one edge.
	first := machine.step(atUsage(thresholds.trigger+1), now)
	if !first.triggered || first.state != pressureStateTriggered {
		t.Fatalf("crossing the trigger line did not trigger: %+v", first)
	}

	// Hover just below the trigger but above resume, which is what a busy process near its
	// budget actually looks like. Upstream stays triggered here and must not re-fire.
	for i := 0; i < 6; i++ {
		now = now.Add(pressureMinInterval)
		step := machine.step(atUsage(thresholds.trigger-1), now)
		if step.triggered {
			t.Fatalf("re-fired on poll %d while hovering below the trigger; every fire closes "+
				"every connection, so flapping here is worse than not acting at all", i)
		}
		if step.state != pressureStateTriggered {
			t.Fatalf("left the triggered state at usage above resume (%d > %d) on poll %d; the "+
				"separate resume threshold is what prevents oscillation",
				thresholds.trigger-1, thresholds.resume, i)
		}
	}

	// Only clearing the resume threshold returns to normal.
	now = now.Add(pressureMinInterval)
	recovered := machine.step(atUsage(thresholds.resume-1), now)
	if recovered.state != pressureStateNormal {
		t.Fatalf("state = %v after dropping below resume, want normal", recovered.state)
	}
	if recovered.triggered {
		t.Fatal("recovery reported a trigger")
	}
}

func TestPredictorFiresBeforeTheLimitIsReached(t *testing.T) {
	machine := newPressureMachine(thresholdModeLimit, testLimit)
	now := time.Unix(1_800_000_000, 0)

	// Start well below the armed threshold so no threshold crossing can explain the trigger.
	thresholds := computeLimitThresholds(testLimit, pressureSafetyMargin)
	start := uint64(20 << 20)
	if start >= thresholds.armed {
		t.Fatalf("test baseline %d is not below the armed threshold %d", start, thresholds.armed)
	}

	machine.notifyPressure()
	baseline := machine.step(atUsage(start), now)
	if baseline.triggered {
		t.Fatal("the baseline poll triggered")
	}

	// Grow fast enough that the remaining headroom is consumed in well under a second: from
	// 20 MiB to 39 MiB in 100 ms is ~190 MiB/s against ~11 MiB of headroom.
	now = now.Add(pressureMinInterval)
	grown := machine.step(atUsage(39<<20), now)

	if !grown.triggered {
		t.Fatalf("a footprint growing at ~190 MiB/s with ~11 MiB of headroom did not trigger: "+
			"%+v. Reaching the limit on iOS is a jetsam kill, so reacting only after the "+
			"threshold is the same as not reacting", grown)
	}
	if !grown.predicted {
		t.Fatal("triggered, but not reported as a prediction; the distinction is what tells a " +
			"device report apart from an ordinary threshold crossing")
	}
	if grown.state != pressureStateTriggered {
		t.Fatalf("state = %v, want triggered", grown.state)
	}
}

// TestPredictorIgnoresSlowGrowth: firing on any growth at all would shed constantly on a process
// that is merely warming up.
func TestPredictorIgnoresSlowGrowth(t *testing.T) {
	machine := newPressureMachine(thresholdModeLimit, testLimit)
	now := time.Unix(1_800_000_000, 0)

	machine.notifyPressure()
	machine.step(atUsage(18<<20), now)

	// 1 MiB over a full second against ~26 MiB of headroom: 26 seconds away.
	now = now.Add(time.Second)
	step := machine.step(atUsage(19<<20), now)
	if step.triggered {
		t.Fatalf("slow growth triggered: %+v. Twenty-six seconds of headroom is not an emergency", step)
	}
}

// TestAvailableModeThresholdsAreInverted: macOS has no budget, so the machine watches the
// MACHINE's free memory. Getting the comparison direction wrong would make it fire when memory is
// plentiful and stay quiet when it runs out.
func TestAvailableModeThresholdsAreInverted(t *testing.T) {
	machine := newPressureMachine(thresholdModeAvailable, 0)
	now := time.Unix(1_800_000_000, 0)

	plenty := machine.step(atAvailable(200<<20, 8<<30), now)
	if plenty.state != pressureStateNormal {
		t.Fatalf("8 GiB free read as %v; the comparison is inverted", plenty.state)
	}

	now = now.Add(pressureMaxInterval)
	scarce := machine.step(atAvailable(200<<20, 8<<20), now)
	if scarce.state != pressureStateTriggered || !scarce.triggered {
		t.Fatalf("8 MiB free read as %v (triggered=%v); this is the case the mode exists for",
			scarce.state, scarce.triggered)
	}
}

// TestAvailableModeStaysQuietWithoutAReading: availableMemory returns -1 off darwin. Treating
// "unknown" as "zero available" would trigger permanently on every non-Apple build.
func TestAvailableModeStaysQuietWithoutAReading(t *testing.T) {
	machine := newPressureMachine(thresholdModeAvailable, 0)
	now := time.Unix(1_800_000_000, 0)
	for i := 0; i < 4; i++ {
		step := machine.step(atUsage(200<<20), now) // availableKnown false
		if step.state != pressureStateNormal || step.triggered {
			t.Fatalf("an unknown available reading produced %v (triggered=%v) on poll %d",
				step.state, step.triggered, i)
		}
		now = now.Add(pressureMaxInterval)
	}
}

func TestModeResolutionMatchesUpstreamPrecedence(t *testing.T) {
	cases := []struct {
		name      string
		softLimit int64
		available int64
		want      thresholdMode
		why       string
	}{
		{
			name: "a configured limit wins", softLimit: 50 << 20, available: 8 << 30,
			want: thresholdModeLimit,
			why:  "the iOS profiles carry the jetsam-derived budget and must threshold on their own footprint",
		},
		{
			name: "no limit but a readable machine", softLimit: 0, available: 8 << 30,
			want: thresholdModeAvailable,
			why:  "the macOS profiles never set a soft limit, exactly as upstream reaches for its NE regime only under C.IsIos",
		},
		{
			name: "neither", softLimit: 0, available: -1,
			want: thresholdModeNone,
			why:  "nothing measurable; guessing would be worse than idling",
		},
		{
			name: "a negative limit is not a limit", softLimit: -1, available: -1,
			want: thresholdModeNone,
			why:  "an unset int64 must not be read as a one-byte budget",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := resolveThresholdMode(testCase.softLimit, testCase.available); got != testCase.want {
				t.Fatalf("mode = %v, want %v — %s", got, testCase.want, testCase.why)
			}
		})
	}
}

// TestIntervalBacksOffAndSnapsBack: the interval is the whole cost of running this machine. It has
// to reach the slow rate when nothing is happening and be at the fast rate the moment it matters.
func TestIntervalBacksOffAndSnapsBack(t *testing.T) {
	machine := newPressureMachine(thresholdModeLimit, testLimit)
	now := time.Unix(1_800_000_000, 0)

	// Quiet: back off to the maximum and stay there.
	var interval time.Duration
	for i := 0; i < 8; i++ {
		interval = machine.step(atUsage(10<<20), now).interval
		now = now.Add(interval)
	}
	if interval != pressureMaxInterval {
		t.Fatalf("quiet interval settled at %v, want %v", interval, pressureMaxInterval)
	}

	// Armed: the middle rate.
	thresholds := computeLimitThresholds(testLimit, pressureSafetyMargin)
	armed := machine.step(atUsage(thresholds.armed+1), now)
	if armed.state != pressureStateArmed {
		t.Fatalf("state = %v, want armed", armed.state)
	}
	if armed.interval != pressureArmedInterval {
		t.Fatalf("armed interval = %v, want %v", armed.interval, pressureArmedInterval)
	}

	// Triggered: the fast rate.
	now = now.Add(armed.interval)
	triggered := machine.step(atUsage(thresholds.trigger+1), now)
	if triggered.interval != pressureMinInterval {
		t.Fatalf("triggered interval = %v, want %v", triggered.interval, pressureMinInterval)
	}

	// What a pressure notification does to the interval is subtle enough that I got it wrong
	// writing this test, so it is pinned in both directions.
	//
	// Upstream's poll() clears forceMinInterval as soon as the reading resolves to normal, and
	// only THEN computes the interval. So a notification followed by a quiet reading does NOT
	// hold the fast rate -- it backs off like any other quiet poll. The flag's real effect is on
	// an ARMED reading, where it overrides the one-second armed rate with the fast rate.
	//
	// That is the sensible reading of the hint: the OS says the machine is short of memory, so
	// while our own numbers still look elevated, watch closely; once they look normal, the
	// episode was someone else's and there is nothing to watch.

	// Quiet after a notification: backs off rather than holding the fast rate.
	machine.notifyPressure()
	now = now.Add(pressureMinInterval)
	quiet := machine.step(atUsage(10<<20), now)
	if quiet.state != pressureStateNormal {
		t.Fatalf("state = %v after a quiet reading, want normal", quiet.state)
	}
	if quiet.interval == pressureMinInterval {
		t.Fatal("held the fast rate on a quiet reading after a notification; upstream clears the " +
			"force flag as soon as the state resolves to normal, so this would poll ten times " +
			"faster than upstream for as long as notifications keep arriving")
	}

	// Armed after a notification: the flag overrides the armed rate with the fast one.
	machine.notifyPressure()
	now = now.Add(quiet.interval)
	hinted := machine.step(atUsage(thresholds.armed+1), now)
	if hinted.state != pressureStateArmed {
		t.Fatalf("state = %v, want armed", hinted.state)
	}
	if hinted.interval != pressureMinInterval {
		t.Fatalf("interval = %v on an armed reading after a notification, want %v — this is the "+
			"only case where the force flag changes anything", hinted.interval, pressureMinInterval)
	}
}

// TestNoneModeIsInert: a build with neither signal must not spin.
func TestNoneModeIsInert(t *testing.T) {
	machine := newPressureMachine(thresholdModeNone, 0)
	step := machine.step(atUsage(1<<30), time.Unix(1_800_000_000, 0))
	if step.triggered || step.state != pressureStateNormal {
		t.Fatalf("none mode acted: %+v", step)
	}
	if step.interval != pressureMaxInterval {
		t.Fatalf("none mode interval = %v, want the slowest rate", step.interval)
	}
}

// TestZeroHeadroomIsNotAReading is the landmine this design nearly shipped with.
//
// os_proc_available_memory() returns 0 for a process with no memory limit, which is every
// ordinary macOS process -- the symbol resolves there, it simply has nothing to report. Reading
// that 0 as "zero bytes left" makes the machine compare 0 against a 32 MiB trigger, so it fires
// on the first poll and never recovers; with shedding enabled it would close every tracked
// connection on a loop, forever, on a machine with tens of gigabytes free.
//
// Measured on this Mac before the fix: availableMemory() resolved, returned 0, and the mode
// resolved to "available" with the trigger already crossed by 32 MiB.
func TestZeroHeadroomIsNotAReading(t *testing.T) {
	if got := resolveThresholdMode(0, 0); got != thresholdModeNone {
		t.Fatalf("mode for a zero headroom reading = %v, want none. Zero means 'no limit' from "+
			"os_proc_available_memory, and treating it as a reading fires the trigger permanently", got)
	}
	if got := resolveThresholdMode(0, -1); got != thresholdModeNone {
		t.Fatalf("mode for an unavailable reading = %v, want none", got)
	}
	if got := resolveThresholdMode(0, 1); got != thresholdModeAvailable {
		t.Fatalf("mode for a positive headroom reading = %v, want available", got)
	}

	// And the sampler must not mark a zero as known, or the mode check above gets bypassed by a
	// machine that was armed while a limit existed and later lost it.
	machine := newPressureMachine(thresholdModeAvailable, 0)
	step := machine.step(pressureSample{usage: 200 << 20, available: 0, availableKnown: false}, timeUnix())
	if step.triggered || step.state != pressureStateNormal {
		t.Fatalf("an unknown headroom produced %+v; the available mode must stay quiet without a "+
			"reading rather than treating absence as exhaustion", step)
	}
}

func timeUnix() time.Time { return time.Unix(1_800_000_000, 0) }
