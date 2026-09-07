package hako

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func testAdmissionConfig(footprint func() int64) probeAdmissionConfig {
	return probeAdmissionConfig{
		stepBytes:    4 << 20,
		ceilingBytes: 48 << 20,
		chargeTTL:    30 * time.Millisecond,
		poll:         time.Millisecond,
		maxWait:      15 * time.Millisecond,
		footprint:    footprint,
	}
}

func drainProbeAdmissionCharges(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for probeAdmissionCharges.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("charges never drained: %d", probeAdmissionCharges.Load())
		}
		time.Sleep(time.Millisecond)
	}
}

func TestProbeAdmissionAdmitsBelowCeilingAndCharges(t *testing.T) {
	defer drainProbeAdmissionCharges(t)
	cfg := testAdmissionConfig(func() int64 { return 40 << 20 })
	waited, verdict := probeAdmissionWait(context.Background(), cfg)
	if waited >= cfg.poll || verdict != probeAdmitted {
		t.Fatalf("low water must admit immediately: waited=%v verdict=%v", waited, verdict)
	}
	if got := probeAdmissionCharges.Load(); got != 1 {
		t.Fatalf("admission must charge one step, got %d", got)
	}
}

func TestProbeAdmissionChargesCountAgainstCeiling(t *testing.T) {
	defer drainProbeAdmissionCharges(t)
	cfg := testAdmissionConfig(func() int64 { return 41 << 20 })
	// 41 + 1*4 = 45 <= 48 admits; second: 41 + 2*4 = 49 > 48 must wait until
	// the first charge decays.
	if _, verdict := probeAdmissionWait(context.Background(), cfg); verdict != probeAdmitted {
		t.Fatal("first admission must not be forced")
	}
	start := time.Now()
	waited, verdict := probeAdmissionWait(context.Background(), cfg)
	if waited < cfg.poll {
		t.Fatal("second admission at charged water must wait")
	}
	if verdict == probeForced {
		// decay (30ms) lands inside maxWait (15ms)? No: 30 > 15, so this
		// admission is forced by maxWait. Accept either only if it waited.
		if time.Since(start) < cfg.maxWait {
			t.Fatal("forced admission must only happen after maxWait")
		}
	}
}

func TestProbeAdmissionWaitsUntilFootprintFalls(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		defer drainProbeAdmissionCharges(t)
		var calls atomic.Int64
		cfg := testAdmissionConfig(func() int64 {
			if calls.Add(1) >= 4 {
				return 40 << 20
			}
			return 49 << 20
		})
		waited, verdict := probeAdmissionWait(context.Background(), cfg)
		if waited < cfg.poll {
			t.Fatal("high water must wait")
		}
		if verdict != probeAdmitted {
			t.Fatal("falling footprint must admit un-forced")
		}
	})
}

func TestProbeAdmissionForcesAfterMaxWait(t *testing.T) {
	defer drainProbeAdmissionCharges(t)
	cfg := testAdmissionConfig(func() int64 { return 49 << 20 })
	start := time.Now()
	waited, verdict := probeAdmissionWait(context.Background(), cfg)
	if verdict != probeForced {
		t.Fatal("sustained high water must force-admit, never refuse")
	}
	if waited < cfg.maxWait || time.Since(start) > 2*time.Second {
		t.Fatalf("forced admission must come at maxWait, waited=%v", waited)
	}
	if got := probeAdmissionCharges.Load(); got != 1 {
		t.Fatalf("forced admission still charges, got %d", got)
	}
}

func TestProbeAdmissionDefersOnContextDone(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		defer drainProbeAdmissionCharges(t)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Millisecond)
		defer cancel()
		cfg := testAdmissionConfig(func() int64 { return 49 << 20 })
		_, verdict := probeAdmissionWait(ctx, cfg)
		if verdict != probeDeferred {
			t.Fatal("context expiry in the queue must defer — never a recorded fake timeout")
		}
		if got := probeAdmissionCharges.Load(); got != 0 {
			t.Fatalf("a deferred probe must not charge, got %d", got)
		}
	})
}

func TestProbeAdmissionSensorUnavailablePassesUncharged(t *testing.T) {
	cfg := testAdmissionConfig(func() int64 { return -1 })
	waited, verdict := probeAdmissionWait(context.Background(), cfg)
	if waited >= cfg.poll || verdict != probeAdmitted {
		t.Fatalf("no sensor must mean no pacing: waited=%v verdict=%v", waited, verdict)
	}
	if got := probeAdmissionCharges.Load(); got != 0 {
		t.Fatalf("no sensor must not charge, got %d", got)
	}
}

func TestProbeAdmissionChargeDecays(t *testing.T) {
	cfg := testAdmissionConfig(func() int64 { return 40 << 20 })
	probeAdmissionWait(context.Background(), cfg)
	drainProbeAdmissionCharges(t)
}

func TestProbeAdmissionShouldArmOnlyForNEOnBudgetedPlatform(t *testing.T) {
	cases := []struct{ budgeted, underNE, want bool }{
		{true, true, true},
		{true, false, false},
		{false, true, false},
		{false, false, false},
	}
	for _, c := range cases {
		if got := probeAdmissionShouldArm(c.budgeted, c.underNE); got != c.want {
			t.Fatalf("shouldArm(%t,%t)=%t want %t", c.budgeted, c.underNE, got, c.want)
		}
	}
}

func TestProbeAdmissionBurstSelfSerializes(t *testing.T) {
	defer drainProbeAdmissionCharges(t)
	// A same-instant burst of ten (the kernel health-check fan-out) at 40 MiB
	// must admit at most two immediately: 40 + 2*4 = 48 fits, a third would
	// need 52.
	cfg := testAdmissionConfig(func() int64 { return 40 << 20 })
	var immediate atomic.Int64
	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			waited, _ := probeAdmissionWait(context.Background(), cfg)
			if waited < cfg.poll {
				immediate.Add(1)
			}
		}()
	}
	for i := 0; i < 10; i++ {
		<-done
	}
	if got := immediate.Load(); got > 2 {
		t.Fatalf("burst must self-serialize: %d admitted immediately, want <= 2", got)
	}
}

func TestProbeAdmissionForcedExitsSerialize(t *testing.T) {
	defer drainProbeAdmissionCharges(t)
	// Sustained high water: ten stuck waiters must not stampede out together
	// at maxWait (the device kill: 300s-storm waiters force-admitted in
	// the same second, +7MB in 200ms). Forced exits are rationed: one per
	// forcedInterval.
	cfg := testAdmissionConfig(func() int64 { return 49 << 20 })
	cfg.maxWait = 10 * time.Millisecond
	cfg.forcedInterval = 40 * time.Millisecond
	var mu sync.Mutex
	var forcedAt []time.Time
	done := make(chan struct{})
	for i := 0; i < 6; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			_, verdict := probeAdmissionWait(context.Background(), cfg)
			if verdict == probeForced {
				mu.Lock()
				forcedAt = append(forcedAt, time.Now())
				mu.Unlock()
			}
		}()
	}
	for i := 0; i < 6; i++ {
		<-done
	}
	if len(forcedAt) != 6 {
		t.Fatalf("all six must eventually force out, got %d", len(forcedAt))
	}
	sort.Slice(forcedAt, func(i, j int) bool { return forcedAt[i].Before(forcedAt[j]) })
	for i := 1; i < len(forcedAt); i++ {
		if gap := forcedAt[i].Sub(forcedAt[i-1]); gap < cfg.forcedInterval*6/10 {
			t.Fatalf("forced exits %d and %d only %v apart, want >= ~%v", i-1, i, gap, cfg.forcedInterval)
		}
	}
}

func TestProbeAdmissionForcedWinnerScavengesFirst(t *testing.T) {
	defer drainProbeAdmissionCharges(t)
	var scavenges atomic.Int64
	cfg := testAdmissionConfig(func() int64 { return 49 << 20 })
	cfg.maxWait = 5 * time.Millisecond
	cfg.forcedInterval = 10 * time.Millisecond
	cfg.scavenge = func() { scavenges.Add(1) }
	if _, verdict := probeAdmissionWait(context.Background(), cfg); verdict != probeForced {
		t.Fatal("sustained high water must force")
	}
	if got := scavenges.Load(); got != 1 {
		t.Fatalf("the forced winner must scavenge once before proceeding, got %d", got)
	}
}

func TestBackgroundProbeDefersFastUnderPressure(t *testing.T) {
	cfg := testAdmissionConfig(func() int64 { return 49 << 20 })
	cfg.backgroundGrace = 8 * time.Millisecond
	start := time.Now()
	waited, verdict := probeAdmissionAdmit(context.Background(), cfg, true)
	if verdict != probeDeferred {
		t.Fatalf("background at sustained high water must defer, got %v", verdict)
	}
	if time.Since(start) > time.Second || waited < cfg.backgroundGrace {
		t.Fatalf("deferral must come at grace, waited=%v", waited)
	}
	if got := probeAdmissionCharges.Load(); got != 0 {
		t.Fatalf("a deferred probe must not charge, got %d", got)
	}
}

func TestBackgroundProbeEarnsAtLowWater(t *testing.T) {
	defer drainProbeAdmissionCharges(t)
	cfg := testAdmissionConfig(func() int64 { return 40 << 20 })
	if _, verdict := probeAdmissionAdmit(context.Background(), cfg, true); verdict != probeAdmitted {
		t.Fatalf("background at low water must earn admission, got %v", verdict)
	}
}

func TestBackgroundProbeDefersOnContextDeath(t *testing.T) {
	cfg := testAdmissionConfig(func() int64 { return 49 << 20 })
	cfg.backgroundGrace = time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Millisecond)
	defer cancel()
	if _, verdict := probeAdmissionAdmit(ctx, cfg, true); verdict != probeDeferred {
		t.Fatalf("background context death must defer, not pass through, got %v", verdict)
	}
	if got := probeAdmissionCharges.Load(); got != 0 {
		t.Fatalf("deferred must not charge, got %d", got)
	}
}

func TestProbeAdmissionCancellationWinsBeforeReservation(t *testing.T) {
	for _, sample := range []int64{-1, 40 << 20, 49 << 20} {
		t.Run(fmt.Sprint(sample), func(t *testing.T) {
			defer drainProbeAdmissionCharges(t)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			var samples, scavenges int
			beforeForced := probeAdmissionLastForcedNs.Load()
			cfg := testAdmissionConfig(func() int64 { samples++; return sample })
			cfg.scavenge = func() { scavenges++ }
			cfg.maxWait = 0
			_, verdict := probeAdmissionWait(ctx, cfg)
			if verdict != probeDeferred {
				t.Fatalf("cancelled request admitted: sample=%d verdict=%v", sample, verdict)
			}
			if got := probeAdmissionCharges.Load(); got != 0 {
				t.Fatalf("cancelled request charged %d", got)
			}
			if samples != 0 || scavenges != 0 || probeAdmissionLastForcedNs.Load() != beforeForced {
				t.Fatalf("pre-cancelled request performed work: samples=%d scavenges=%d", samples, scavenges)
			}
		})
	}
}

func TestProbeAdmissionCancellationDuringSensorDefers(t *testing.T) {
	for _, sample := range []int64{-1, 40 << 20, 49 << 20} {
		t.Run(fmt.Sprint(sample), func(t *testing.T) {
			defer drainProbeAdmissionCharges(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cfg := testAdmissionConfig(func() int64 { cancel(); return sample })
			cfg.maxWait = 0
			_, verdict := probeAdmissionWait(ctx, cfg)
			if verdict != probeDeferred {
				t.Fatalf("sensor returned after cancellation: sample=%d verdict=%v", sample, verdict)
			}
			if got := probeAdmissionCharges.Load(); got != 0 {
				t.Fatalf("cancelled sensor charged %d", got)
			}
		})
	}
}

func TestProbeAdmissionCancellationDuringScavengeDefers(t *testing.T) {
	defer drainProbeAdmissionCharges(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := testAdmissionConfig(func() int64 { return 49 << 20 })
	cfg.maxWait = 0
	cfg.scavenge = cancel
	_, verdict := probeAdmissionWait(ctx, cfg)
	if verdict != probeDeferred {
		t.Fatalf("scavenge returned after cancellation: verdict=%v", verdict)
	}
	if got := probeAdmissionCharges.Load(); got != 0 {
		t.Fatalf("cancelled scavenge charged %d", got)
	}
}
