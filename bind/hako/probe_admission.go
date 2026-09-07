package hako

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/TokenPLS/Hako/adapter"
	"github.com/TokenPLS/Hako/log"
)

// Probe admission pacing.
//
// Every URL test that establishes a connection — dead-at-dial probes do not —
// walks an allocation string whose pages can touch one fresh Go heap arena.
// On device that is a 2.5–4.4 MiB phys_footprint step that the scavenger
// returns within about a second (three iPhones, 1 Hz footprint traces,
// 2026-08-26). Two such steps in the same second on a ~42 MiB resident
// baseline cross the ~50 MiB Network Extension jetsam wall; the killers are
// concurrent probes: the App's sweep workers, and the kernel's own provider
// health checks (10 per provider, three providers same-second at startup).
//
// The gate sits on the single choke point every probe shares
// (adapter.Proxy.urlTest, armed via adapter.SetURLTestAdmission) and paces
// rather than refuses: a probe above the admit line waits for the scavenger
// to hand pages back, and is eligible for a rationed forced admission after
// maxWait. Context cancellation defers without recording a probe result. Each
// admission charges one presumed arena step against the line for chargeTTL —
// the measured lifetime of a step — so a same-second burst self-serializes
// even before the footprint sensor can see the first touch.
const (
	// Charge per admitted probe. First priced at the largest measured
	// single-second step (4.5 MiB); the worker ladder (2026-08-26, mini,
	// w2..w16) showed sustained churn reuses arenas — peak footprint stayed
	// <= 43.7 MB at every rung under the old price while gate waits, not
	// memory, throttled the sweep — so the charge is the sustained marginal
	// cost, not the worst single step. The forced ration, the pre-forced
	// scavenge and the threshold machine still cover the outlier.
	probeAdmissionStepBytes = int64(3145728) // 3 MiB
	// Admit line: the 50 MiB jetsam budget minus one worst-case step (4.5
	// MiB, which a charged probe may still take even though the sustained
	// price below is 3) rounded to a whole MiB of margin — the ladder's
	// worst peak under the old line was 43.7.
	probeAdmissionCeilingBytes = int64(49283072) // 47 MiB
	// How long one admission counts against the line — the measured time the
	// scavenger takes to return a step's pages.
	probeAdmissionChargeTTL = time.Second
	probeAdmissionPoll      = 100 * time.Millisecond
	// After maxWait a stuck waiter becomes eligible for a forced exit. Forced
	// exits are rationed (one per forcedInterval) and the winner scavenges
	// first: on device, ten storm waiters hitting their own 3s deadline in
	// the same second force-admitted together and put +7MB on a 43MB
	// footprint in 200ms. A sustained
	// plateau therefore degrades to slow pacing, never to refusal and never
	// to a stampede.
	probeAdmissionMaxWait        = 3 * time.Second
	probeAdmissionForcedInterval = time.Second
	// How long a background health check may wait for an earned slot before
	// this round is skipped for it.
	probeAdmissionBackgroundGrace = 300 * time.Millisecond
)

// probeAdmissionVerdict says how a probe left the gate.
type probeAdmissionVerdict uint8

const (
	// probeAdmitted: the reservation fit under the ceiling (charged).
	probeAdmitted probeAdmissionVerdict = iota
	// probeForced: waited past maxWait and won a rationed forced exit
	// (charged, after a synchronous scavenge).
	probeForced
	// probeCtxExpired is retired (was verdict=2): a probe whose context died
	// in the queue used to pass through and be recorded as a timeout — a
	// fake result. Both classes now defer instead. The constant remains so
	// verdict numbering in device logs stays stable.
	probeCtxExpired
	// probeDeferred: the gate skipped this probe without a recorded result.
	// Background probes defer at their 300ms grace; any probe defers when
	// its own context dies while queuing. The caller returns
	// adapter.ErrURLTestDeferred before any bookkeeping, the node keeps its
	// last known state, and the App can requeue interactive ones ( v4:
	// truthfulness must not depend on picking the right worker count).
	probeDeferred
)

type probeAdmissionConfig struct {
	stepBytes      int64
	ceilingBytes   int64
	chargeTTL      time.Duration
	poll           time.Duration
	maxWait        time.Duration
	forcedInterval time.Duration
	// backgroundGrace is how long a background probe may wait for an earned
	// slot before the gate defers it. Short: storms dissolve, they retry on
	// their own schedule.
	backgroundGrace time.Duration
	footprint       func() int64
	// scavenge runs once before a forced winner proceeds, so the step it is
	// about to take lands on freshly returned pages. FreeMemory in production.
	scavenge func()
}

// probeAdmissionCharges counts admissions younger than chargeTTL: presumed
// arena steps in flight that the footprint sensor may not show yet.
var probeAdmissionCharges atomic.Int64

// probeAdmissionLastForcedNs rations forced exits: a waiter past maxWait may
// only leave when it wins the CAS from the previous forced exit's timestamp.
var probeAdmissionLastForcedNs atomic.Int64

func defaultProbeAdmissionConfig() probeAdmissionConfig {
	return probeAdmissionConfig{
		stepBytes:       probeAdmissionStepBytes,
		ceilingBytes:    probeAdmissionCeilingBytes,
		chargeTTL:       probeAdmissionChargeTTL,
		poll:            probeAdmissionPoll,
		maxWait:         probeAdmissionMaxWait,
		forcedInterval:  probeAdmissionForcedInterval,
		backgroundGrace: probeAdmissionBackgroundGrace,
		footprint:       MemoryFootprint,
		scavenge:        FreeMemory,
	}
}

// probeAdmissionWait blocks until footprint + (charges+1)×step — existing
// presumed steps plus this probe's own — fits under the ceiling, then records
// this probe's charge. A waiter past maxWait competes for a rationed forced
// exit (one per forcedInterval; the winner scavenges first). A waiter whose
// own context dies is deferred without a charge or a fabricated result. A footprint sensor
// reporting <= 0 (non-darwin hosts) admits immediately and uncharged: no
// sensor, no pacing.
func probeAdmissionWait(ctx context.Context, cfg probeAdmissionConfig) (waited time.Duration, verdict probeAdmissionVerdict) {
	return probeAdmissionAdmit(ctx, cfg, false)
}

// probeAdmissionAdmit is the two-class gate. Interactive probes (API delay
// tests — someone is watching) earn, then compete for rationed forced exits.
// Background probes (scheduled health checks) earn or step aside: past
// backgroundGrace, or on their own context's death, they are deferred —
// skipped without a recorded result — because a storm that cannot fit must
// dissolve, not queue into fake timeouts.
func probeAdmissionAdmit(ctx context.Context, cfg probeAdmissionConfig, background bool) (waited time.Duration, verdict probeAdmissionVerdict) {
	charge := func() {
		probeAdmissionCharges.Add(1)
		time.AfterFunc(cfg.chargeTTL, func() { probeAdmissionCharges.Add(-1) })
	}
	// tryReserve admits by compare-and-swap so a same-instant burst (the
	// kernel's own health checks arrive 10 at a time) cannot all read the
	// same charge count and slip under the line together.
	tryReserve := func(footprint int64) bool {
		for {
			if ctx.Err() != nil {
				return false
			}
			charges := probeAdmissionCharges.Load()
			if footprint+(charges+1)*cfg.stepBytes > cfg.ceilingBytes {
				return false
			}
			if probeAdmissionCharges.CompareAndSwap(charges, charges+1) {
				time.AfterFunc(cfg.chargeTTL, func() { probeAdmissionCharges.Add(-1) })
				return true
			}
		}
	}
	// tryForcedSlot rations forced exits to one per forcedInterval.
	tryForcedSlot := func() bool {
		for {
			if ctx.Err() != nil {
				return false
			}
			last := probeAdmissionLastForcedNs.Load()
			now := time.Now().UnixNano()
			if now-last < int64(cfg.forcedInterval) {
				return false
			}
			if probeAdmissionLastForcedNs.CompareAndSwap(last, now) {
				return true
			}
		}
	}
	start := time.Now()
	for {
		if ctx.Err() != nil {
			return time.Since(start), probeDeferred
		}
		footprint := cfg.footprint()
		// A sensor may take long enough for the caller to revoke its request.
		// Do not turn that late reading into a new reservation.
		if ctx.Err() != nil {
			return time.Since(start), probeDeferred
		}
		if footprint <= 0 {
			return time.Since(start), probeAdmitted
		}
		if tryReserve(footprint) {
			return time.Since(start), probeAdmitted
		}
		if background {
			if time.Since(start) >= cfg.backgroundGrace {
				return time.Since(start), probeDeferred
			}
		} else if time.Since(start) >= cfg.maxWait && tryForcedSlot() {
			if ctx.Err() != nil {
				return time.Since(start), probeDeferred
			}
			if cfg.scavenge != nil {
				cfg.scavenge()
			}
			if ctx.Err() != nil {
				// Keep the consumed forced slot: refunding it could let another
				// waiter bypass the existing ration. No probe charge was made.
				return time.Since(start), probeDeferred
			}
			charge()
			return time.Since(start), probeForced
		}
		select {
		case <-ctx.Done():
			return time.Since(start), probeDeferred
		case <-time.After(cfg.poll):
		}
	}
}

// probeAdmissionShouldArm mirrors nePacingSoftLimit's platform gate: only
// the iOS family (build tag, not GOOS — tvOS builds GOOS=darwin) running
// under a Network Extension lives against the jetsam wall this gate guards.
func probeAdmissionShouldArm(budgetedPlatform, underNetworkExtension bool) bool {
	return budgetedPlatform && underNetworkExtension
}

// armProbeAdmission installs the pacer on the adapter choke point. Armed only
// for the iOS family under a Network Extension (the platform with the jetsam
// wall); everywhere else the adapter hook stays nil and urlTest runs exactly
// as it does upstream.
func armProbeAdmission() {
	cfg := defaultProbeAdmissionConfig()
	adapter.SetURLTestAdmission(func(ctx context.Context) error {
		background := adapter.IsBackgroundProbe(ctx)
		waited, verdict := probeAdmissionAdmit(ctx, cfg, background)
		if waited >= cfg.poll || verdict == probeDeferred {
			// Info, not debug: one device round must be able to adjudicate
			// the gate without a log-level change ( final judgment ran
			// blind on this line at debug).
			log.Infoln("[Memory] probe admission: waited %dms verdict=%d background=%t footprint=%d charges=%d", waited.Milliseconds(), verdict, background, cfg.footprint(), probeAdmissionCharges.Load())
		}
		if verdict == probeDeferred {
			return adapter.ErrURLTestDeferred
		}
		return nil
	})
}
