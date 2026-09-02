package statistic

import (
	"testing"
	"time"

	"github.com/TokenPLS/Hako/common/atomic"
)

// The rate sampler used to be an unconditional 1 Hz ticker started at package init and never
// stopped: it ran for the life of every process importing this package, with no reader and no
// tunnel required. sing-box has no process-lifetime accounting ticker at all -- its equivalents
// live inside clash-api HTTP handlers with defer tick.Stop(), so they exist only while a client is
// attached.
//
// Two things are worth testing, and the second one is the reason this change was ranked last and
// nearly skipped:
//
//   - the sampler stops when nobody reads, and a read restarts it;
//   - resuming does NOT publish the traffic that accumulated while it was stopped. Publishing it
//     would display a whole idle span as one second of traffic -- a rate spike that never
//     happened. A naive "pause the ticker" implementation has exactly that bug, which is why
//     pause-gating this was explicitly rejected earlier.

func waitUntil(t *testing.T, deadline time.Duration, condition func() bool) bool {
	t.Helper()
	until := time.Now().Add(deadline)
	for time.Now().Before(until) {
		if condition() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return condition()
}

func TestResumingDoesNotPublishTheIdleAccumulation(t *testing.T) {
	manager := newTestManager()
	go manager.handle()

	// Nobody has read a rate, so the sampler is idle from the start. Push a large amount of
	// traffic: this is the accumulation that must never be published as one second's worth.
	const idleBytes = 500 << 20 // 500 MiB, far more than any real second
	manager.PushUploaded("direct", idleBytes)
	manager.PushDownloaded("direct", idleBytes)
	time.Sleep(1500 * time.Millisecond)

	if up, down := manager.uploadBlip.Load(), manager.downloadBlip.Load(); up != 0 || down != 0 {
		t.Fatalf("the idle sampler published a rate (up=%d down=%d); it should not have been "+
			"sampling at all", up, down)
	}

	// Now read, which wakes the sampler. The 500 MiB accumulated while it was stopped must be
	// discarded rather than published.
	manager.Now()

	if !waitUntil(t, 3*time.Second, func() bool {
		return manager.uploadTemp.Load() == 0
	}) {
		t.Fatalf("the sampler did not clear the idle accumulation: uploadTemp=%d", manager.uploadTemp.Load())
	}

	// Give it a couple of sampling ticks and confirm no spike was ever published.
	time.Sleep(2500 * time.Millisecond)
	if up := manager.uploadBlip.Load(); up >= idleBytes {
		t.Fatalf("published %d bytes/s after resuming; the whole idle span was reported as one "+
			"second of traffic, which is the fake spike this design exists to avoid", up)
	}
	if down := manager.downloadBlip.Load(); down >= idleBytes {
		t.Fatalf("published %d bytes/s down after resuming, same fake spike", down)
	}
}

func TestSamplerPublishesRealTrafficWhileBeingRead(t *testing.T) {
	manager := newTestManager()
	go manager.handle()

	// Wake it and keep it awake, the way a once-per-second poller does.
	manager.Now()

	const perSecond = 3 << 20
	published := waitUntil(t, 6*time.Second, func() bool {
		manager.PushUploaded("direct", perSecond/4)
		manager.Now()
		time.Sleep(120 * time.Millisecond)
		return manager.uploadBlip.Load() > 0
	})
	if !published {
		t.Fatal("a sampler being read every 120 ms never published a rate, so reads are not " +
			"keeping it alive and the rate view would sit at zero")
	}
}

func TestSamplerStopsWhenNobodyReads(t *testing.T) {
	manager := newTestManager()
	go manager.handle()

	manager.Now()
	manager.PushUploaded("direct", 4<<20)

	// Wait for a published rate, so we know it was running.
	if !waitUntil(t, 4*time.Second, func() bool { return manager.uploadBlip.Load() > 0 }) {
		t.Fatal("never published a rate while being read")
	}

	// Stop reading for longer than the idle timeout, then push traffic. A stopped sampler leaves
	// it in temp; a running one would move it into blip.
	time.Sleep(sampleIdleTimeout + time.Second)
	manager.uploadTemp.Store(0)
	manager.PushUploaded("direct", 7<<20)
	time.Sleep(2 * time.Second)

	if manager.uploadTemp.Load() != 7<<20 {
		t.Fatalf("uploadTemp = %d after the idle timeout, want the pushed 7 MiB left untouched; "+
			"the sampler is still running with no reader", manager.uploadTemp.Load())
	}
}

// TestSnapshotDoesNotWakeTheSampler: Snapshot returns totals and connections, not rates. Waking
// the sampler for it would put a 1 Hz ticker back for every caller that never looks at a rate,
// which is most of them.
func TestSnapshotDoesNotWakeTheSampler(t *testing.T) {
	manager := newTestManager()
	go manager.handle()

	manager.Snapshot()
	manager.PushUploaded("direct", 9<<20)
	time.Sleep(2 * time.Second)

	if got := manager.uploadBlip.Load(); got != 0 {
		t.Fatalf("Snapshot woke the sampler: published %d bytes/s", got)
	}
	if manager.lastReadAt.Load() != 0 {
		t.Fatal("Snapshot recorded a rate read")
	}
}

// newTestManager builds a manager with its own counters so tests never race the package-level
// DefaultManager, whose sampler is already running.
func newTestManager() *Manager {
	return &Manager{
		uploadTemp:         atomic.NewInt64(0),
		downloadTemp:       atomic.NewInt64(0),
		uploadBlip:         atomic.NewInt64(0),
		downloadBlip:       atomic.NewInt64(0),
		uploadTotal:        atomic.NewInt64(0),
		downloadTotal:      atomic.NewInt64(0),
		proxyUploadTemp:    atomic.NewInt64(0),
		proxyDownloadTemp:  atomic.NewInt64(0),
		proxyUploadBlip:    atomic.NewInt64(0),
		proxyDownloadBlip:  atomic.NewInt64(0),
		proxyUploadTotal:   atomic.NewInt64(0),
		proxyDownloadTotal: atomic.NewInt64(0),
		lastReadAt:         atomic.NewInt64(0),
		sampleWake:         make(chan struct{}, 1),
	}
}
