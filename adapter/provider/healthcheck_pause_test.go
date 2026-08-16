package provider

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/common/utils"
	"github.com/TokenPLS/Hako/component/pause"
	C "github.com/TokenPLS/Hako/constant"
)

// HealthCheck.process registers its ticker with the process-wide pause manager so the URL
// tests stop while the device sleeps. The registration is two lines; the risk in it is the
// other two:
//
//   - it must actually happen, or an idle device keeps paying a TCP connect plus a full TLS
//     handshake per proxy per interval, which on Apple is one trustd XPC round trip per
//     verification (an idle iPhone logged 17,568 over 6.7 hours);
//   - it must be released when the health check stops, or every configuration reload leaves a
//     callback behind holding a dead ticker, for the life of the process.
//
// The pause package's own tests cover the ticker behaviour. These cover the wiring.

func TestHealthCheckRegistersAndReleasesItsPauseCallback(t *testing.T) {
	baseline := pause.Outstanding()

	// One second is the minimum: NewHealthCheck takes the interval in seconds.
	healthCheck := NewHealthCheck(nil, "http://127.0.0.1:1/never", 1, 1, true, nil)

	stopped := make(chan struct{})
	go func() {
		healthCheck.process()
		close(stopped)
	}()

	if !waitFor(func() bool { return pause.Outstanding() == baseline+1 }) {
		t.Fatalf("process() did not register a pause callback: outstanding %d, want %d. "+
			"Without it the ticker keeps firing while the device sleeps",
			pause.Outstanding(), baseline+1)
	}

	healthCheck.close()

	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("process() did not return after close()")
	}

	if !waitFor(func() bool { return pause.Outstanding() == baseline }) {
		t.Fatalf("the pause callback outlived the health check: outstanding %d, want the baseline "+
			"%d. Each configuration reload would leave one behind for the life of the process",
			pause.Outstanding(), baseline)
	}
}

// TestRepeatedHealthChecksDoNotAccumulateCallbacks is the reload case stated directly: a
// counter that only ever grows is what the leak looks like in production, where reloads happen
// far more often than restarts.
func TestRepeatedHealthChecksDoNotAccumulateCallbacks(t *testing.T) {
	baseline := pause.Outstanding()

	for round := 0; round < 5; round++ {
		healthCheck := NewHealthCheck(nil, "http://127.0.0.1:1/never", 1, 1, true, nil)
		stopped := make(chan struct{})
		go func() {
			healthCheck.process()
			close(stopped)
		}()
		if !waitFor(func() bool { return pause.Outstanding() > baseline }) {
			t.Fatalf("round %d never registered", round)
		}
		healthCheck.close()
		select {
		case <-stopped:
		case <-time.After(5 * time.Second):
			t.Fatalf("round %d did not stop", round)
		}
	}

	if !waitFor(func() bool { return pause.Outstanding() == baseline }) {
		t.Fatalf("after five create/destroy rounds outstanding is %d, want the baseline %d",
			pause.Outstanding(), baseline)
	}
}

func waitFor(condition func() bool) bool {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return condition()
}

// countingProxy is the smallest thing HealthCheck.execute will drive: it calls exactly
// Name, URLTest, AliveForTestUrl and LastDelayForTestUrl. Embedding the interface leaves
// everything else nil, so any method this test did not anticipate panics loudly instead of
// quietly returning a zero value.
type countingProxy struct {
	C.Proxy
	urlTests atomic.Int64
}

func (p *countingProxy) Name() string { return "probe" }
func (p *countingProxy) URLTest(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) (uint16, error) {
	p.urlTests.Add(1)
	return 0, errors.New("probe never dials")
}
func (p *countingProxy) AliveForTestUrl(url string) bool       { return false }
func (p *countingProxy) LastDelayForTestUrl(url string) uint16 { return 0 }

// A wake has to produce a check, not just restart the clock. sing's RegisterTicker does
// `resume(); ticker.Reset(duration)` -- so with a nil resume, a device that slept through a
// scheduled check runs the next one a full interval after waking, and whatever the user sees
// on unlock is as stale as the sleep made it. That is the pause turning into a silent
// degradation of the very data it was added to keep cheap.
func TestWakeRunsAHealthCheckInsteadOfOnlyRestartingTheClock(t *testing.T) {
	t.Cleanup(pause.DeviceWake)

	// An interval far longer than the test: if a check happens, only the resume can have
	// caused it, never a tick.
	healthCheck := NewHealthCheck(nil, "http://127.0.0.1:1/never", 1, 3600, false, nil)
	probe := &countingProxy{}
	healthCheck.setProxies([]C.Proxy{probe})

	stopped := make(chan struct{})
	go func() {
		healthCheck.process()
		close(stopped)
	}()
	t.Cleanup(func() {
		healthCheck.close()
		<-stopped
	})

	// process() kicks one check on entry; wait it out so the wake's check is unambiguous.
	if !waitFor(func() bool { return probe.urlTests.Load() >= 1 }) {
		t.Fatal("process() did not run its initial check; the rest of this test cannot distinguish causes")
	}
	// check() is behind a singledo.Single with a one-second result cache, so a wake inside
	// that window is answered from the cache and never reaches the proxy. Waiting past it is
	// what makes a green here mean the resume ran, rather than that the timing happened to
	// dodge the deduplication.
	time.Sleep(1200 * time.Millisecond)
	initial := probe.urlTests.Load()

	pause.DevicePause()
	pause.DeviceWake()

	if !waitFor(func() bool { return probe.urlTests.Load() > initial }) {
		t.Fatalf("no health check followed the wake (url tests still %d): with a nil resume the "+
			"ticker is merely Reset, so the next check is a full interval away", probe.urlTests.Load())
	}
}
