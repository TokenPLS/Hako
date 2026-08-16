package pause

import (
	"sync/atomic"
	"testing"
	"time"
)

// The value of this package is that a periodic task stops while the device sleeps. So the
// tests observe the ticker actually not firing, not merely that a state flag flipped: an
// assertion on IsDevicePaused would have passed even if RegisterTicker did nothing.
//
// The manager is process-wide, so every test here must leave it awake and its callback list
// empty, or it corrupts the next one.

func TestRegisteredTickerStopsWhilePausedAndResumesOnWake(t *testing.T) {
	const interval = 10 * time.Millisecond
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var ticks atomic.Int64
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				ticks.Add(1)
			case <-done:
				return
			}
		}
	}()
	defer close(done)

	unregister := RegisterTicker(ticker, interval, nil)
	defer unregister()

	// Running: ticks accumulate.
	time.Sleep(6 * interval)
	running := ticks.Load()
	if running == 0 {
		t.Fatal("the ticker never fired before pausing, so this test cannot observe it stopping")
	}

	DevicePause()
	defer DeviceWake()

	// Let any tick already delivered to the channel drain, then take the baseline.
	time.Sleep(2 * interval)
	atPause := ticks.Load()

	time.Sleep(10 * interval)
	if paused := ticks.Load(); paused != atPause {
		t.Fatalf("the ticker fired %d more time(s) while the device was paused; each of those is "+
			"a round of URL tests, and on Apple one trustd round trip per handshake",
			paused-atPause)
	}
	if !IsDevicePaused() {
		t.Fatal("IsDevicePaused is false during a pause")
	}

	DeviceWake()
	time.Sleep(6 * interval)
	if resumed := ticks.Load(); resumed <= atPause {
		t.Fatalf("the ticker did not resume after wake: %d ticks, still at the paused count %d. "+
			"A pause that never ends would silently disable health checking for the whole session",
			resumed, atPause)
	}
	if IsDevicePaused() {
		t.Fatal("IsDevicePaused is still true after DeviceWake")
	}
}

// TestUnregisterStopsTrackingTheTicker is the leak guard. The callback list is process-wide, so
// a health check that registers per configuration reload and never unregisters accumulates
// callbacks for the life of the process -- each one holding a reference to a dead ticker.
func TestUnregisterStopsTrackingTheTicker(t *testing.T) {
	const interval = 10 * time.Millisecond
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	unregister := RegisterTicker(ticker, interval, nil)
	unregister()

	var ticks atomic.Int64
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				ticks.Add(1)
			case <-done:
				return
			}
		}
	}()
	defer close(done)

	DevicePause()
	defer DeviceWake()

	time.Sleep(2 * interval)
	atPause := ticks.Load()
	time.Sleep(8 * interval)

	if paused := ticks.Load(); paused == atPause {
		t.Fatal("an unregistered ticker was still stopped by DevicePause, so the callback is " +
			"still in the process-wide list; every configuration reload would leak one")
	}
}

// TestResumeCallbackRunsBeforeTheTickerRestarts: callers pass a resume function to do work the
// pause deferred. Upstream invokes it before Reset, and something relying on that ordering --
// refreshing state the next tick will read -- must not be reordered silently.
func TestResumeCallbackRunsBeforeTheTickerRestarts(t *testing.T) {
	const interval = 10 * time.Millisecond
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var resumed atomic.Bool
	unregister := RegisterTicker(ticker, interval, func() { resumed.Store(true) })
	defer unregister()

	DevicePause()
	if resumed.Load() {
		t.Fatal("the resume callback ran on pause")
	}

	DeviceWake()
	if !resumed.Load() {
		t.Fatal("the resume callback did not run on wake")
	}
}

// TestRegisteringWhileAlreadyPausedStopsImmediately: a provider created while the device is
// asleep -- a configuration reload during sleep -- must not start ticking until wake.
func TestRegisteringWhileAlreadyPausedStopsImmediately(t *testing.T) {
	const interval = 10 * time.Millisecond

	DevicePause()
	defer DeviceWake()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	unregister := RegisterTicker(ticker, interval, nil)
	defer unregister()

	var ticks atomic.Int64
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				ticks.Add(1)
			case <-done:
				return
			}
		}
	}()
	defer close(done)

	time.Sleep(8 * interval)
	if got := ticks.Load(); got != 0 {
		t.Fatalf("a ticker registered during a pause fired %d time(s); a reload while the device "+
			"sleeps would restart the very traffic the pause exists to stop", got)
	}
}
