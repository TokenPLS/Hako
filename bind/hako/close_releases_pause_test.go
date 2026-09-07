package hako

import (
	"testing"
	"time"

	"github.com/TokenPLS/Hako/component/pause"
)

// The case this file exists for: "disconnect on sleep" delivers sleep() (Pause) and, moments
// later while the device is still asleep, stopTunnel (Close). Nothing released what Pause
// armed, and component/pause's manager is process-wide, so both defects outlived the service
// that caused them.

// TestCloseWakesTheDeviceItPaused: Close must not leave the process-wide manager paused on
// behalf of a service that no longer exists -- a reconnect started in that window would
// otherwise inherit a pause it never asked for, and its own health checks would not run until
// whatever released the stale pause got around to it.
func TestCloseWakesTheDeviceItPaused(t *testing.T) {
	for _, profile := range []runtimeProfile{runtimeProfileMacOSPacketTunnel, runtimeProfileIOSPacketTunnel} {
		t.Run(profile.String(), func(t *testing.T) {
			withRuntimeProfile(t, profile)
			leaveAwake(t)

			service := &BoxService{}
			service.Pause()
			if !pause.IsDevicePaused() {
				t.Fatal("Pause did not pause the device")
			}

			if err := service.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			if pause.IsDevicePaused() {
				t.Fatal("the device is still reported paused after Close; a service started in " +
					"this window would inherit a pause it never asked for")
			}
		})
	}
}

// TestCloseNeverWakesAPauseThisServiceDidNotMake: the manager is shared, so Close must release
// only a pause its OWN Pause call made -- never a device-wide pause some other live service is
// still holding.
func TestCloseNeverWakesAPauseThisServiceDidNotMake(t *testing.T) {
	withRuntimeProfile(t, runtimeProfileMacOSPacketTunnel)
	leaveAwake(t)

	// Something else paused the device -- a sibling service, or a test's own DevicePause.
	// This service never called Pause, so pauseCount == wakeCount == 0.
	pause.DevicePause()

	service := &BoxService{}
	if err := service.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !pause.IsDevicePaused() {
		t.Fatal("Close woke a pause this service never made; a sibling service still holding " +
			"the pause would have its health checks resumed out from under it")
	}
}

// TestCloseStopsTheEndPauseTimerBeforeItCanFireAgainstAClosedService: armEndPauseTimer's
// callback is the bare, receiver-less pause.DeviceWake -- it does not know or care whether the
// *BoxService that armed it still exists. If Close does not stop it, it goes on running and
// wakes the device up to a minute later regardless of anything that happened to the service in
// the meantime, including a fresh Pause this test issues afterward to stand in for whatever the
// next service or reconnect does.
func TestCloseStopsTheEndPauseTimerBeforeItCanFireAgainstAClosedService(t *testing.T) {
	withRuntimeProfile(t, runtimeProfileIOSPacketTunnel)
	leaveAwake(t)

	service := &BoxService{}
	service.Pause()
	if service.endPauseTimer == nil {
		t.Fatal("no end-pause timer was armed on iOS")
	}

	// Shorten the timer so the test does not wait the shipped minute to observe whether the
	// leaked callback still runs. Reset on a live timer is the same call armEndPauseTimer itself
	// uses to extend a repeated sleep, so this is not reaching around the production path.
	service.endPauseMu.Lock()
	service.endPauseTimer.Reset(50 * time.Millisecond)
	service.endPauseMu.Unlock()

	if err := service.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Put the manager into a paused state that only the leaked timer's unconditional
	// pause.DeviceWake() could clear -- nothing else in this test touches it from here on. If
	// Close stopped the timer, this stays paused for the life of the sleep below; if the timer
	// is still armed, it fires within 50ms and clears it out from under the test.
	pause.DevicePause()
	time.Sleep(300 * time.Millisecond)
	if !pause.IsDevicePaused() {
		t.Fatal("something woke the device after Close -- the end-pause timer from the closed " +
			"service was not stopped and fired against a service that no longer exists")
	}
}
