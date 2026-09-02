package hako

import (
	"testing"
	"time"

	"github.com/TokenPLS/Hako/component/pause"
)

// Pause stops health checks; Wake resumes them, on every profile. iOS additionally arms a
// one-minute backstop, because the failure that timer guards is a wake callback that never
// arrives -- which would leave the core paused, and health checking silently off, for the rest
// of the session.
//
// This used to be written as a platform SPLIT copied from sing-box's CommandServer, where Wake
// resumed only off iOS and the timer was the sole resume path on iOS. That made the platform
// the pausing was measured on the one where a delivered wake did nothing.: sing-box is
// never the authority on what behaviour should be, and no measurement was offered for the
// split. Apple documents wake as delivered "immediately after the system wakes up"
// (NEProvider.h), with no iOS exception.
//
// The runtime profile is the discriminator rather than a build constant, because the same
// binary carries the macOS profiles.

func withRuntimeProfile(t *testing.T, profile runtimeProfile) {
	t.Helper()
	original := currentRuntimeProfile()
	setupRuntimeProfile.Store(uint32(profile))
	t.Cleanup(func() { setupRuntimeProfile.Store(uint32(original)) })
}

// leaveAwake keeps one test's pause state from leaking into the next: the manager is
// process-wide.
func leaveAwake(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		pause.DeviceWake()
		if pause.IsDevicePaused() {
			t.Error("the device is still paused after cleanup; later tests will misbehave")
		}
	})
}

func TestPauseAndWakeDriveTheDevicePauseManager(t *testing.T) {
	for _, testCase := range []struct {
		name          string
		profile       runtimeProfile
		wakeResumes   bool
		armsExpiry    bool
		whyWakeResume string
	}{
		{
			name:          "macOS packet tunnel",
			profile:       runtimeProfileMacOSPacketTunnel,
			wakeResumes:   true,
			armsExpiry:    false,
			whyWakeResume: "a delivered wake resumes, and this profile never armed a backstop to fall back on",
		},
		{
			name:          "iOS packet tunnel",
			profile:       runtimeProfileIOSPacketTunnel,
			wakeResumes:   true,
			armsExpiry:    true,
			whyWakeResume: "a delivered wake resumes here too; the timer is only the backstop for one that never arrives",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			withRuntimeProfile(t, testCase.profile)
			leaveAwake(t)

			service := &BoxService{}

			service.Pause()
			if !pause.IsDevicePaused() {
				t.Fatal("Pause did not pause the device; every registered ticker keeps running")
			}
			if service.pauseCount.Load() != 1 {
				t.Fatalf("pauseCount = %d, want 1", service.pauseCount.Load())
			}

			armed := service.endPauseTimer != nil
			if armed != testCase.armsExpiry {
				t.Fatalf("end-pause timer armed = %v, want %v", armed, testCase.armsExpiry)
			}

			service.Wake()
			if service.wakeCount.Load() != 1 {
				t.Fatalf("wakeCount = %d, want 1", service.wakeCount.Load())
			}
			if resumed := !pause.IsDevicePaused(); resumed != testCase.wakeResumes {
				t.Fatalf("Wake resumed the device = %v, want %v — %s",
					resumed, testCase.wakeResumes, testCase.whyWakeResume)
			}
		})
	}
}

// TestIOSEndPauseTimerActuallyFires: an armed timer that never runs would leave the core paused
// for the session, which is strictly worse than never pausing. One second is substituted for
// the shipped minute so the test observes the real timer rather than asserting a field.
func TestIOSEndPauseTimerActuallyFires(t *testing.T) {
	withRuntimeProfile(t, runtimeProfileIOSPacketTunnel)
	leaveAwake(t)

	service := &BoxService{}
	service.Pause()
	if !pause.IsDevicePaused() {
		t.Fatal("Pause did not pause the device")
	}
	if service.endPauseTimer == nil {
		t.Fatal("no end-pause timer was armed on iOS")
	}

	// Shorten the armed timer instead of waiting a minute. Reset on a live timer replaces its
	// deadline, which is the same call path Pause uses when it re-arms.
	service.endPauseMu.Lock()
	service.endPauseTimer.Reset(50 * time.Millisecond)
	service.endPauseMu.Unlock()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !pause.IsDevicePaused() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the end-pause timer fired without waking the device; on iOS nothing else resumes " +
		"it, so health checking would stay off for the rest of the session")
}

// TestRepeatedSleepExtendsTheWindow: iOS delivers sleep() repeatedly while a device stays
// asleep, and each one has to push the expiry out. Otherwise the first minute ends and the
// URL tests resume for the rest of the night, which is the behaviour being fixed.
func TestRepeatedSleepExtendsTheWindow(t *testing.T) {
	withRuntimeProfile(t, runtimeProfileIOSPacketTunnel)
	leaveAwake(t)

	service := &BoxService{}
	service.Pause()
	first := service.endPauseTimer

	service.Pause()
	if service.endPauseTimer != first {
		t.Fatal("a second sleep replaced the timer instead of resetting it; upstream resets, and " +
			"replacing leaks the old one")
	}
	if !pause.IsDevicePaused() {
		t.Fatal("a second sleep left the device awake")
	}
	if service.pauseCount.Load() != 2 {
		t.Fatalf("pauseCount = %d, want 2", service.pauseCount.Load())
	}
}
