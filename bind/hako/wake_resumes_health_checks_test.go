package hako

import (
	"testing"

	"github.com/TokenPLS/Hako/component/pause"
)

// Pausing health checks is a Hako addition, not upstream behaviour: mihomo has
// no component/pause at all and its ticker runs through a device sleep. The
// addition earns its keep with a measurement -- an idle iPhone logged 17,568
// certificate verifications over 6.7 hours because every tick URL-tests every
// proxy -- so what is pinned here is the deviation's boundary, not the deviation.
//
// The boundary is: a wake resumes. It used to resume only off iOS, so on the one
// platform the measurement came from, the resume was left to a one-minute timer
// and the next check landed at sleep + 60s + a full interval. The reason on
// record was that sing-box's CommandServer splits it that way, and the code even
// conceded the call would be "harmless in isolation". does not accept
// sing-box as an authority on what behaviour should be, and no measurement was
// ever offered for the split, so it goes.
//
// The timer stays, demoted to what it always actually was: a backstop against a
// wake callback that never arrives, which would strand the core paused for the
// session. Apple's own NEProvider.h documents wake as delivered "immediately
// after the system wakes up", with no iOS exception.
func TestWakeResumesHealthChecksOnEveryProfileIncludingIOS(t *testing.T) {
	for _, profile := range []runtimeProfile{
		runtimeProfileIOSPacketTunnel,
		runtimeProfileMacOSPacketTunnel,
		runtimeProfileMacOSApplication,
	} {
		t.Run(profile.String(), func(t *testing.T) {
			withRuntimeProfile(t, profile)
			leaveAwake(t)

			service := &BoxService{}
			service.Pause()
			if !pause.IsDevicePaused() {
				t.Fatal("Pause did not pause the device")
			}

			service.Wake()

			if pause.IsDevicePaused() {
				t.Error("Wake left the device paused; health checks stay stopped until a timer " +
					"expires, so the next check lands a full interval after that")
			}
		})
	}
}

// The backstop is still armed on iOS, because the failure it guards -- a wake
// that never arrives -- is not disproven by wake now working when it does arrive.
func TestIOSStillArmsTheBackstopTimerAfterWakeResumes(t *testing.T) {
	withRuntimeProfile(t, runtimeProfileIOSPacketTunnel)
	leaveAwake(t)

	service := &BoxService{}
	service.Pause()
	if service.endPauseTimer == nil {
		t.Fatal("the backstop timer must still be armed on iOS")
	}
	service.Wake()
	if pause.IsDevicePaused() {
		t.Fatal("Wake must resume regardless of the backstop")
	}
}
