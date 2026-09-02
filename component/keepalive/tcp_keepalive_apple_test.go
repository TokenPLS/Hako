package keepalive

import (
	"runtime"
	"testing"
	"time"
)

// Every outbound socket was getting Go's own keepalive defaults -- 15s idle, 15s
// interval, 9 probes -- because component/dialer/dialer.go calls SetNetDialer above the
// DefaultSocketHook branch, so Apple builds get it, while keepAliveIdle and
// keepAliveInterval are only ever assigned from configuration that has no default. Zero
// reaches Go, and net/tcpsockopt_darwin.go substitutes 15s for zero.
//
// On darwin that steady-state probe rate is 20x the reference: sing-box ships 5 minutes
// idle and 75 seconds between unanswered retransmits. It matters because darwin resets
// the idle timer after an ACKed probe and uses Interval only for retransmits, so the
// ratio in normal operation is 15s versus 300s -- and tunnel/tunnel.go has no idle
// teardown for relayed TCP, so an idle outbound socket keeps probing indefinitely. Each
// probe on cellular promotes the radio out of idle.
//
// The change is deliberately scoped to darwin. 15s/15s is upstream's behaviour on
// platforms that do not pay a radio-wake cost for it, and diverging there would be
// stricter than upstream without the platform requiring it. There is precedent for the
// shape: SetDisableKeepAlive already forces keepalive off on android.

func TestUnconfiguredKeepAliveUsesAppleFriendlyDefaults(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "ios" {
		t.Skipf("the carve-out is darwin-only by design; %s keeps upstream behaviour", runtime.GOOS)
	}
	restore := saveKeepAlive()
	defer restore()

	SetKeepAliveIdle(0)
	SetKeepAliveInterval(0)

	if got, want := KeepAliveIdle(), 5*time.Minute; got != want {
		t.Fatalf("unconfigured KeepAliveIdle() = %v, want %v; zero would reach Go and become 15s", got, want)
	}
	if got, want := KeepAliveInterval(), 75*time.Second; got != want {
		t.Fatalf("unconfigured KeepAliveInterval() = %v, want %v", got, want)
	}
}

func TestExplicitConfigurationStillWins(t *testing.T) {
	restore := saveKeepAlive()
	defer restore()

	SetKeepAliveIdle(42 * time.Second)
	SetKeepAliveInterval(7 * time.Second)

	if got, want := KeepAliveIdle(), 42*time.Second; got != want {
		t.Fatalf("KeepAliveIdle() = %v, want the configured %v; a default must not shadow config", got, want)
	}
	if got, want := KeepAliveInterval(), 7*time.Second; got != want {
		t.Fatalf("KeepAliveInterval() = %v, want the configured %v", got, want)
	}
}

// TestNonAppleKeepsUpstreamZero documents the other half of the scoping decision, so a
// future change cannot widen the carve-out without a test going red.
func TestNonAppleKeepsUpstreamZero(t *testing.T) {
	if runtime.GOOS == "darwin" || runtime.GOOS == "ios" {
		t.Skip("darwin has the carve-out; this asserts the absence of one elsewhere")
	}
	restore := saveKeepAlive()
	defer restore()

	SetKeepAliveIdle(0)
	SetKeepAliveInterval(0)

	if got := KeepAliveIdle(); got != 0 {
		t.Fatalf("KeepAliveIdle() = %v on %s, want 0 so Go's own default applies", got, runtime.GOOS)
	}
}

func saveKeepAlive() func() {
	idle, interval, disabled := KeepAliveIdle(), KeepAliveInterval(), DisableKeepAlive()
	rawIdle, rawInterval := keepAliveIdle.Load(), keepAliveInterval.Load()
	_ = idle
	_ = interval
	return func() {
		keepAliveIdle.Store(rawIdle)
		keepAliveInterval.Store(rawInterval)
		setDisableKeepAlive(disabled)
	}
}
