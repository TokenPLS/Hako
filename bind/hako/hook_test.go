package hako

import (
	"net"
	"syscall"
	"testing"

	"github.com/TokenPLS/Hako/component/dialer"
)

// hookPlatform records AutoDetectControl calls and toggles the opt-in.
type hookPlatform struct {
	recordingPlatform
	enabled    bool
	gotFd      int32
	callCount  int
	controlErr error
}

func (p *hookPlatform) UsePlatformAutoDetectInterfaceControl() bool { return p.enabled }
func (p *hookPlatform) AutoDetectInterfaceControl(fd int32) error {
	p.callCount++
	p.gotFd = fd
	return p.controlErr
}

func TestInstallSocketHook(t *testing.T) {
	orig := dialer.DefaultSocketHook
	origTransform := dialer.DefaultAddressTransform
	t.Cleanup(func() {
		dialer.DefaultSocketHook = orig
		dialer.DefaultAddressTransform = origTransform
	})

	// Opt-out clears any prior hook.
	dialer.DefaultSocketHook = func(_, _ string, _ syscall.RawConn) error { return nil }
	installSocketHook(&hookPlatform{enabled: false})
	if dialer.DefaultSocketHook != nil {
		t.Fatal("opt-out must clear DefaultSocketHook")
	}
	if dialer.DefaultAddressTransform != nil {
		t.Fatal("opt-out must clear DefaultAddressTransform")
	}

	// Opt-in installs a hook that forwards the fd to AutoDetectControl.
	platform := &hookPlatform{enabled: true}
	installSocketHook(platform)
	if dialer.DefaultSocketHook == nil {
		t.Fatal("opt-in must install DefaultSocketHook")
	}
	if dialer.DefaultAddressTransform == nil {
		t.Fatal("opt-in must install DefaultAddressTransform")
	}

	// Drive the hook with a real socket's RawConn.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()
	raw, err := pc.(*net.UDPConn).SyscallConn()
	if err != nil {
		t.Fatalf("syscallconn: %v", err)
	}
	if err := dialer.DefaultSocketHook("udp", "1.1.1.1:53", raw); err != nil {
		t.Fatalf("hook returned error: %v", err)
	}
	if platform.callCount != 1 {
		t.Fatalf("AutoDetectControl called %d times, want 1", platform.callCount)
	}
	if platform.gotFd <= 0 {
		t.Fatalf("AutoDetectControl got fd %d, want a valid descriptor", platform.gotFd)
	}
}
