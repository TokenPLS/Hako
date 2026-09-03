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

// A configuration whose dns.listen and proxy-server-nameserver both name
// 127.0.0.1:1053 -- the shape desktop tutorials hand out -- resolved nothing on
// a device: every query to its own resolver left on a socket the hook had bound
// to en0 or pdp_ip0, where 127.0.0.1 does not exist, and the kernel answered
// "write udp 127.0.0.1:x->127.0.0.1:1053: write: can't assign requested
// address". Upstream draws this line itself at component/dialer/dialer.go:97-100
// ("avoid 'The requested address is not valid in its context.'"), but only in
// the branch taken when no socket hook is installed -- which is never our
// branch, because this binding installs one.
func TestSocketHookLeavesLoopbackUnscoped(t *testing.T) {
	orig := dialer.DefaultSocketHook
	origTransform := dialer.DefaultAddressTransform
	t.Cleanup(func() {
		dialer.DefaultSocketHook = orig
		dialer.DefaultAddressTransform = origTransform
	})

	platform := &hookPlatform{enabled: true}
	installSocketHook(platform)
	if dialer.DefaultSocketHook == nil {
		t.Fatal("opt-in must install DefaultSocketHook")
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback listener available: %v", err)
	}
	defer listener.Close()

	rawConnOf := func(t *testing.T) syscall.RawConn {
		t.Helper()
		conn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		t.Cleanup(func() { conn.Close() })
		raw, err := conn.(*net.TCPConn).SyscallConn()
		if err != nil {
			t.Fatalf("syscall conn: %v", err)
		}
		return raw
	}

	// Upstream's own predicate is "not global unicast" (bind_darwin.go:14-19),
	// which is wider than loopback: link-local and multicast destinations are
	// left unscoped too. An earlier draft of this fix tested only for loopback
	// and would have kept scoping these.
	for _, address := range []string{
		"127.0.0.1:1053", "[::1]:53", "localhost:53", listener.Addr().String(),
		"169.254.1.1:53",   // link-local
		"[fe80::1]:53",     // link-local v6
		"224.0.0.251:5353", // multicast (mDNS)
		"0.0.0.0:0",        // unspecified as a DESTINATION
	} {
		before := platform.callCount
		if err := dialer.DefaultSocketHook("udp", address, rawConnOf(t)); err != nil {
			t.Fatalf("hook returned an error for %q: %v", address, err)
		}
		if platform.callCount != before {
			t.Fatalf("%q was scoped to an interface; upstream leaves a non-global-unicast destination unbound", address)
		}
	}

	// A real destination still goes through the platform: this is the guarantee
	// the hook exists for, and loosening it was never the aim.
	for _, address := range []string{"223.5.5.5:53", "[2400:3200::1]:53", "example.com:443"} {
		before := platform.callCount
		if err := dialer.DefaultSocketHook("udp", address, rawConnOf(t)); err != nil {
			t.Fatalf("hook returned an error for %q: %v", address, err)
		}
		if platform.callCount != before+1 {
			t.Fatalf("%q must still be scoped: callCount %d -> %d", address, before, platform.callCount)
		}
	}

	// A KNOWN GAP, pinned as it behaves today rather than as it should. A packet
	// socket on a wildcard LOCAL address still gets bound, because the hook is
	// handed the local address and learns nothing about the peer. Upstream has
	// no such gap: its listen path tests the PEER (component/dialer/dialer.go:97-100),
	// an argument the hook branch never sees. It is reachable on macOS through a
	// proxy whose SERVER is on loopback -- every outbound UDP dial passes
	// address="" with the server as rAddrPort -- where TCP is exempted here and
	// UDP is not, failing with the same "can't assign requested address".
	// Pinned so that closing it is a deliberate change with a failing test,
	// not something that quietly starts or stops working.
	before := platform.callCount
	if err := dialer.DefaultSocketHook("udp", "", rawConnOf(t)); err != nil {
		t.Fatalf("hook returned an error for an empty address: %v", err)
	}
	if platform.callCount != before+1 {
		t.Fatalf("an address the hook cannot read must stay scoped: callCount %d -> %d", before, platform.callCount)
	}
}
