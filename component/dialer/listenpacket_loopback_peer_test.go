package dialer

import (
	"context"
	"net/netip"
	"syscall"
	"testing"
)

// Upstream exempts a loopback PEER from interface scoping on the packet path:
// dialer.go:97-100 clears interfaceName when rAddrPort is loopback, "to avoid
// 'The requested address is not valid in its context.'" That exemption sits on
// the branch taken when no socket hook is installed. Apple always installs one
// (the only DefaultSocketHook in this tree), and the hook's signature carries
// the LOCAL address only -- so for every outbound UDP dial, which passes
// address="" with the server as rAddrPort, the hook bound the socket to a
// physical interface and a server on 127.0.0.1 got "can't assign requested
// address" for UDP while TCP went through.
//
// The fix routes a non-global-unicast peer around the hook, onto upstream's own
// branch where the exemption already lives. Nothing is invented here.
func TestListenPacketLeavesALoopbackPeerOutOfTheSocketHook(t *testing.T) {
	orig := DefaultSocketHook
	origScoping := SocketHookScopesInterfaceOnly
	origIface := DefaultInterface.Load()
	t.Cleanup(func() {
		DefaultSocketHook = orig
		SocketHookScopesInterfaceOnly = origScoping
		DefaultInterface.Store(origIface)
	})
	// The exemption asks which hook this is. Hako's does nothing but scope, so
	// it declares that (bind/hako/hook.go) and may be skipped; a hook that
	// audits or tags sockets is not skipped, which is the second half of this
	// file. Without this line the test would be measuring the wrong build.
	SocketHookScopesInterfaceOnly = true
	// No default interface, so the hook-less branch has nothing to bind and
	// the only observable is whether the hook was consulted.
	DefaultInterface.Store("")

	calls := 0
	DefaultSocketHook = func(_, _ string, _ syscall.RawConn) error {
		calls++
		return nil
	}

	for _, peer := range []string{"127.0.0.1:1053", "[::1]:53", "169.254.1.1:53", "224.0.0.251:5353"} {
		before := calls
		pc, err := ListenPacket(context.Background(), "udp", "", netip.MustParseAddrPort(peer))
		if err != nil {
			t.Fatalf("ListenPacket toward %s: %v", peer, err)
		}
		pc.Close()
		if calls != before {
			t.Errorf("peer %s went through the socket hook; upstream leaves a non-global-unicast peer unscoped", peer)
		}
	}

	// A routable peer still goes through the hook: that is what the hook is
	// for, and loosening it was never the aim.
	before := calls
	pc, err := ListenPacket(context.Background(), "udp", "", netip.MustParseAddrPort("223.5.5.5:53"))
	if err != nil {
		t.Fatalf("ListenPacket toward a routable peer: %v", err)
	}
	pc.Close()
	if calls != before+1 {
		t.Errorf("a routable peer must still be scoped by the hook: calls %d -> %d", before, calls)
	}

	// No peer at all -- an unconnected listener -- is the hook's job as before.
	before = calls
	pc, err = ListenPacket(context.Background(), "udp", "", netip.AddrPort{})
	if err != nil {
		t.Fatalf("ListenPacket with no peer: %v", err)
	}
	pc.Close()
	if calls != before+1 {
		t.Errorf("a listener with no peer must still be scoped by the hook: calls %d -> %d", before, calls)
	}
}

// The other half, added 2026-08-27 after Codex pointed out that's
// exemption was written for any hook at all. An embedding platform that
// installs a hook to observe sockets -- not to scope them -- must keep seeing
// every socket, exactly as it did before. Skipping it would have been a
// silent change to somebody else's contract, made while fixing something else.
func TestASocketHookThatDoesNotOnlyScopeStillSeesEveryPeer(t *testing.T) {
	orig := DefaultSocketHook
	origScoping := SocketHookScopesInterfaceOnly
	origIface := DefaultInterface.Load()
	t.Cleanup(func() {
		DefaultSocketHook = orig
		SocketHookScopesInterfaceOnly = origScoping
		DefaultInterface.Store(origIface)
	})
	DefaultInterface.Store("")
	SocketHookScopesInterfaceOnly = false // an auditing hook, as CMFA's may be

	calls := 0
	DefaultSocketHook = func(_, _ string, _ syscall.RawConn) error {
		calls++
		return nil
	}

	for _, peer := range []string{"127.0.0.1:1053", "[::1]:53", "169.254.1.1:53", "224.0.0.251:5353"} {
		before := calls
		pc, err := ListenPacket(context.Background(), "udp", "", netip.MustParseAddrPort(peer))
		if err != nil {
			t.Fatalf("ListenPacket toward %s: %v", peer, err)
		}
		pc.Close()
		if calls != before+1 {
			// The decision number stays in the comment above and out of this
			// string: the message is user-visible text, and the export's
			// task-id gate reads text, not comments. A ledger reference in an
			// assertion message is an internal identifier shipped to whoever
			// reads a public test failure.
			t.Errorf("peer %s skipped a hook that never said it only scopes; the exemption for an "+
				"interface-scoping hook must not reach a hook installed to observe sockets", peer)
		}
	}
}
