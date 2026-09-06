package hako

import (
	"net"
	"net/netip"
	"syscall"

	"github.com/TokenPLS/Hako/component/dialer"
)

// interfaceScopableTarget reports whether a destination is one an interface
// scope can apply to, using upstream's own test for it. component/dialer/
// bind_darwin.go:14-19 opens bindControl with exactly this check -- an address
// that is not global unicast is returned from unbound -- so on darwin upstream
// never scopes a loopback, link-local, multicast or unspecified destination to
// an interface. That guard sits INSIDE the bind function, which is only reached
// on the branch taken when no socket hook is installed; this binding installs
// one, so upstream's guard has never run on Apple.
//
// The predicate is upstream's, not a narrower one of our own choosing: an
// earlier draft here tested only for loopback, which would have kept scoping
// link-local and multicast destinations that upstream leaves alone.
func interfaceScopableTarget(address string) bool {
	if address == "" {
		return true
	}
	addrPort, err := netip.ParseAddrPort(address)
	if err != nil {
		host, _, splitErr := net.SplitHostPort(address)
		if splitErr != nil {
			host = address
		}
		if host == "localhost" {
			return false
		}
		addr, parseErr := netip.ParseAddr(host)
		if parseErr != nil {
			// A name this layer cannot resolve to an address is left to the
			// platform, which is what happened before this exemption existed.
			return true
		}
		return addr.Unmap().IsGlobalUnicast()
	}
	return addrPort.Addr().Unmap().IsGlobalUnicast()
}

func installSocketHook(platform PlatformInterface) {
	if platform == nil || !platform.UsePlatformAutoDetectInterfaceControl() {
		dialer.DefaultSocketHook = nil
		dialer.SocketHookScopesInterfaceOnly = false
		installPhysicalAddressTransform(false)
		return
	}
	installPhysicalAddressTransform(true)
	// This hook only scopes sockets to an interface, which is what lets the
	// packet path skip it for a peer that must not be scoped
	// (component/dialer/dialer.go:96). Declared rather than assumed: the
	// exemption used to apply to any hook at all, including one an embedder
	// installed to audit sockets.
	dialer.SocketHookScopesInterfaceOnly = true
	dialer.DefaultSocketHook = func(_, address string, conn syscall.RawConn) error {
		// A destination that is not global unicast is never scoped to an
		// interface. Upstream draws this line itself, twice: component/dialer/
		// bind_darwin.go:14-19 returns from bindControl without binding, and
		// component/dialer/dialer.go:97-100 clears interfaceName on the listen
		// path "to avoid 'The requested address is not valid in its context.'".
		// Both live on the branch taken when no socket hook is installed, and
		// this binding installs one, so neither has ever run on Apple.
		//
		// The cost was a real one: a configuration whose dns.listen and
		// proxy-server-nameserver both name 127.0.0.1:1053 (a shape copied
		// straight from desktop tutorials) resolves nothing at all, because
		// every query to its own resolver leaves on a socket bound to en0 or
		// pdp_ip0, where 127.0.0.1 does not exist. The kernel reports
		// "write udp 127.0.0.1:x->127.0.0.1:1053: write: can't assign requested
		// address" and every dial that needed a proxy server's name fails with
		// it.
		//
		// Skipping the bind here does not weaken what the hook is for. The hook
		// exists so our own outbound traffic is not routed back into the tunnel
		// a destination that is not global unicast never
		// reaches the routing table at all, so there is nothing to keep out of
		// the tunnel.
		//
		// KNOWN GAP, not a safe edge. A packet socket opened on a WILDCARD local
		// address (":0") and then written to a loopback PEER still gets bound,
		// because the address this hook receives is the local one and says
		// nothing about the peer. Upstream does not have this gap: its listen
		// path tests rAddrPort -- the peer -- at component/dialer/dialer.go:97-100,
		// and the hook branch never sees that argument.
		//
		// It is reachable, and the iOS lane found where: every outbound UDP
		// dial passes address="" with the server as rAddrPort
		// (adapter/outbound/shadowsocks.go:242, shadowsocksr.go:92,
		// socks5.go:142, hysteria.go:78, gost_relay.go:57). So a proxy whose
		// SERVER is on loopback -- a local sidecar on macOS, 127.0.0.1:1080 --
		// gets its TCP exempted here and its UDP still bound to en0, failing
		// with the same "can't assign requested address". iOS has no local
		// sidecar; macOS does.
		//
		// Closing it means teaching the hook branch about rAddrPort, which is a
		// change to component/dialer/dialer.go:86 -- an upstream file, so a
		// registered fork delta and its own commit, not a rider on this one.
		if !interfaceScopableTarget(address) {
			return nil
		}
		var ctrlErr error
		if err := conn.Control(func(fd uintptr) {
			ctrlErr = platform.AutoDetectInterfaceControl(int32(fd))
		}); err != nil {
			return err
		}
		return ctrlErr
	}
}
