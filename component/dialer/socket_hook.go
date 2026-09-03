package dialer

import (
	"context"
	"net"
	"net/netip"
	"syscall"
)

// SocketControl
// never change type traits because it's used in CMFA
type SocketControl func(network, address string, conn syscall.RawConn) error

// DefaultSocketHook
// never change type traits because it's used in CMFA
var DefaultSocketHook SocketControl

// SocketHookScopesInterfaceOnly declares that DefaultSocketHook does nothing
// but bind sockets to an interface, so skipping it for a peer that must not be
// scoped costs nothing.
//
// The packet path's exemption (dialer.go:96) originally applied to ANY hook,
// and that quietly changed what an embedding platform's hook observes: a
// consumer using it to audit or tag sockets stopped being called for loopback,
// link-local and multicast peers. Hako's hook only scopes, so it can be skipped
// safely -- CMFA's may not be, and it never asked to be. This flag is how the
// exemption says which hook it is talking about instead of assuming every hook
// is the same one. Default false: an embedder that does not set it keeps
// upstream's behaviour exactly.
//
// Raised by Codex on 2026-08-27 while reviewing: the fix was right for
// Apple and its boundary was drawn one level too wide.
var SocketHookScopesInterfaceOnly bool

// AddressTransform lets an embedding platform adapt a resolved physical
// destination before socket creation. Hako's Apple binding uses this for the
// system getaddrinfo DNS64/NAT64 synthesis required on IPv6-only paths. It is
// nil in ordinary mihomo builds and must never rewrite logical proxy payload
// destinations -- only the outer transport address passed to this dialer.
type AddressTransform func(network string, destination netip.Addr) (netip.Addr, error)

var DefaultAddressTransform AddressTransform

func TransformPhysicalAddress(network string, destination netip.Addr) (netip.Addr, error) {
	if DefaultAddressTransform == nil || !destination.IsValid() {
		return destination, nil
	}
	return DefaultAddressTransform(network, destination)
}

func socketHookToToDialer(dialer *net.Dialer) {
	addControlToDialer(dialer, func(ctx context.Context, network, address string, c syscall.RawConn) error {
		return DefaultSocketHook(network, address, c)
	})
}

func socketHookToListenConfig(lc *net.ListenConfig) {
	addControlToListenConfig(lc, func(ctx context.Context, network, address string, c syscall.RawConn) error {
		return DefaultSocketHook(network, address, c)
	})
}
