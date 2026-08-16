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
