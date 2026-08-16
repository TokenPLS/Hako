package hako

import (
	"net"
	"net/netip"
)

// gomobile cannot bind slices, maps, or (string, error) returns across the
// boundary — collections cross as iterator interfaces and optional strings
// as *StringBox.
// Swift implements these protocols for Swift→Go collections and consumes
// Go-side instances for Go→Swift ones.

type StringIterator interface {
	Len() int32
	HasNext() bool
	Next() string
}

// RoutePrefix is one CIDR entry crossing the boundary. The accessor shape
// (Address/Prefix/Mask/String) mirrors libbox tun.go RoutePrefix so the
// Swift openTun0 that builds NEPacketTunnelNetworkSettings reuses near
// verbatim. Fields are private: gomobile exports the methods.
type RoutePrefix struct {
	address netip.Addr
	prefix  int
}

func newRoutePrefix(p netip.Prefix) *RoutePrefix {
	return &RoutePrefix{address: p.Addr(), prefix: p.Bits()}
}

// Address is the network address, e.g. "198.18.0.0".
func (p *RoutePrefix) Address() string {
	return p.address.String()
}

// Prefix is the CIDR prefix length (bits).
func (p *RoutePrefix) Prefix() int32 {
	return int32(p.prefix)
}

// Mask is the dotted/expanded subnet mask NEIPv4Settings/NEIPv6Settings want
// (v4: "255.255.0.0"; v6: expanded).
func (p *RoutePrefix) Mask() string {
	bits := 32
	if p.address.Is6() {
		bits = 128
	}
	return net.IP(net.CIDRMask(p.prefix, bits)).String()
}

// String renders the canonical "addr/prefix" form.
func (p *RoutePrefix) String() string {
	if p == nil {
		return ""
	}
	return netip.PrefixFrom(p.address, p.prefix).String()
}

type RoutePrefixIterator interface {
	Len() int32
	HasNext() bool
	Next() *RoutePrefix
}

// NetworkInterface mirrors libbox platform.go NetworkInterface (WIFI-state
// fields omitted; extend if GetInterfaces needs more).
type NetworkInterface struct {
	Index     int32
	MTU       int32
	Name      string
	Addresses StringIterator
	Flags     int32
	Type      int32
	Metered   bool
}

type NetworkInterfaceIterator interface {
	Len() int32
	HasNext() bool
	Next() *NetworkInterface
}

// StringBox is the optional-string carrier (nil = absent); gomobile cannot
// express *string (libbox panic.go StringBox analogue).
type StringBox struct {
	Value string
}

// WrapString boxes a string for APIs that take an optional value.
func WrapString(value string) *StringBox {
	return &StringBox{Value: value}
}

// iterator is the single generic implementation behind every exported
// iterator interface. Next() on an exhausted iterator returns the zero value.
type iterator[T any] struct {
	values []T
}

func (i *iterator[T]) Len() int32 {
	return int32(len(i.values))
}

func (i *iterator[T]) HasNext() bool {
	return len(i.values) > 0
}

func (i *iterator[T]) Next() T {
	if len(i.values) == 0 {
		var zero T
		return zero
	}
	next := i.values[0]
	i.values = i.values[1:]
	return next
}

func newStringIterator(values []string) StringIterator {
	return &iterator[string]{values}
}

func newRoutePrefixIterator(values []*RoutePrefix) RoutePrefixIterator {
	return &iterator[*RoutePrefix]{values}
}

// mapRoutePrefix adapts a slice of netip.Prefix (mihomo config shape) to the
// boundary iterator (libbox tun.go mapRoutePrefix analogue).
func mapRoutePrefix(prefixes []netip.Prefix) RoutePrefixIterator {
	out := make([]*RoutePrefix, 0, len(prefixes))
	for _, p := range prefixes {
		out = append(out, newRoutePrefix(p))
	}
	return newRoutePrefixIterator(out)
}

func newNetworkInterfaceIterator(values []*NetworkInterface) NetworkInterfaceIterator {
	return &iterator[*NetworkInterface]{values}
}
