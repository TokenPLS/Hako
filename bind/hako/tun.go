package hako

import (
	"errors"
	"fmt"
	"net/netip"
	"sync/atomic"

	LC "github.com/TokenPLS/Hako/listener/config"
)

// The Apple/Core link MTU is selected once by Setup. 4064 remains the current
// compatibility default until the device matrix chooses a final value;
// 1280 is the IPv6 minimum and 9000 is a conservative upper bound for the
// gVisor/PacketFlow buffers. The YAML value is never trusted on iOS.
const (
	defaultTunMTU int32 = 4064
	minimumTunMTU int32 = 1280
	maximumTunMTU int32 = 9000
)

var setupTunMTU atomic.Int32

func validateTunMTU(mtu int) error {
	if mtu == 0 {
		return nil
	}
	if mtu < int(minimumTunMTU) || mtu > int(maximumTunMTU) {
		return fmt.Errorf("hako: SetupOptions.TunMTU must be 0 or %d...%d, got %d", minimumTunMTU, maximumTunMTU, mtu)
	}
	return nil
}

func setTunMTU(mtu int32) {
	if mtu == 0 {
		mtu = defaultTunMTU
	}
	setupTunMTU.Store(mtu)
}

func normalizedTunMTU(mtu int) int32 {
	if mtu == 0 {
		return defaultTunMTU
	}
	return int32(mtu) // caller validated the range before narrowing
}

func effectiveTunMTU() int32 {
	if mtu := setupTunMTU.Load(); mtu != 0 {
		return mtu
	}
	return defaultTunMTU
}

// packetFlowBridgeDevice marks a public NEPacketTunnelFlow adapter fd. The fd
// is one end of an AF_UNIX/SOCK_DGRAM socketpair, not Apple's private utun fd.
// listener/sing_tun uses the marker to skip utun-only name probing.
const packetFlowBridgeDevice = "hako-packet-flow"

// TunMTU exposes the startup-selected value to Swift. The same value is
// forced into cfg.General.Tun before gVisor starts.
func TunMTU() int32 {
	return effectiveTunMTU()
}

// TunOptions is the read-only view of cfg.General.Tun handed to
// PlatformInterface.OpenTun. Swift calls these getters to build
// NEPacketTunnelNetworkSettings (addresses, MTU, DNS, routes) and returns a
// utun fd. Surface mirrors libbox tun.go, trimmed to what iOS NENetworkSettings
// consumes — Android package/UID and the in-core HTTP-proxy getters are
// dropped.
type TunOptions interface {
	GetInet4Address() RoutePrefixIterator
	GetInet6Address() RoutePrefixIterator
	GetDNSServerAddress() (*StringBox, error)
	GetMTU() int32
	GetAutoRoute() bool
	GetStrictRoute() bool
	GetInet4RouteAddress() RoutePrefixIterator
	GetInet6RouteAddress() RoutePrefixIterator
	GetInet4RouteExcludeAddress() RoutePrefixIterator
	GetInet6RouteExcludeAddress() RoutePrefixIterator
}

// tunOptions adapts mihomo's listener/config.Tun to the TunOptions surface.
// Private, like libbox's — gomobile bridges it through the TunOptions
// interface when Go passes it to platform.OpenTun.
type tunOptions struct {
	tun *LC.Tun
}

// newTunOptions snapshots the tun section for the OpenTun handoff.
func newTunOptions(tun *LC.Tun) TunOptions {
	return &tunOptions{tun: tun}
}

func (o *tunOptions) GetInet4Address() RoutePrefixIterator {
	return mapRoutePrefix(o.tun.Inet4Address)
}

func (o *tunOptions) GetInet6Address() RoutePrefixIterator {
	return mapRoutePrefix(o.tun.Inet6Address)
}

// GetDNSServerAddress returns the in-tunnel DNS server IP: the tun gateway's
// next address (Inet4Address[0]+1), matching libbox. iOS points
// NEDNSSettings here; the reconciliation with mihomo's own DNSHijack
// (single-source invariant) is enforced by dnsHijackCovers.
func (o *tunOptions) GetDNSServerAddress() (*StringBox, error) {
	if len(o.tun.Inet4Address) == 0 || o.tun.Inet4Address[0].Bits() == 32 {
		return nil, errors.New("hako: need one more IPv4 address for DNS hijacking")
	}
	return WrapString(o.tun.Inet4Address[0].Addr().Next().String()), nil
}

// GetMTU returns the configured MTU, falling back to the effective setup MTU when unset so
// the getter never yields 0.
func (o *tunOptions) GetMTU() int32 {
	if o.tun.MTU == 0 {
		return effectiveTunMTU()
	}
	return int32(o.tun.MTU)
}

func (o *tunOptions) GetAutoRoute() bool {
	return o.tun.AutoRoute
}

func (o *tunOptions) GetStrictRoute() bool {
	return o.tun.StrictRoute
}

func (o *tunOptions) GetInet4RouteAddress() RoutePrefixIterator {
	return mapRoutePrefix(routePrefixesByFamily(o.tun.Inet4RouteAddress, o.tun.RouteAddress, true))
}

func (o *tunOptions) GetInet6RouteAddress() RoutePrefixIterator {
	return mapRoutePrefix(routePrefixesByFamily(o.tun.Inet6RouteAddress, o.tun.RouteAddress, false))
}

func (o *tunOptions) GetInet4RouteExcludeAddress() RoutePrefixIterator {
	return mapRoutePrefix(routePrefixesByFamily(o.tun.Inet4RouteExcludeAddress, o.tun.RouteExcludeAddress, true))
}

func (o *tunOptions) GetInet6RouteExcludeAddress() RoutePrefixIterator {
	return mapRoutePrefix(routePrefixesByFamily(o.tun.Inet6RouteExcludeAddress, o.tun.RouteExcludeAddress, false))
}

func routePrefixesByFamily(specific, generic []netip.Prefix, ipv4 bool) []netip.Prefix {
	routes := append([]netip.Prefix(nil), specific...)
	for _, prefix := range generic {
		if prefix.Addr().Is4() == ipv4 {
			routes = append(routes, prefix)
		}
	}
	return routes
}
