package hako

import (
	"errors"
	"net"
	"net/netip"
	"strconv"

	"github.com/TokenPLS/Hako/log"
)

// errNoRoute is the answer of the route lookups below when the OS has no route at all to
// an address; errRouteLookupUnsupported when the platform cannot ask.
var (
	errNoRoute                = errors.New("no route")
	errRouteLookupUnsupported = errors.New("route lookup unsupported here")
)

// The two questions the physical-path filter asks the OS, as variables so a test can
// answer them without a routing socket: where a packet to addr leaves right now, and which
// interface carries the unscoped default route -- the physical path the packet tunnel
// binds its outbound sockets to.
var (
	resolverRouteInterface = routeInterfaceIndex
	primaryRouteInterface  = defaultRouteInterfaceIndex
)

// reachableFromThePhysicalPath keeps the resolvers a packet tunnel can actually dial. The
// core binds every outbound socket to the physical interface, so a resolver whose route
// leaves through another interface -- Tailscale's MagicDNS at 100.100.100.100 through its
// own utun, a corporate VPN's resolver through ipsec0 -- is unreachable from inside the
// tunnel even though /etc/resolv.conf lists it. Measured on the reader's Mac (2026-09-06):
// resolv.conf said 100.100.100.100 and fd7a:115c:a1e0::53, both routed through utun9 only.
//
// Read BEFORE this product's tunnel comes up, the unscoped default route is the physical
// interface, and "routed through the same interface as the default route" is the test.
// Point-to-point is deliberately not the test: cellular (pdp_ip0) is point-to-point and is
// the physical path on a phone. Loopback stays (a local resolver is the user's choice, as
// before); an address the OS has no route to goes; and when the platform cannot answer the
// question at all, nothing is dropped -- the filter must never be stricter than the
// knowledge behind it.
func reachableFromThePhysicalPath(servers []string) []string {
	if len(servers) == 0 {
		return servers
	}
	primary, primaryErr := primaryRouteInterface()
	kept := make([]string, 0, len(servers))
	for _, server := range servers {
		addr, err := netip.ParseAddr(server)
		if err != nil {
			// The resolver library preserves nonstandard ports. Route lookup asks
			// about the host address while the returned server keeps its port.
			if endpoint, endpointErr := netip.ParseAddrPort(server); endpointErr == nil {
				addr, err = endpoint.Addr(), nil
			}
		}
		if err != nil || addr.IsLoopback() {
			kept = append(kept, server)
			continue
		}
		index, err := resolverRouteInterface(addr)
		switch {
		case errors.Is(err, errNoRoute):
			log.Warnln("[Apple] system resolver %s has no route at all; dropped", server)
			continue
		case err != nil, primaryErr != nil:
			// The OS would not say (sandbox, platform). Keep it: an unanswered question
			// is not evidence of unreachability.
			kept = append(kept, server)
			continue
		case index != primary:
			log.Warnln("[Apple] system resolver %s is routed through %s, not the primary interface %s a packet tunnel binds to; dropped", server, interfaceNameByIndex(index), interfaceNameByIndex(primary))
			continue
		}
		kept = append(kept, server)
	}
	return kept
}

func interfaceNameByIndex(index int) string {
	if iface, err := net.InterfaceByIndex(index); err == nil {
		return iface.Name
	}
	return "interface#" + strconv.Itoa(index)
}
