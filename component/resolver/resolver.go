package resolver

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/TokenPLS/Hako/common/utils"
	"github.com/TokenPLS/Hako/component/trie"

	"github.com/metacubex/randv2"
	"github.com/miekg/dns"
)

var (
	// DefaultResolver aim to resolve ip
	DefaultResolver Resolver

	// ProxyServerHostResolver resolve ip for proxies server host, only nil when DefaultResolver is nil
	ProxyServerHostResolver Resolver

	// DirectHostResolver resolve ip for direct outbound host, only nil when DefaultResolver is nil
	DirectHostResolver Resolver

	// SystemResolver always using system dns, and was init in dns module
	SystemResolver Resolver

	// DisableIPv6 means don't resolve ipv6 host
	// default value is true
	DisableIPv6 = true

	// DefaultHosts aim to resolve hosts
	DefaultHosts = NewHosts(trie.New[HostValue]())

	// DefaultDNSTimeout defined the default dns request timeout
	DefaultDNSTimeout = time.Second * 5
)

var (
	ErrIPNotFound   = errors.New("couldn't find ip")
	ErrIPVersion    = errors.New("ip version error")
	ErrIPv6Disabled = errors.New("ipv6 disabled")
)

type Resolver interface {
	LookupIP(ctx context.Context, host string) (ips []netip.Addr, err error)
	LookupIPv4(ctx context.Context, host string) (ips []netip.Addr, err error)
	LookupIPv6(ctx context.Context, host string) (ips []netip.Addr, err error)
	ResolveECH(ctx context.Context, host string) ([]byte, error)
	ExchangeContext(ctx context.Context, m *dns.Msg) (msg *dns.Msg, err error)
	Invalid() bool
	ClearCache()
	ResetConnection()
}

// LookupIPv4WithResolver same as LookupIPv4, but with a resolver
func LookupIPv4WithResolver(ctx context.Context, host string, r Resolver) ([]netip.Addr, error) {
	if node, ok := DefaultHosts.Search(host, false); ok {
		if addrs := utils.Filter(node.IPs, func(ip netip.Addr) bool {
			return ip.Is4()
		}); len(addrs) > 0 {
			return addrs, nil
		}
	}

	ip, err := netip.ParseAddr(host)
	if err == nil {
		ip = ip.Unmap()
		if ip.Is4() {
			return []netip.Addr{ip}, nil
		}
		return []netip.Addr{}, ErrIPVersion
	}

	if r != nil && r.Invalid() {
		return r.LookupIPv4(ctx, host)
	}

	return SystemResolver.LookupIPv4(ctx, host)
}

// LookupIPv4 with a host, return ipv4 list
func LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	return LookupIPv4WithResolver(ctx, host, DefaultResolver)
}

// ResolveIPv4WithResolver same as ResolveIPv4, but with a resolver
func ResolveIPv4WithResolver(ctx context.Context, host string, r Resolver) (netip.Addr, error) {
	ips, err := LookupIPv4WithResolver(ctx, host, r)
	if err != nil {
		return netip.Addr{}, err
	} else if len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("%w: %s", ErrIPNotFound, host)
	}
	return ips[randv2.IntN(len(ips))], nil
}

// ResolveIPv4 with a host, return ipv4
func ResolveIPv4(ctx context.Context, host string) (netip.Addr, error) {
	return ResolveIPv4WithResolver(ctx, host, DefaultResolver)
}

// LookupIPv6WithResolver same as LookupIPv6, but with a resolver
func LookupIPv6WithResolver(ctx context.Context, host string, r Resolver) ([]netip.Addr, error) {
	if DisableIPv6 {
		return nil, ErrIPv6Disabled
	}

	if node, ok := DefaultHosts.Search(host, false); ok {
		if addrs := utils.Filter(node.IPs, func(ip netip.Addr) bool {
			return ip.Is6()
		}); len(addrs) > 0 {
			return addrs, nil
		}
	}

	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if ip.Is6() {
			return []netip.Addr{ip}, nil
		}
		return nil, ErrIPVersion
	}

	if r != nil && r.Invalid() {
		return r.LookupIPv6(ctx, host)
	}

	return SystemResolver.LookupIPv6(ctx, host)
}

// LookupIPv6 with a host, return ipv6 list
func LookupIPv6(ctx context.Context, host string) ([]netip.Addr, error) {
	return LookupIPv6WithResolver(ctx, host, DefaultResolver)
}

// ResolveIPv6WithResolver same as ResolveIPv6, but with a resolver
func ResolveIPv6WithResolver(ctx context.Context, host string, r Resolver) (netip.Addr, error) {
	ips, err := LookupIPv6WithResolver(ctx, host, r)
	if err != nil {
		return netip.Addr{}, err
	} else if len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("%w: %s", ErrIPNotFound, host)
	}
	return ips[randv2.IntN(len(ips))], nil
}

func ResolveIPv6(ctx context.Context, host string) (netip.Addr, error) {
	return ResolveIPv6WithResolver(ctx, host, DefaultResolver)
}

// LookupIPWithResolver same as LookupIP, but with a resolver
func LookupIPWithResolver(ctx context.Context, host string, r Resolver) ([]netip.Addr, error) {
	if node, ok := DefaultHosts.Search(host, false); ok {
		return node.IPs, nil
	}

	if r != nil && r.Invalid() {
		if DisableIPv6 {
			return r.LookupIPv4(ctx, host)
		}
		return r.LookupIP(ctx, host)
	} else if DisableIPv6 {
		return LookupIPv4WithResolver(ctx, host, r)
	}

	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		return []netip.Addr{ip}, nil
	}

	return SystemResolver.LookupIP(ctx, host)
}

// LookupIP with a host, return ip
func LookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	return LookupIPWithResolver(ctx, host, DefaultResolver)
}

// ResolveIPWithResolver same as ResolveIP, but with a resolver
func ResolveIPWithResolver(ctx context.Context, host string, r Resolver) (netip.Addr, error) {
	ips, err := LookupIPWithResolver(ctx, host, r)
	if err != nil {
		return netip.Addr{}, err
	} else if len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("%w: %s", ErrIPNotFound, host)
	}
	ipv4s, ipv6s := SortationAddr(ips)
	if len(ipv4s) > 0 {
		return ipv4s[randv2.IntN(len(ipv4s))], nil
	}
	return ipv6s[randv2.IntN(len(ipv6s))], nil
}

// ResolveIP with a host, return ip and priority return TypeA
func ResolveIP(ctx context.Context, host string) (netip.Addr, error) {
	return ResolveIPWithResolver(ctx, host, DefaultResolver)
}

// ResolveIPPrefer6WithResolver same as ResolveIP, but with a resolver
func ResolveIPPrefer6WithResolver(ctx context.Context, host string, r Resolver) (netip.Addr, error) {
	ips, err := LookupIPWithResolver(ctx, host, r)
	if err != nil {
		return netip.Addr{}, err
	} else if len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("%w: %s", ErrIPNotFound, host)
	}
	ipv4s, ipv6s := SortationAddr(ips)
	if len(ipv6s) > 0 {
		return ipv6s[randv2.IntN(len(ipv6s))], nil
	}
	return ipv4s[randv2.IntN(len(ipv4s))], nil
}

// ResolveIPPrefer6 with a host, return ip and priority return TypeAAAA
func ResolveIPPrefer6(ctx context.Context, host string) (netip.Addr, error) {
	return ResolveIPPrefer6WithResolver(ctx, host, DefaultResolver)
}

func ResolveECHWithResolver(ctx context.Context, host string, r Resolver) ([]byte, error) {
	if r != nil && r.Invalid() {
		return r.ResolveECH(ctx, host)
	}
	return SystemResolver.ResolveECH(ctx, host)
}

func ResolveECH(ctx context.Context, host string) ([]byte, error) {
	return ResolveECHWithResolver(ctx, host, DefaultResolver)
}

// ClearCache and ResetConnection must reach EVERY configured resolver, not just the two
// obvious ones. ProxyServerHostResolver and DirectHostResolver exist whenever
// proxy-server-nameserver or direct-nameserver is configured, and skipping them left their
// caches and upstream sockets scoped to the previous network path after a change. The
// omission is invisible from the resolution path, which only ever calls LookupIP.
// ResolverAggregate is implemented by a Resolver whose ClearCache and ResetConnection fan
// out to other Resolvers it holds -- dns.Resolvers, which walks its main, proxy and direct
// members. updateDNS registers that aggregate as DefaultResolver AND registers the
// aggregate's own ProxyResolver / DirectResolver as ProxyServerHostResolver and
// DirectHostResolver, so the same member is reachable twice through different values.
// Identity cannot see that; the aggregate has to say what it contains, and the lifecycle
// helpers ask before visiting a candidate on its own.
type ResolverAggregate interface {
	ContainsResolver(Resolver) bool
}

func eachConfiguredResolver(do func(Resolver)) {
	// Deduplicated twice over, because the four are not four distinct objects. By identity,
	// for the case where two variables hold the very same value; and by containment, for
	// the case updateDNS actually builds -- DefaultResolver holds the whole dns.Resolvers
	// aggregate while ProxyServerHostResolver and DirectHostResolver hold that aggregate's
	// own members, whose ClearCache and ResetConnection the aggregate already fans out to.
	// Identity alone let each member be visited a second time, in its own goroutine; that
	// was "idempotent so merely wasteful" until v1.19.30 started sharing one raw DNS
	// transport across those members, where a second reset landing after a query has
	// rebuilt the transport closes the new one.
	//
	// SystemResolver is initialised by the dns module and needs no nil check; the rest are
	// nil until the corresponding option is configured.
	candidates := []Resolver{DefaultResolver, ProxyServerHostResolver, DirectHostResolver, SystemResolver}
	seen := make(map[Resolver]struct{}, len(candidates))
	for i, r := range candidates {
		if r == nil {
			continue
		}
		if _, duplicate := seen[r]; duplicate {
			continue
		}
		covered := false
		for j, other := range candidates {
			if j == i || other == nil {
				continue
			}
			if aggregate, ok := other.(ResolverAggregate); ok && aggregate.ContainsResolver(r) {
				covered = true
				break
			}
		}
		if covered {
			continue
		}
		seen[r] = struct{}{}
		do(r)
	}
}

func ClearCache() {
	eachConfiguredResolver(func(r Resolver) { go r.ClearCache() })
}

func ResetConnection() {
	eachConfiguredResolver(func(r Resolver) { go r.ResetConnection() })
}

// CloseQueries ends in-flight queries. It is the SHUTDOWN signal and must not be called on a
// path change: ResetConnection is what a path change wants, and conflating the two is what made
// every default-interface change hand the caller a SERVFAIL (see dns.Resolver's queryMu).
//
// Not added to the Resolver interface: the optional assertion keeps implementations that have no
// query lifetime of their own -- and any future one -- from having to carry a no-op. Unlike its
// neighbours this runs SYNCHRONOUSLY, because a shutdown that returns before the cancellations
// land is the leak it exists to close.
func CloseQueries() {
	eachConfiguredResolver(func(r Resolver) {
		if closer, ok := r.(interface{ CloseQueries() }); ok {
			closer.CloseQueries()
		}
	})
}

func SortationAddr(ips []netip.Addr) (ipv4s, ipv6s []netip.Addr) {
	for _, v := range ips {
		if v.Unmap().Is4() {
			ipv4s = append(ipv4s, v)
		} else {
			ipv6s = append(ipv6s, v)
		}
	}
	return
}
