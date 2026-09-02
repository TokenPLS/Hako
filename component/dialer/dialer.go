package dialer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/TokenPLS/Hako/common/atomic"
	"github.com/TokenPLS/Hako/component/keepalive"
	"github.com/TokenPLS/Hako/component/mptcp"
	"github.com/TokenPLS/Hako/component/resolver"
)

const (
	DefaultTCPTimeout = 5 * time.Second
	DefaultUDPTimeout = DefaultTCPTimeout

	dualStackFallbackTimeout = 300 * time.Millisecond
)

var (
	tcpConcurrent = atomic.NewBool(false)
)

func SetTcpConcurrent(concurrent bool) {
	tcpConcurrent.Store(concurrent)
}

func GetTcpConcurrent() bool {
	return tcpConcurrent.Load()
}

func DialContext(ctx context.Context, network, address string, options ...Option) (net.Conn, error) {
	opt := applyOptions(options...)

	if opt.network == 4 || opt.network == 6 {
		if strings.Contains(network, "tcp") {
			network = "tcp"
		} else {
			network = "udp"
		}

		network = fmt.Sprintf("%s%d", network, opt.network)
	}

	ips, port, err := parseAddr(ctx, network, address, opt.resolver)
	if err != nil {
		return nil, err
	}

	tcpConcurrent := GetTcpConcurrent()

	switch network {
	case "tcp4", "tcp6", "udp4", "udp6":
		if tcpConcurrent {
			return parallelDialContext(ctx, network, ips, port, opt)
		}
		return serialDialContext(ctx, network, ips, port, opt)
	case "tcp", "udp":
		if tcpConcurrent {
			if opt.prefer != 4 && opt.prefer != 6 {
				return parallelDialContext(ctx, network, ips, port, opt)
			}
			return dualStackDialContext(ctx, parallelDialContext, network, ips, port, opt)
		}
		return dualStackDialContext(ctx, serialDialContext, network, ips, port, opt)
	default:
		return nil, ErrorInvalidedNetworkStack
	}
}

func ListenPacket(ctx context.Context, network, address string, rAddrPort netip.AddrPort, options ...Option) (net.PacketConn, error) {
	opt := applyOptions(options...)

	lc := &net.ListenConfig{}
	if opt.addrReuse {
		addrReuseToListenConfig(lc)
	}
	// A socket hook owns the socket's scoping (see DialContext), but it is
	// handed the LOCAL address only and every outbound UDP dial passes "" for
	// that -- so the hook cannot see the peer, and the exemption below it for
	// a loopback peer never ran while a hook was installed. Apple installs one
	// unconditionally, and a proxy whose server sat on 127.0.0.1 got its UDP
	// bound to a physical interface and "can't assign requested address". A
	// peer that is not global unicast therefore takes the hook-less branch,
	// where upstream's own exemption already lives; a routable peer, or no
	// peer at all, is scoped by the hook as before.
	//
	// The exemption is conditioned on SocketHookScopesInterfaceOnly so it
	// applies to a hook that does nothing but scope. A hook that audits or tags
	// still sees every socket, which is what it saw before -- skipping it
	// would have been a silent change to somebody else's contract.
	peerScopable := !rAddrPort.IsValid() || rAddrPort.Addr().Unmap().IsGlobalUnicast()
	if !SocketHookScopesInterfaceOnly {
		peerScopable = true
	}
	if DefaultSocketHook != nil && peerScopable { // ignore interfaceName, routingMark when DefaultSocketHook not null (in CMFA)
		socketHookToListenConfig(lc)
	} else {
		if opt.interfaceName == "" {
			opt.interfaceName = DefaultInterface.Load()
		}
		if opt.interfaceName == "" {
			if finder := DefaultInterfaceFinder.Load(); finder != nil {
				opt.interfaceName = finder.FindInterfaceName(rAddrPort.Addr().Unmap())
			}
		}
		if !peerScopable {
			// avoid "The requested address is not valid in its context."
			// Upstream tested IsLoopback here; not-global-unicast is what its
			// darwin bindControl tests (bind_darwin.go:14-19), and the two
			// paths should refuse to scope the same peers.
			opt.interfaceName = ""
		}
		if opt.interfaceName != "" {
			bind := bindIfaceToListenConfig
			if opt.fallbackBind {
				bind = fallbackBindIfaceToListenConfig
			}
			addr, err := bind(opt.interfaceName, lc, network, address, rAddrPort)
			if err != nil {
				return nil, err
			}
			address = addr
		}
		if opt.routingMark == 0 {
			opt.routingMark = int(DefaultRoutingMark.Load())
		}
		if opt.routingMark != 0 {
			bindMarkToListenConfig(opt.routingMark, lc, network, address)
		}
	}

	return lc.ListenPacket(ctx, network, address)
}

func dialContext(ctx context.Context, network string, destination netip.Addr, port string, opt option) (net.Conn, error) {
	var address string
	destination, port = resolver.LookupIP4P(destination, port)
	originalDestination := destination
	var err error
	destination, err = TransformPhysicalAddress(network, destination)
	if err != nil {
		return nil, err
	}
	// IPv4Only/IPv6Only select the logical DNS answer family. A platform
	// transform may still need an IPv6 socket to reach that IPv4 target through
	// NAT64 (or vice versa), so align the concrete socket family afterwards.
	if originalDestination.Is4() && destination.Is6() {
		switch network {
		case "tcp4":
			network = "tcp6"
		case "udp4":
			network = "udp6"
		}
	} else if originalDestination.Is6() && destination.Is4() {
		switch network {
		case "tcp6":
			network = "tcp4"
		case "udp6":
			network = "udp4"
		}
	}
	address = net.JoinHostPort(destination.String(), port)

	netDialer := opt.netDialer
	switch netDialer.(type) {
	case nil:
		netDialer = &net.Dialer{}
	case *net.Dialer:
		_netDialer := *netDialer.(*net.Dialer)
		netDialer = &_netDialer // make a copy
	default:
		return netDialer.DialContext(ctx, network, address)
	}

	dialer := netDialer.(*net.Dialer)
	keepalive.SetNetDialer(dialer)
	mptcp.SetNetDialer(dialer, opt.mpTcp)

	// A socket hook owns the socket's scoping, so interfaceName, routingMark and tfo are
	// deliberately ignored while one is installed. The comment here used to say "in CMFA",
	// which reads as Android-only; the Apple binding installs the same hook
	// (bind/hako/hook.go), so this branch is the normal path on iOS and macOS too. That
	// mis-reading is what left the tfo option labelled as effective in the iOS UI.
	if DefaultSocketHook != nil {
		socketHookToToDialer(dialer)
	} else {
		if opt.interfaceName == "" {
			opt.interfaceName = DefaultInterface.Load()
		}
		if opt.interfaceName == "" {
			if finder := DefaultInterfaceFinder.Load(); finder != nil {
				opt.interfaceName = finder.FindInterfaceName(destination)
			}
		}
		if opt.interfaceName != "" {
			bind := bindIfaceToDialer
			if opt.fallbackBind {
				bind = fallbackBindIfaceToDialer
			}
			if err := bind(opt.interfaceName, dialer, network, destination); err != nil {
				return nil, err
			}
		}
		if opt.routingMark == 0 {
			opt.routingMark = int(DefaultRoutingMark.Load())
		}
		if opt.routingMark != 0 {
			bindMarkToDialer(opt.routingMark, dialer, network, destination)
		}
		if opt.tfo && !DisableTFO {
			return dialTFO(ctx, *dialer, network, address)
		}
	}

	return dialer.DialContext(ctx, network, address)
}

func ICMPControl(destination netip.Addr) func(network, address string, conn syscall.RawConn) error {
	return func(network, address string, conn syscall.RawConn) error {
		if DefaultSocketHook != nil {
			return DefaultSocketHook(network, address, conn)
		}
		dialer := &net.Dialer{}
		interfaceName := DefaultInterface.Load()
		if interfaceName == "" {
			if finder := DefaultInterfaceFinder.Load(); finder != nil {
				interfaceName = finder.FindInterfaceName(destination)
			}
		}
		if interfaceName != "" {
			if err := bindIfaceToDialer(interfaceName, dialer, network, destination); err != nil {
				return err
			}
		}
		routingMark := int(DefaultRoutingMark.Load())
		if routingMark != 0 {
			bindMarkToDialer(routingMark, dialer, network, destination)
		}
		if dialer.ControlContext != nil {
			return dialer.ControlContext(context.TODO(), network, address, conn)
		}
		return nil
	}
}

type dialFunc func(ctx context.Context, network string, ips []netip.Addr, port string, opt option) (net.Conn, error)

func dualStackDialContext(ctx context.Context, dialFn dialFunc, network string, ips []netip.Addr, port string, opt option) (net.Conn, error) {
	ipv4s, ipv6s := resolver.SortationAddr(ips)
	if len(ipv4s) == 0 && len(ipv6s) == 0 {
		return nil, ErrorNoIpAddress
	}
	if len(ipv4s) == 0 && len(ipv6s) != 0 {
		return dialFn(ctx, network, ipv6s, port, opt)
	}
	if len(ipv4s) != 0 && len(ipv6s) == 0 {
		return dialFn(ctx, network, ipv4s, port, opt)
	}

	preferIPVersion := opt.prefer

	// The fallback ticker only ever fires for a fallback that exists, and a fallback
	// only exists when one leg is non-primary -- which requires prefer to be 4 or 6.
	// With prefer unset both legs are primary, the first success returns immediately,
	// and the ticker is allocated and stopped for nothing on every dual-stack dial.
	// Created only when it can fire; a nil channel blocks forever in select, which is
	// exactly the wanted behaviour.
	var fallbackTick <-chan time.Time
	if preferIPVersion == 4 || preferIPVersion == 6 {
		fallbackTicker := time.NewTicker(dualStackFallbackTimeout)
		defer fallbackTicker.Stop()
		fallbackTick = fallbackTicker.C
	}

	results := make(chan dialResult)
	returned := make(chan struct{})
	defer close(returned)

	var wg sync.WaitGroup

	// Each leg gets its own cancellable context so a leg we are no longer waiting for is
	// released immediately. Previously both legs ran on the caller's context, so a leg
	// that stalled held its dial -- and its socket, and the radio wake behind it -- until
	// the caller's own deadline, five seconds by default.
	//
	// EVERY leg's cancel runs before returning, the winner's included. An earlier version
	// spared the winner out of caution about a custom opt.netDialer still using its
	// context; that was wrong, because Go retains a cancellable child in its parent's
	// children set until one of the two cancels runs, so one uncancelled winner per
	// successful dial accumulated for the parent's whole life. Cancelling the winner is
	// safe by the contract net.Dialer documents -- a connection, once established, is
	// unaffected by later expiry of its dial context -- and this tree already depends on
	// exactly that: tunnel.go dials under a WithTimeout it cancels immediately afterwards
	// and then uses the connection for the rest of its life.
	cancels := make([]context.CancelFunc, 0, 2)
	cancelAllLegs := func() {
		for _, cancel := range cancels {
			cancel()
		}
	}

	racer := func(legCtx context.Context, cancel context.CancelFunc, leg int, ips []netip.Addr, isPrimary bool) {
		defer wg.Done()
		result := dialResult{isPrimary: isPrimary}
		defer func() {
			select {
			case results <- result:
			case <-returned:
				if result.Conn != nil && result.error == nil {
					_ = result.Conn.Close()
				}
				cancel()
			}
		}()
		result.Conn, result.error = dialFn(legCtx, network, ips, port, opt)
	}

	startRacer := func(ips []netip.Addr, isPrimary bool) {
		legCtx, cancel := context.WithCancel(ctx)
		leg := len(cancels)
		cancels = append(cancels, cancel)
		wg.Add(1)
		go racer(legCtx, cancel, leg, ips, isPrimary)
	}

	if len(ipv4s) != 0 {
		startRacer(ipv4s, preferIPVersion != 6)
	}

	if len(ipv6s) != 0 {
		startRacer(ipv6s, preferIPVersion != 4)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var fallback dialResult
	var errs []error

loop:
	for {
		select {
		case <-fallbackTick:
			if fallback.error == nil && fallback.Conn != nil {
				cancelAllLegs()
				return fallback.Conn, nil
			}
		case res, ok := <-results:
			if !ok {
				break loop
			}
			if res.error == nil {
				if res.isPrimary {
					if fallback.error == nil && fallback.Conn != nil {
						go func() { // close fallback connection in new goroutine to avoid blocking
							_ = fallback.Conn.Close()
						}()
					}
					cancelAllLegs()
					return res.Conn, nil
				}
				fallback = res
			} else {
				if res.isPrimary {
					errs = append([]error{fmt.Errorf("connect failed: %w", res.error)}, errs...)
				} else {
					errs = append(errs, fmt.Errorf("connect failed: %w", res.error))
				}
			}
		}
	}

	if fallback.error == nil && fallback.Conn != nil {
		cancelAllLegs()
		return fallback.Conn, nil
	}
	cancelAllLegs()
	return nil, errors.Join(errs...)
}

func parallelDialContext(ctx context.Context, network string, ips []netip.Addr, port string, opt option) (net.Conn, error) {
	if len(ips) == 0 {
		return nil, ErrorNoIpAddress
	}
	if len(ips) == 1 {
		return dialContext(ctx, network, ips[0], port, opt)
	}
	results := make(chan dialResult)
	returned := make(chan struct{})
	defer close(returned)
	racer := func(ctx context.Context, ip netip.Addr) {
		result := dialResult{isPrimary: true, ip: ip}
		defer func() {
			select {
			case results <- result:
			case <-returned:
				if result.Conn != nil && result.error == nil {
					_ = result.Conn.Close()
				}
			}
		}()
		result.Conn, result.error = dialContext(ctx, network, ip, port, opt)
	}

	for _, ip := range ips {
		go racer(ctx, ip)
	}
	var errs []error
	for i := 0; i < len(ips); i++ {
		res := <-results
		if res.error == nil {
			return res.Conn, nil
		}
		errs = append(errs, res.error)
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return nil, os.ErrDeadlineExceeded
}

func serialDialContext(ctx context.Context, network string, ips []netip.Addr, port string, opt option) (net.Conn, error) {
	if len(ips) == 0 {
		return nil, ErrorNoIpAddress
	}
	var errs []error
	for _, ip := range ips {
		if conn, err := dialContext(ctx, network, ip, port, opt); err == nil {
			return conn, nil
		} else {
			errs = append(errs, err)
		}
	}
	return nil, errors.Join(errs...)
}

type dialResult struct {
	ip netip.Addr
	net.Conn
	error
	isPrimary bool
}

func parseAddr(ctx context.Context, network, address string, preferResolver resolver.Resolver) ([]netip.Addr, string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, "-1", err
	}

	if preferResolver == nil {
		preferResolver = resolver.ProxyServerHostResolver
	}

	var ips []netip.Addr
	switch network {
	case "tcp4", "udp4":
		ips, err = resolver.LookupIPv4WithResolver(ctx, host, preferResolver)
	case "tcp6", "udp6":
		ips, err = resolver.LookupIPv6WithResolver(ctx, host, preferResolver)
	default:
		ips, err = resolver.LookupIPWithResolver(ctx, host, preferResolver)
	}
	if err != nil {
		return nil, "-1", fmt.Errorf("dns resolve failed: %w", err)
	}
	for i, ip := range ips {
		if ip.Is4In6() {
			ips[i] = ip.Unmap()
		}
	}
	return ips, port, nil
}

type Dialer struct {
	Opt option
}

func (d Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return DialContext(ctx, network, address, WithOption(d.Opt))
}

func (d Dialer) ListenPacket(ctx context.Context, network, address string, rAddrPort netip.AddrPort) (net.PacketConn, error) {
	return ListenPacket(ctx, ParseNetwork(network, rAddrPort.Addr()), address, rAddrPort, WithOption(d.Opt))
}

func NewDialer(options ...Option) Dialer {
	opt := applyOptions(options...)
	return Dialer{Opt: opt}
}
