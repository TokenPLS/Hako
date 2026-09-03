//go:build darwin

package hako

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"

	"github.com/TokenPLS/Hako/adapter/inbound"
	"github.com/TokenPLS/Hako/log"

	"golang.org/x/sys/unix"
)

// The Network Extension kernel gives a provider process's sockets an interface
// scope (the fact sing-tun's bindif file established with a device A/B/C
// experiment for the System stack's NAT listener). For inbound listeners the
// scope means: a listener left alone hears the physical default interface and
// nothing else, so 127.0.0.1 connections to the proxy and controller ports
// time out while the same ports answer on the LAN address. Two moves repair
// the loopback face, both on the LISTEN side only -- the outbound dialer's
// physical-interface bind is the "don't route our own traffic back into the
// tunnel" guarantee and is never touched here:
//
//   - a listener whose address IS loopback is explicitly bound to the loopback
//     interface (IP_BOUND_IF/IPV6_BOUND_IF), the reverse of the outbound
//     scope; an explicit bind is what the extension's packet filter honors,
//     which is the same mechanism that fixed the System stack's NAT listener;
//   - a wildcard TCP listener gains loopback companion listeners (127.0.0.1
//     and/or ::1 on the same port, themselves loopback-bound via the hook),
//     because one socket cannot be explicitly bound to two interfaces. The
//     wildcard's physical face is measured working under the scope and stays
//     untouched.
//
// A companion that cannot be created fails the whole listen: a wildcard
// listener whose loopback face is missing or someone else's socket is exactly
// the silent-dead state this file exists to end (the same no-fallback ruling
// as the bindif file). Wildcard UDP keeps today's behavior -- the loopback
// face of a wildcard packet conn is a recorded gap, not a silent one.
func installListenerScopeHooks(underNetworkExtension bool) {
	if !underNetworkExtension {
		inbound.DefaultListenerHook = nil
		inbound.DefaultListenerWrapper = nil
		return
	}
	inbound.DefaultListenerHook = listenerScopeControl
	inbound.DefaultListenerWrapper = listenerLoopbackCompanion
	log.Infoln("[Apple] inbound listeners run under the Network Extension socket scope; loopback faces will be explicitly bound to the loopback interface")
}

// loopbackInterfaceIndex resolves the up loopback interface. Enumerated per
// listen rather than cached: listens are rare (start and reload), and a
// cached index would survive states the kernel does not.
func loopbackInterfaceIndex() (int, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return 0, fmt.Errorf("enumerate interfaces: %w", err)
	}
	for _, candidate := range interfaces {
		if candidate.Flags&net.FlagLoopback != 0 && candidate.Flags&net.FlagUp != 0 {
			return candidate.Index, nil
		}
	}
	return 0, errors.New("no up loopback interface")
}

// listenerScopeControl binds a loopback-addressed listener socket to the
// loopback interface. Non-loopback addresses -- wildcard included -- pass
// through untouched: the physical face works under the extension's own scope,
// and binding it anywhere would break that.
func listenerScopeControl(network, address string, conn syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		// Not host:port (the controller's unix socket rides this face too).
		return nil
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || !addr.IsLoopback() {
		return nil
	}
	index, err := loopbackInterfaceIndex()
	if err != nil {
		return fmt.Errorf("bind %s listener to loopback interface: %w", address, err)
	}
	var opErr error
	controlErr := conn.Control(func(fd uintptr) {
		if addr.Unmap().Is6() {
			opErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, index)
		} else {
			opErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, index)
		}
	})
	if controlErr != nil {
		return controlErr
	}
	if opErr != nil {
		// A refused bind must fail the listen: a listener that is up but
		// unbound is deaf to loopback, silently -- the state this exists to end.
		return fmt.Errorf("bind %s listener to loopback interface index %d: %w", address, index, opErr)
	}
	return nil
}

// listenerLoopbackCompanion gives a wildcard TCP listener the loopback face
// the extension scope takes away, by listening on the loopback addresses of
// the same port. relisten builds companions through the same configuration
// path as the primary, so each companion passes listenerScopeControl and is
// loopback-bound.
func listenerLoopbackCompanion(network, address string, primary net.Listener, relisten func(context.Context, string, string) (net.Listener, error)) (net.Listener, error) {
	if !strings.HasPrefix(network, "tcp") {
		return primary, nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return primary, nil
	}
	if host != "" {
		addr, parseErr := netip.ParseAddr(host)
		if parseErr != nil || !addr.IsUnspecified() {
			return primary, nil
		}
	}
	tcpAddr, ok := primary.Addr().(*net.TCPAddr)
	if !ok {
		return primary, nil
	}
	port := fmt.Sprintf("%d", tcpAddr.Port)

	// "" and "::" (dual-stack unless the network itself is single-family)
	// carry both loopback families; "0.0.0.0" and tcp4 carry v4 only, tcp6
	// carries v6 only.
	wantV4 := network != "tcp6" && host != "::"
	wantV6 := network != "tcp4" && host != "0.0.0.0"
	if host == "::" && network == "tcp" {
		wantV4 = true
	}

	companions := make([]net.Listener, 0, 2)
	fail := func(err error) (net.Listener, error) {
		for _, companion := range companions {
			_ = companion.Close()
		}
		_ = primary.Close()
		return nil, err
	}
	if wantV4 {
		companion, listenErr := relisten(context.Background(), "tcp4", net.JoinHostPort("127.0.0.1", port))
		if listenErr != nil {
			return fail(fmt.Errorf("hako: loopback companion for %s listener on port %s: %w", network, port, listenErr))
		}
		companions = append(companions, companion)
	}
	if wantV6 {
		companion, listenErr := relisten(context.Background(), "tcp6", net.JoinHostPort("::1", port))
		if listenErr != nil {
			return fail(fmt.Errorf("hako: loopback companion for %s listener on port %s: %w", network, port, listenErr))
		}
		companions = append(companions, companion)
	}
	if len(companions) == 0 {
		return primary, nil
	}
	return newCompanionListener(primary, companions), nil
}

type companionAccept struct {
	conn net.Conn
	err  error
}

// companionListener merges Accept across the primary listener and its
// loopback companions. Addr is the primary's, so logs and diagnostics keep
// naming the address the configuration asked for.
type companionListener struct {
	primary   net.Listener
	listeners []net.Listener
	results   chan companionAccept
	closed    chan struct{}
	closeOnce sync.Once
	closeErr  error
}

func newCompanionListener(primary net.Listener, companions []net.Listener) *companionListener {
	merged := &companionListener{
		primary:   primary,
		listeners: append([]net.Listener{primary}, companions...),
		results:   make(chan companionAccept),
		closed:    make(chan struct{}),
	}
	for _, listener := range merged.listeners {
		go merged.pump(listener)
	}
	return merged
}

func (l *companionListener) pump(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case l.results <- companionAccept{err: err}:
			case <-l.closed:
				return
			}
			continue
		}
		select {
		case l.results <- companionAccept{conn: conn}:
		case <-l.closed:
			conn.Close()
			return
		}
	}
}

func (l *companionListener) Accept() (net.Conn, error) {
	select {
	case result := <-l.results:
		return result.conn, result.err
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *companionListener) Close() error {
	l.closeOnce.Do(func() {
		close(l.closed)
		for _, listener := range l.listeners {
			if err := listener.Close(); err != nil && l.closeErr == nil {
				l.closeErr = err
			}
		}
	})
	return l.closeErr
}

func (l *companionListener) Addr() net.Addr {
	return l.primary.Addr()
}
