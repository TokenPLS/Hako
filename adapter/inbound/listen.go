package inbound

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"github.com/TokenPLS/Hako/common/atomic"
	"github.com/TokenPLS/Hako/common/sockopt"
	"github.com/TokenPLS/Hako/component/keepalive"
	"github.com/TokenPLS/Hako/component/mptcp"

	"github.com/metacubex/tfo-go"
)

var (
	globalTFO   = atomic.NewBool(false)
	globalMPTCP = atomic.NewBool(false)
)

// DefaultListenerHook and DefaultListenerWrapper are the inbound counterparts
// of dialer.DefaultSocketHook: nil by default, changing nothing, installed by
// the Apple bind layer where the Network Extension's socket interface scope
// makes an untouched listener structurally deaf to loopback traffic. The hook
// runs in every listener socket's Control chain (Listen and ListenPacket
// both); the wrapper runs after a successful TCP Listen and may replace the
// listener, with relisten building any companion through the same
// configuration path — hook included — as the primary.
var (
	DefaultListenerHook    func(network, address string, conn syscall.RawConn) error
	DefaultListenerWrapper func(network, address string, primary net.Listener, relisten func(context.Context, string, string) (net.Listener, error)) (net.Listener, error)
)

func SetTfo(open bool) {
	globalTFO.Store(open)
}

func Tfo() bool {
	return globalTFO.Load()
}

func SetMPTCP(open bool) {
	globalMPTCP.Store(open)
}

func MPTCP() bool {
	return globalMPTCP.Load()
}

type ListenConfig struct {
	routeMark int
}

func NewListenConfig() *ListenConfig {
	return &ListenConfig{}
}

func (l *ListenConfig) SetRouteMark(mark int) {
	l.routeMark = mark
}

func (l ListenConfig) newListenConfig() *tfo.ListenConfig {
	lc := tfo.ListenConfig{DisableTFO: !Tfo()}
	keepalive.SetNetListenConfig(&lc.ListenConfig)
	mptcp.SetNetListenConfig(&lc.ListenConfig, MPTCP())
	lc.Control = func(network, address string, c syscall.RawConn) error {
		if l.routeMark != 0 {
			err := sockopt.RawConnMark(c, l.routeMark)
			if err != nil {
				return err
			}
		}
		if hook := DefaultListenerHook; hook != nil {
			return hook(network, address, c)
		}
		return nil
	}
	return &lc
}

func (l ListenConfig) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	address, err := preResolve(network, address)
	if err != nil {
		return nil, err
	}
	listener, err := l.newListenConfig().Listen(ctx, network, address)
	if err != nil {
		return nil, err
	}
	if wrapper := DefaultListenerWrapper; wrapper != nil {
		return wrapper(network, address, listener, func(ctx context.Context, network, address string) (net.Listener, error) {
			return l.newListenConfig().Listen(ctx, network, address)
		})
	}
	return listener, nil
}

func (l ListenConfig) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	address, err := preResolve(network, address)
	if err != nil {
		return nil, err
	}
	return l.newListenConfig().ListenPacket(ctx, network, address)
}

func preResolve(network, address string) (string, error) {
	switch network { // like net.Resolver.internetAddrList but filter domain to avoid call net.Resolver.lookupIPAddr
	case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6", "ip", "ip4", "ip6":
		if host, port, err := net.SplitHostPort(address); err == nil {
			switch host {
			case "localhost":
				switch network {
				case "tcp6", "udp6", "ip6":
					address = net.JoinHostPort("::1", port)
				default:
					address = net.JoinHostPort("127.0.0.1", port)
				}
			case "": // internetAddrList can handle this special case
				break
			default:
				if _, err := netip.ParseAddr(host); err != nil { // not ip
					return "", fmt.Errorf("invalid network address: %s", address)
				}
			}
		}
	}
	return address, nil
}
