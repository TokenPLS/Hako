package shadowsocks

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync/atomic"

	"github.com/TokenPLS/Hako/adapter/inbound"
	N "github.com/TokenPLS/Hako/common/net"
	C "github.com/TokenPLS/Hako/constant"
	LC "github.com/TokenPLS/Hako/listener/config"
	"github.com/TokenPLS/Hako/listener/jls"
	"github.com/TokenPLS/Hako/listener/restls"
	"github.com/TokenPLS/Hako/listener/shadowtls"
	"github.com/TokenPLS/Hako/listener/sing"
	"github.com/TokenPLS/Hako/transport/shadowsocks/core"
	obfs "github.com/TokenPLS/Hako/transport/simple-obfs"
	"github.com/TokenPLS/Hako/transport/socks5"
)

type Listener struct {
	closed       atomic.Bool
	config       LC.ShadowsocksServer
	listeners    []net.Listener
	udpListeners []*UDPListener
	pickCipher   core.Cipher
	handler      *sing.ListenerHandler
	simpleObfs   func(net.Conn) net.Conn
}

var defaultListener atomic.Pointer[Listener]

func New(config LC.ShadowsocksServer, lc C.InboundListenConfig, tunnel C.Tunnel, additions ...inbound.Addition) (*Listener, error) {
	pickCipher, err := core.PickCipher(config.Cipher, nil, config.Password)
	if err != nil {
		return nil, err
	}

	h, err := sing.NewListenerHandler(sing.ListenerConfig{
		Tunnel:    tunnel,
		Type:      C.SHADOWSOCKS,
		Additions: additions,
		MuxOption: config.MuxOption,
	})
	if err != nil {
		return nil, err
	}

	sl := &Listener{config: config, pickCipher: pickCipher, handler: h}
	defaultListener.Store(sl)

	securityModes := make([]string, 0, 3)
	if config.ShadowTLS.Enable {
		securityModes = append(securityModes, "shadow-tls")
	}
	if config.ResTLS.Enable {
		securityModes = append(securityModes, "res-tls")
	}
	if config.JLSConfig.Enable {
		securityModes = append(securityModes, "jls")
	}
	if len(securityModes) > 1 {
		return nil, fmt.Errorf("security modes are mutually exclusive: %s", strings.Join(securityModes, ", "))
	}

	var shadowTLSBuilder *shadowtls.Builder
	if config.ShadowTLS.Enable {
		shadowTLSBuilder, err = shadowtls.New(config.ShadowTLS, tunnel)
		if err != nil {
			return nil, err
		}
	}

	var restlsBuilder *restls.Builder
	if config.ResTLS.Enable {
		restlsBuilder = restls.New(config.ResTLS, tunnel)
	}

	var jlsBuilder *jls.Builder
	if config.JLSConfig.Enable {
		jlsBuilder, err = jls.New(config.JLSConfig, tunnel)
		if err != nil {
			return nil, err
		}
	}

	if config.SimpleObfs.Enable {
		switch config.SimpleObfs.Mode {
		case "http":
			sl.simpleObfs = obfs.NewHTTPObfsServer
		case "tls":
			sl.simpleObfs = obfs.NewTLSObfsServer
		default:
			return nil, fmt.Errorf("unsupported simple obfs mode: %s", config.SimpleObfs.Mode)
		}
	}

	for _, addr := range strings.Split(config.Listen, ",") {
		addr := addr

		if config.Udp {
			//UDP
			ul, err := NewUDP(addr, lc, pickCipher, tunnel, additions...)
			if err != nil {
				return nil, err
			}
			sl.udpListeners = append(sl.udpListeners, ul)
		}

		//TCP
		l, err := lc.Listen(context.Background(), "tcp", addr)
		if err != nil {
			return nil, err
		}
		if shadowTLSBuilder != nil {
			l = shadowTLSBuilder.NewListener(l)
		} else if restlsBuilder != nil {
			l = restlsBuilder.NewListener(l)
		} else if jlsBuilder != nil {
			l = jlsBuilder.NewListener(l)
		}
		sl.listeners = append(sl.listeners, l)

		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					if sl.closed.Load() {
						break
					}
					continue
				}
				go sl.HandleConn(c, tunnel, additions...)
			}
		}()
	}

	return sl, nil
}

func (l *Listener) Close() error {
	l.closed.Store(true)
	defaultListener.CompareAndSwap(l, nil)
	var retErr error
	for _, lis := range l.listeners {
		err := lis.Close()
		if err != nil {
			retErr = err
		}
	}
	for _, lis := range l.udpListeners {
		err := lis.Close()
		if err != nil {
			retErr = err
		}
	}
	return retErr
}

func (l *Listener) Config() string {
	return l.config.String()
}

func (l *Listener) AddrList() (addrList []net.Addr) {
	for _, lis := range l.listeners {
		addrList = append(addrList, lis.Addr())
	}
	for _, lis := range l.udpListeners {
		addrList = append(addrList, lis.LocalAddr())
	}
	return
}

func (l *Listener) HandleConn(conn net.Conn, tunnel C.Tunnel, additions ...inbound.Addition) {
	user, loaded := shadowtls.UserFromConn(conn)
	if jlsUser, jlsLoaded := jls.UserFromConn(conn); jlsLoaded {
		user, loaded = jlsUser, true
	}
	if loaded {
		additions = append(append([]inbound.Addition(nil), additions...), inbound.WithInUser(user))
	}
	if l.simpleObfs != nil {
		conn = l.simpleObfs(conn)
	}
	conn = l.pickCipher.StreamConn(conn)
	conn = N.NewDeadlineConn(conn) // embed ss can't handle readDeadline correctly

	target, err := socks5.ReadAddr0(conn)
	if err != nil {
		_ = conn.Close()
		return
	}
	l.handler.HandleSocket(target, conn, additions...)
	//tunnel.HandleTCPConn(inbound.NewSocket(target, conn, C.SHADOWSOCKS, additions...))
}

func HandleShadowSocks(conn net.Conn, tunnel C.Tunnel, additions ...inbound.Addition) bool {
	listener := defaultListener.Load()
	if listener != nil && listener.pickCipher != nil {
		go listener.HandleConn(conn, tunnel, additions...)
		return true
	}
	return false
}
