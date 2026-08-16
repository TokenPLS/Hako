package hako

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	coreInbound "github.com/TokenPLS/Hako/adapter/inbound"
	coreAuth "github.com/TokenPLS/Hako/component/auth"
	C "github.com/TokenPLS/Hako/constant"
	authStore "github.com/TokenPLS/Hako/listener/auth"
	LC "github.com/TokenPLS/Hako/listener/config"
	"github.com/TokenPLS/Hako/listener/mixed"
	"github.com/TokenPLS/Hako/tunnel"
)

const (
	// ProxyShareMinimumPort and ProxyShareMaximumPort are generated into the
	// gomobile SDK so the containing App can validate before making a request.
	ProxyShareMinimumPort int32 = 1024
	ProxyShareMaximumPort int32 = 65535
	// SOCKS5 username/password fields are one-byte length-prefixed.
	ProxyShareMaximumCredentialBytes int32 = 255
	// ProxyShareMinimumPasswordBytes is the wire-protocol floor for the LAN
	// proxy-share credential, not a strength policy: SOCKS5 (RFC 1929) and HTTP
	// Basic (RFC 7617) only require a non-empty password, and the upstream
	// authenticator compares it verbatim with no length rule. Password strength
	// is surfaced as a non-blocking client-side hint, never a bind-layer reject.
	ProxyShareMinimumPasswordBytes int32 = 1
)

var proxyShareAllowedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
}

type proxyShareConfiguration struct {
	port     int32
	username string
	password string
}

// proxySharePortUnavailableError marks the one rejection the user can act on:
// the port they picked cannot be bound. Whether that happens at all is a
// platform decision -- a config listener on 127.0.0.1:P and this wildcard bind
// coexist on macOS and collide on iOS -- so the App cannot predict it and must
// be told.
//
// Naming the port leaks nothing: the caller chose it, reaches this API only
// through the App Group socket, and could learn the same by binding it. What
// stays redacted is the cause (which listener, which address) and every
// credential; those live in the wrapped error, which the route never renders.
type proxySharePortUnavailableError struct {
	port  int32
	cause error
}

func (e proxySharePortUnavailableError) Error() string {
	return fmt.Sprintf("hako: proxy-share port %d is unavailable", e.port)
}

func (e proxySharePortUnavailableError) Unwrap() error { return e.cause }

type proxyShareRuntime struct {
	configuration  *proxyShareConfiguration
	authentication coreAuth.AuthStore
	listeners      []*mixed.Listener
}

type proxyShareListenConfig struct {
	base    C.InboundListenConfig
	network string
}

func (configuration proxyShareListenConfig) Listen(
	ctx context.Context,
	_ string,
	address string,
) (net.Listener, error) {
	listener, err := configuration.base.Listen(ctx, configuration.network, address)
	if err != nil {
		return nil, err
	}
	return &proxyShareFilteredListener{Listener: listener}, nil
}

func (configuration proxyShareListenConfig) ListenPacket(
	ctx context.Context,
	_ string,
	address string,
) (net.PacketConn, error) {
	network := "udp4"
	if configuration.network == "tcp6" {
		network = "udp6"
	}
	packetConnection, err := configuration.base.ListenPacket(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return &proxyShareFilteredPacketConnection{PacketConn: packetConnection}, nil
}

type proxyShareFilteredListener struct {
	net.Listener
}

func (listener *proxyShareFilteredListener) Accept() (net.Conn, error) {
	for {
		connection, err := listener.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if proxyShareRemoteAllowed(connection.RemoteAddr()) {
			return connection, nil
		}
		_ = connection.Close()
	}
}

type proxyShareFilteredPacketConnection struct {
	net.PacketConn
}

func (connection *proxyShareFilteredPacketConnection) ReadFrom(payload []byte) (int, net.Addr, error) {
	for {
		count, remote, err := connection.PacketConn.ReadFrom(payload)
		if err != nil {
			return count, remote, err
		}
		if proxyShareRemoteAllowed(remote) {
			return count, remote, nil
		}
	}
}

func proxyShareRemoteAllowed(remote net.Addr) bool {
	var ip net.IP
	switch address := remote.(type) {
	case *net.TCPAddr:
		ip = address.IP
	case *net.UDPAddr:
		ip = address.IP
	default:
		host, _, err := net.SplitHostPort(remote.String())
		if err != nil {
			return false
		}
		ip = net.ParseIP(host)
	}
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	address = address.Unmap()
	for _, prefix := range proxyShareAllowedPrefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

type proxyShareStatus struct {
	Enabled                bool     `json:"enabled"`
	Port                   int32    `json:"port"`
	Protocols              []string `json:"protocols"`
	AuthenticationRequired bool     `json:"authenticationRequired"`
}

// StartProxyShare exposes one controlled mixed HTTP/SOCKS5 listener for local
// network peers: opening a LAN port through THIS surface is an explicit,
// authenticated runtime action rather than a side effect of importing a
// configuration.
//
// It is no longer the only way a listener opens. The zero-squeeze ruling
// restored the source YAML's own inbound surface -- `listeners`, ss-config,
// vmess-config, tuic-server and the shared ports are honoured as written
// -- so this comment used to claim a safety property the code had
// stopped providing. What the reader actually gets for a configured listener
// is disclosure, not suppression: unauthenticatedLANListenerNotices names it,
// its exposure and the fact that the allow-lan permission does not cover it.
func (s *BoxService) StartProxyShare(port int32, username, password string) error {
	configuration, err := newProxyShareConfiguration(port, username, password)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return errors.New("hako: proxy share requires a running service")
	}
	// A config's own listeners (mixed-port and friends) coexist with the share.
	// Upstream never refuses because a listener exists -- a genuine port
	// collision is the bind error below, exactly as ReCreateMixed reports it
	// (ruled 2026-08-15; the old blanket refusal predated, when NE
	// stripped every config listener and the branch could refuse nobody).
	previous := s.proxyShare
	if previous != nil {
		_ = previous.close()
		s.proxyShare = nil
	}
	runtime, err := newProxyShareRuntime(configuration)
	if err != nil {
		if previous != nil {
			restored, restoreError := newProxyShareRuntime(previous.configuration)
			if restoreError != nil {
				s.updateRuntimeInboundCountLocked()
				return errors.New("hako: proxy share update and rollback failed")
			}
			s.proxyShare = restored
		}
		return err
	}
	s.proxyShare = runtime
	s.updateRuntimeInboundCountLocked()
	return nil
}

// StopProxyShare is idempotent. It closes the owned listener before clearing
// authentication and LAN policy so there is no unauthenticated transition.
func (s *BoxService) StopProxyShare() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.stopProxyShareLocked()
	if s.running {
		s.updateRuntimeInboundCountLocked()
	}
	return err
}

// ProxyShareStatusJSON intentionally omits credentials and interface/IP data.
// The client already owns the secret in Keychain and can obtain displayable
// LAN addresses from Apple APIs when the user opens the feature UI.
func (s *BoxService) ProxyShareStatusJSON() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return mustJSON(s.proxyShareStatusLocked())
}

func (s *BoxService) proxyShareStatusLocked() proxyShareStatus {
	if !s.running || s.proxyShare == nil || len(s.proxyShare.listeners) != 2 {
		return proxyShareStatus{}
	}
	authenticator := s.proxyShare.authentication.Authenticator()
	configuration := s.proxyShare.configuration
	if authenticator == nil || !authenticator.Verify(configuration.username, configuration.password) {
		return proxyShareStatus{}
	}
	return proxyShareStatus{
		Enabled:                true,
		Port:                   configuration.port,
		Protocols:              []string{"http", "socks5"},
		AuthenticationRequired: true,
	}
}

func (s *BoxService) reapplyProxyShareLocked() error {
	if s.proxyShare == nil {
		return nil
	}
	if len(s.proxyShare.listeners) != 2 {
		return errors.New("hako: proxy-share listener is unavailable")
	}
	return nil
}

func (s *BoxService) stopProxyShareLocked() error {
	if s.proxyShare == nil {
		return nil
	}
	err := s.proxyShare.close()
	s.proxyShare = nil
	return err
}

func (s *BoxService) updateRuntimeInboundCountLocked() {
	s.inboundCount = s.runtimeInboundCountLocked()
	setOOMEvidenceCoreState(true, s.startTimeUnix, s.inboundCount, s.outboundCount)
}

func (s *BoxService) runtimeInboundCountLocked() int32 {
	count := runtimeInboundCount()
	if s.proxyShare != nil {
		count++
	}
	return count
}

func newProxyShareConfiguration(port int32, username, password string) (*proxyShareConfiguration, error) {
	if port < ProxyShareMinimumPort || port > ProxyShareMaximumPort {
		return nil, fmt.Errorf("hako: proxy-share port must be within %d...%d", ProxyShareMinimumPort, ProxyShareMaximumPort)
	}
	if !validProxyShareUsername(username) {
		return nil, errors.New("hako: proxy-share username is invalid")
	}
	if !validProxySharePassword(password) {
		return nil, fmt.Errorf("hako: proxy-share password must be %d...%d bytes without control characters", ProxyShareMinimumPasswordBytes, ProxyShareMaximumCredentialBytes)
	}
	return &proxyShareConfiguration{port: port, username: username, password: password}, nil
}

func validProxyShareUsername(value string) bool {
	return value != "" &&
		len(value) <= int(ProxyShareMaximumCredentialBytes) &&
		utf8.ValidString(value) &&
		strings.TrimSpace(value) == value &&
		!strings.ContainsRune(value, ':') &&
		strings.IndexFunc(value, unicode.IsControl) < 0
}

func validProxySharePassword(value string) bool {
	return len(value) >= int(ProxyShareMinimumPasswordBytes) &&
		len(value) <= int(ProxyShareMaximumCredentialBytes) &&
		utf8.ValidString(value) &&
		strings.IndexFunc(value, unicode.IsControl) < 0
}

func newProxyShareRuntime(configuration *proxyShareConfiguration) (*proxyShareRuntime, error) {
	// Authentication is private to these listeners; source filtering is owned
	// by proxyShareListenConfig. Neither uses mihomo's mutable process-global
	// default LAN/auth state, so config reload cannot race or weaken it.
	authentication := authStore.NewAuthStore(coreAuth.NewAuthenticator([]coreAuth.AuthUser{{
		User: configuration.username,
		Pass: configuration.password,
	}}))
	runtime := &proxyShareRuntime{
		configuration:  configuration,
		authentication: authentication,
	}
	port := strconv.Itoa(int(configuration.port))
	for _, endpoint := range []struct {
		host    string
		network string
	}{{"0.0.0.0", "tcp4"}, {"::", "tcp6"}} {
		listener, err := mixed.NewWithConfig(
			LC.AuthServer{
				Enable:    true,
				Listen:    net.JoinHostPort(endpoint.host, port),
				AuthStore: authentication,
			},
			proxyShareListenConfig{
				base:    coreInbound.NewListenConfig(),
				network: endpoint.network,
			},
			tunnel.Tunnel,
			coreInbound.WithInName("HAKO-PROXY-SHARE"),
			coreInbound.WithSpecialRules(""),
		)
		if err != nil {
			_ = runtime.close()
			return nil, proxySharePortUnavailableError{
				port:  configuration.port,
				cause: fmt.Errorf("hako: proxy-share listener failed to start on %s: %w", endpoint.host, err),
			}
		}
		runtime.listeners = append(runtime.listeners, listener)
	}
	return runtime, nil
}

func (runtime *proxyShareRuntime) close() error {
	if runtime == nil {
		return nil
	}
	var closeErrors []error
	for _, listener := range runtime.listeners {
		if err := listener.Close(); err != nil {
			closeErrors = append(closeErrors, err)
		}
	}
	runtime.listeners = nil
	return errors.Join(closeErrors...)
}
