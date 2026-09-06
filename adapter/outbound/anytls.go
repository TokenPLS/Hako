package outbound

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	N "github.com/TokenPLS/Hako/common/net"
	"github.com/TokenPLS/Hako/component/proxydialer"
	C "github.com/TokenPLS/Hako/constant"
	"github.com/TokenPLS/Hako/transport/anytls"
	"github.com/TokenPLS/Hako/transport/vmess"

	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/sing/common/uot"
)

type AnyTLS struct {
	*Base
	// The session client is built on the first dial, not at load. An idle
	// node used to pay its whole client here -- including the idle-cleanup
	// goroutine session.NewClient starts -- multiplied by every node of a
	// subscription while exactly one is active. Validation stays in
	// NewAnyTLS; only the construction waits.
	client      *anytls.Client
	clientOnce  sync.Once
	buildClient func() *anytls.Client
	option      *AnyTLSOption
}

type AnyTLSOption struct {
	BasicOption
	Name                     string           `proxy:"name"`
	Server                   string           `proxy:"server"`
	Port                     int              `proxy:"port"`
	Password                 string           `proxy:"password"`
	ALPN                     []string         `proxy:"alpn,omitempty"`
	SNI                      string           `proxy:"sni,omitempty"`
	ECHOpts                  ECHOptions       `proxy:"ech-opts,omitempty"`
	ShadowTLSOpts            ShadowTLSOptions `proxy:"shadow-tls-opts,omitempty"`
	RestlsOpts               RestlsOptions    `proxy:"restls-opts,omitempty"`
	JLSOpts                  JLSOptions       `proxy:"jls-opts,omitempty"`
	ClientFingerprint        string           `proxy:"client-fingerprint,omitempty"`
	SkipCertVerify           bool             `proxy:"skip-cert-verify,omitempty"`
	NameCertVerify           string           `proxy:"name-cert-verify,omitempty"`
	Fingerprint              string           `proxy:"fingerprint,omitempty"`
	Certificate              string           `proxy:"certificate,omitempty"`
	PrivateKey               string           `proxy:"private-key,omitempty"`
	UDP                      bool             `proxy:"udp,omitempty"`
	ClientMetadata           string           `proxy:"client-metadata,omitempty"`
	IdleSessionCheckInterval int              `proxy:"idle-session-check-interval,omitempty"`
	IdleSessionTimeout       int              `proxy:"idle-session-timeout,omitempty"`
	MinIdleSession           int              `proxy:"min-idle-session,omitempty"`
	DisableReuse             bool             `proxy:"disable-reuse,omitempty"`
}

func (t *AnyTLS) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	c, err := t.lazyClient().CreateProxy(ctx, M.ParseSocksaddrHostPort(metadata.String(), metadata.DstPort))
	if err != nil {
		return nil, err
	}
	return NewConn(c, t), nil
}

func (t *AnyTLS) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if err = t.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}

	// create tcp
	c, err := t.lazyClient().CreateProxy(ctx, uot.RequestDestination(2))
	if err != nil {
		return nil, err
	}

	// create uot on tcp
	destination := M.SocksaddrFromNet(metadata.UDPAddr())
	return NewPacketConn(N.NewThreadSafePacketConn(uot.NewLazyConn(c, uot.Request{Destination: destination})), t), nil
}

// SupportUOT implements C.ProxyAdapter
func (t *AnyTLS) SupportUOT() bool {
	return true
}

// ProxyInfo implements C.ProxyAdapter
func (t *AnyTLS) ProxyInfo() C.ProxyInfo {
	info := t.Base.ProxyInfo()
	info.DialerProxy = t.option.DialerProxy
	return info
}

// Close implements C.ProxyAdapter
func (t *AnyTLS) Close() error {
	// Only a client that was actually built holds sessions or a goroutine.
	if t.clientBuilt() {
		return t.client.Close()
	}
	return nil
}

func NewAnyTLS(option AnyTLSOption) (*AnyTLS, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	outbound := &AnyTLS{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.AnyTLS,
			ProviderName: option.ProviderName,
			UDP:          option.UDP,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option: &option,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	singDialer := proxydialer.NewSingDialer(outbound.dialer)

	tOption := anytls.ClientConfig{
		Password:                 option.Password,
		Server:                   M.ParseSocksaddrHostPort(option.Server, uint16(option.Port)),
		Dialer:                   singDialer,
		ClientMetadata:           option.ClientMetadata,
		IdleSessionCheckInterval: time.Duration(option.IdleSessionCheckInterval) * time.Second,
		IdleSessionTimeout:       time.Duration(option.IdleSessionTimeout) * time.Second,
		MinIdleSession:           option.MinIdleSession,
		DisableReuse:             option.DisableReuse,
	}
	echConfig, err := option.ECHOpts.Parse()
	if err != nil {
		return nil, err
	}
	shadowTLSConfig, err := option.ShadowTLSOpts.Parse()
	if err != nil {
		return nil, err
	}
	restlsConfig, err := option.RestlsOpts.Parse(option.SNI, option.ClientFingerprint)
	if err != nil {
		return nil, err
	}
	jlsConfig, err := option.JLSOpts.Parse()
	if err != nil {
		return nil, err
	}
	securityModes := make([]string, 0, 3)
	if shadowTLSConfig != nil {
		securityModes = append(securityModes, "ShadowTLS")
	}
	if restlsConfig != nil {
		securityModes = append(securityModes, "Restls")
	}
	if jlsConfig != nil {
		securityModes = append(securityModes, "JLS")
	}
	if len(securityModes) > 1 {
		return nil, errors.New("security modes are mutually exclusive: " + strings.Join(securityModes, ", "))
	}
	tlsConfig := &vmess.TLSConfig{
		Host:              option.SNI,
		SkipCertVerify:    option.SkipCertVerify,
		NameCertVerify:    option.NameCertVerify,
		NextProtos:        option.ALPN,
		FingerPrint:       option.Fingerprint,
		Certificate:       option.Certificate,
		PrivateKey:        option.PrivateKey,
		ClientFingerprint: option.ClientFingerprint,
		ECH:               echConfig,
		ShadowTLS:         shadowTLSConfig,
		Restls:            restlsConfig,
		JLS:               jlsConfig,
	}
	if tlsConfig.Host == "" {
		tlsConfig.Host = option.Server
	}
	tOption.TLSConfig = tlsConfig

	outbound.buildClient = func() *anytls.Client {
		return anytls.NewClient(context.TODO(), tOption)
	}

	return outbound, nil
}

func (t *AnyTLS) lazyClient() *anytls.Client {
	t.clientOnce.Do(func() {
		t.client = t.buildClient()
	})
	return t.client
}

func (t *AnyTLS) clientBuilt() bool {
	built := true
	// Once.Do runs at most one function ever; if ours runs, the client was
	// never built before this Close and there is nothing to close.
	t.clientOnce.Do(func() { built = false })
	return built
}
