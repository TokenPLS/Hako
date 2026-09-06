package outbound

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strconv"

	N "github.com/TokenPLS/Hako/common/net"
	"github.com/TokenPLS/Hako/component/ca"
	C "github.com/TokenPLS/Hako/constant"

	"github.com/metacubex/http"
	"github.com/metacubex/tls"
)

type Http struct {
	*Base
	user      string
	pass      string
	tlsConfig *tls.Config
	option    *HttpOption
}

type HttpOption struct {
	BasicOption
	Name           string            `proxy:"name"`
	Server         string            `proxy:"server"`
	Port           int               `proxy:"port"`
	UserName       string            `proxy:"username,omitempty"`
	Password       string            `proxy:"password,omitempty"`
	TLS            bool              `proxy:"tls,omitempty"`
	SNI            string            `proxy:"sni,omitempty"`
	SkipCertVerify bool              `proxy:"skip-cert-verify,omitempty"`
	NameCertVerify string            `proxy:"name-cert-verify,omitempty"`
	Fingerprint    string            `proxy:"fingerprint,omitempty"`
	Certificate    string            `proxy:"certificate,omitempty"`
	PrivateKey     string            `proxy:"private-key,omitempty"`
	Headers        map[string]string `proxy:"headers,omitempty"`
}

// StreamConnContext implements C.ProxyAdapter
func (h *Http) StreamConnContext(ctx context.Context, c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	if h.tlsConfig != nil {
		cc := tls.Client(c, h.tlsConfig)
		err := cc.HandshakeContext(ctx)
		c = cc
		if err != nil {
			return nil, fmt.Errorf("%s connect error: %w", h.addr, err)
		}
	}

	if err := h.shakeHandContext(ctx, c, metadata); err != nil {
		return nil, err
	}
	return c, nil
}

// DialContext implements C.ProxyAdapter
func (h *Http) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	c, err := h.dialer.DialContext(ctx, "tcp", h.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", h.addr, err)
	}

	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	c, err = h.StreamConnContext(ctx, c, metadata)
	if err != nil {
		return nil, err
	}

	return NewConn(c, h), nil
}

// ProxyInfo implements C.ProxyAdapter
func (h *Http) ProxyInfo() C.ProxyInfo {
	info := h.Base.ProxyInfo()
	info.DialerProxy = h.option.DialerProxy
	return info
}

func (h *Http) shakeHandContext(ctx context.Context, c net.Conn, metadata *C.Metadata) (err error) {
	if ctx.Done() != nil {
		done := N.SetupContextForConn(ctx, c)
		defer done(&err)
	}

	addr := metadata.RemoteAddress()
	HeaderString := "CONNECT " + addr + " HTTP/1.1\r\n"
	tempHeaders := map[string]string{
		"Host":             addr,
		"User-Agent":       "Go-http-client/1.1",
		"Proxy-Connection": "Keep-Alive",
	}

	for key, value := range h.option.Headers {
		tempHeaders[key] = value
	}

	if h.user != "" && h.pass != "" {
		auth := h.user + ":" + h.pass
		tempHeaders["Proxy-Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
	}

	for key, value := range tempHeaders {
		HeaderString += key + ": " + value + "\r\n"
	}

	HeaderString += "\r\n"

	_, err = c.Write([]byte(HeaderString))

	if err != nil {
		return err
	}

	resp, err := http.ReadResponse(bufio.NewReader(c), nil)

	if err != nil {
		return err
	}

	if resp.StatusCode == http.StatusOK {
		return nil
	}

	if resp.StatusCode == http.StatusProxyAuthRequired {
		return errors.New("HTTP need auth")
	}

	if resp.StatusCode == http.StatusMethodNotAllowed {
		return errors.New("CONNECT method not allowed by proxy")
	}

	if resp.StatusCode >= http.StatusInternalServerError {
		return errors.New(resp.Status)
	}

	return fmt.Errorf("can not connect remote err code: %d", resp.StatusCode)
}

func NewHttp(option HttpOption) (*Http, error) {
	var tlsConfig *tls.Config
	if option.TLS {
		sni := option.Server
		if option.SNI != "" {
			sni = option.SNI
		}
		var err error
		tlsConfig, err = ca.GetTLSConfig(ca.Option{
			TLSConfig: &tls.Config{
				InsecureSkipVerify: option.SkipCertVerify,
				ServerName:         sni,
			},
			Fingerprint:    option.Fingerprint,
			NameCertVerify: option.NameCertVerify,
			Certificate:    option.Certificate,
			PrivateKey:     option.PrivateKey,
		})
		if err != nil {
			return nil, err
		}
		// An HTTP proxy tunnels each proxied connection over its OWN new TLS
		// connection (HTTP CONNECT does not multiplex), so without session
		// resumption every proxied connection pays a full TLS handshake -- and on
		// iOS that is a SecTrustEvaluate/trustd verification per connection, a storm
		// under load. Arm a session cache so repeated dials to this proxy resume: a
		// resumed handshake does not re-send the server certificate, so verification
		// is preserved (a MITM without the session key still gets a full, verified
		// handshake) while the redundant per-connection cost is skipped. Scoped to
		// this TCP HTTP proxy on purpose -- QUIC proxies manage their own session
		// tickets and must not be given a ClientSessionCache here.
		if tlsConfig.ClientSessionCache == nil {
			tlsConfig.ClientSessionCache = tls.NewLRUClientSessionCache(0)
		}
	}

	outbound := &Http{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         net.JoinHostPort(option.Server, strconv.Itoa(option.Port)),
			Type:         C.Http,
			ProviderName: option.ProviderName,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		user:      option.UserName,
		pass:      option.Password,
		tlsConfig: tlsConfig,
		option:    &option,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	return outbound, nil
}
