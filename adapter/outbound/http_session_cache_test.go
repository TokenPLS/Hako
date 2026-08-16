package outbound

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/metacubex/tls"
)

// TestNewHttpArmsSessionCache: a TLS HTTP proxy arms a client session cache so
// its per-connection TLS dials can resume; a plaintext HTTP proxy has no TLS
// config to touch.
func TestNewHttpArmsSessionCache(t *testing.T) {
	h, err := NewHttp(HttpOption{Name: "tls", Server: "127.0.0.1", Port: 8080, TLS: true, SkipCertVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	if h.tlsConfig == nil || h.tlsConfig.ClientSessionCache == nil {
		t.Fatal("a TLS HTTP proxy must arm a ClientSessionCache")
	}
	plain, err := NewHttp(HttpOption{Name: "plain", Server: "127.0.0.1", Port: 8080})
	if err != nil {
		t.Fatal(err)
	}
	if plain.tlsConfig != nil {
		t.Fatal("a plaintext HTTP proxy must not build a TLS config")
	}
}

// TestNewHttpTLSConfigResumes proves the armed cache actually resumes on the
// proxy's own TLS config: the second dial is an abbreviated handshake that does
// not re-send (and so does not re-verify) the server certificate -- exactly the
// per-connection SecTrustEvaluate/trustd cost the storm was paying.
func TestNewHttpTLSConfigResumes(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "hako.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"hako.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}},
		MaxVersion:   tls.VersionTLS12, // the ticket arrives in-handshake, simplest to assert
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				_, _ = io.Copy(io.Discard, c)
				_ = c.Close()
			}(conn)
		}
	}()

	_, portStr, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewHttp(HttpOption{Name: "tls", Server: "127.0.0.1", Port: port, TLS: true, SkipCertVerify: true, SNI: "hako.test"})
	if err != nil {
		t.Fatal(err)
	}
	// Clone shares the proxy's ClientSessionCache; pin TLS 1.2 for a deterministic
	// in-handshake ticket without altering the cache under test.
	clientCfg := h.tlsConfig.Clone()
	clientCfg.MaxVersion = tls.VersionTLS12

	dialResumed := func() bool {
		conn, err := tls.Dial("tcp", listener.Addr().String(), clientCfg)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		return conn.ConnectionState().DidResume
	}
	if dialResumed() {
		t.Fatal("first handshake must be full, not resumed")
	}
	if !dialResumed() {
		t.Fatal("second handshake must resume via the proxy's session cache")
	}
}
