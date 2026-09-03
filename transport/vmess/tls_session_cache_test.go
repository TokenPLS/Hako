package vmess

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/component/ech"

	"github.com/metacubex/tls"
)

// trojan, vless, vmess, the shadowsocks v2ray/gost plugins and shadow-tls all reach TLS
// through TLSConfig.ToStdConfig, which builds a fresh *tls.Config inside the per-flow
// dial. metacubex/tls disables resumption when ClientSessionCache is nil, so every
// proxied flow ran a full handshake and re-verified the server certificate -- on iOS an
// XPC round trip to trustd each time.
//
// Resumption needs a long-lived CACHE, not a long-lived config, so a fresh config per
// dial is fine as long as the cache it points at outlives the dial.
//
// The scope of that cache is a security decision, not a performance one, and the naive
// answer is wrong. metacubex/tls keys its cache on config.ServerName alone (falling back
// to the remote address) -- handshake_client.go clientSessionCacheKey. The key does NOT
// include InsecureSkipVerify, the pinning fields, the client certificate or the ALPN set.
// So one process-wide cache is safe across DIFFERENT servers but not across different
// security settings for the SAME server name: a session established by an outbound with
// skip-cert-verify would be resumed by one that was supposed to verify, and a resumed
// handshake does not re-send the certificate, so the verification would simply not
// happen. That is a downgrade introduced by an optimisation.
//
// Caches are therefore bucketed by the full security-relevant identity of the config.
// Same identity shares, anything different is isolated.

func TestSessionCacheIsSharedForIdenticalSecurityIdentity(t *testing.T) {
	first := &TLSConfig{Host: "example.com", NextProtos: []string{"h2"}}
	second := &TLSConfig{Host: "example.com", NextProtos: []string{"h2"}}

	if sessionCacheFor(first) != sessionCacheFor(second) {
		t.Fatal("two configs with the same security identity must share one cache, or " +
			"resumption never happens across flows")
	}
}

// TestSessionCacheIsolatesDifferentSecurityIdentities is the assertion that matters. Each
// case differs from the baseline in exactly one security-relevant field, and each must
// get its own cache.
func TestSessionCacheIsolatesDifferentSecurityIdentities(t *testing.T) {
	baseline := sessionCacheFor(&TLSConfig{Host: "example.com", NextProtos: []string{"h2"}})

	cases := []struct {
		name   string
		config *TLSConfig
		why    string
	}{
		{
			name:   "skip-cert-verify",
			config: &TLSConfig{Host: "example.com", NextProtos: []string{"h2"}, SkipCertVerify: true},
			why:    "sharing lets an unverified session be resumed by a config that should verify",
		},
		{
			name:   "different server name",
			config: &TLSConfig{Host: "other.example.com", NextProtos: []string{"h2"}},
			why:    "a session belongs to the server that issued it",
		},
		{
			name:   "certificate pin",
			config: &TLSConfig{Host: "example.com", NextProtos: []string{"h2"}, FingerPrint: "ab" + repeat("cd", 31)},
			why:    "differently pinned configs must not trade sessions even at the same name",
		},
		{
			name:   "name-cert-verify",
			config: &TLSConfig{Host: "example.com", NextProtos: []string{"h2"}, NameCertVerify: "pinned.example.com"},
			why:    "the verified identity differs, so the session is not interchangeable",
		},
		{
			name:   "different ALPN",
			config: &TLSConfig{Host: "example.com", NextProtos: []string{"http/1.1"}},
			why:    "a resumed session carries its negotiated protocol; mixing ALPN sets can mismatch",
		},
		{
			name:   "no ALPN",
			config: &TLSConfig{Host: "example.com"},
			why:    "absent is not the same as h2",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			cache := sessionCacheFor(testCase.config)
			if cache == nil {
				t.Fatal("every config must still get a cache")
			}
			if cache == baseline {
				t.Fatalf("shares a cache with the baseline: %s", testCase.why)
			}
		})
	}
}

// TestSessionCacheSurvivesRepeatedConfigConstruction: the per-flow config is rebuilt on
// every dial, so the cache must be found again rather than recreated, or resumption never
// happens no matter how many flows there are.
func TestSessionCacheSurvivesRepeatedConfigConstruction(t *testing.T) {
	var first any
	for i := 0; i < 50; i++ {
		cache := sessionCacheFor(&TLSConfig{Host: "steady.example.com", NextProtos: []string{"h2"}})
		if i == 0 {
			first = cache
			continue
		}
		if cache != first {
			t.Fatalf("dial %d got a different cache; a per-flow config must still find the "+
				"long-lived cache for its identity", i)
		}
	}
}

func repeat(unit string, times int) string {
	out := ""
	for i := 0; i < times; i++ {
		out += unit
	}
	return out
}

// TestBucketedCacheActuallyResumes closes the loop the identity tests cannot: that a
// config rebuilt per dial, pointing at its bucket, really resumes and really stops
// re-verifying. The verification counter is the quantity that matters -- a resumed
// handshake does not re-send the certificate, so it cannot trigger one.
func TestBucketedCacheActuallyResumes(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "flow.hako.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"flow.hako.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MaxVersion:   tls.VersionTLS12,
	})
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

	verifications := 0
	resumed := make([]bool, 0, 6)
	for i := 0; i < 6; i++ {
		// A fresh TLSConfig every iteration: this is what the per-flow dial does.
		flowConfig := &TLSConfig{Host: "flow.hako.test", SkipCertVerify: true}
		config, err := flowConfig.ToStdConfig()
		if err != nil {
			t.Fatal(err)
		}
		// What StreamTLSConn's plain-TLS branch does: attach the bucket to the per-flow
		// config just before handing it to tls.Client.
		config.ClientSessionCache = sessionCacheFor(flowConfig)
		config.MaxVersion = tls.VersionTLS12
		config.VerifyPeerCertificate = func([][]byte, [][]*x509.Certificate) error {
			verifications++
			return nil
		}
		conn, err := tls.Dial("tcp", listener.Addr().String(), config)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		resumed = append(resumed, conn.ConnectionState().DidResume)
		_ = conn.Close()
	}

	if resumed[0] {
		t.Fatal("the first flow must be a full handshake")
	}
	for i, didResume := range resumed[1:] {
		if !didResume {
			t.Fatalf("flow %d did not resume; a per-flow config must still find its bucket", i+2)
		}
	}
	if verifications != 1 {
		t.Fatalf("6 flows cost %d certificate verifications, want 1", verifications)
	}
}

// The three assertions below came out of adversarial review, which found that arming the
// cache inside ToStdConfig reached callers it must not and missed the ones it claimed.

// TestToStdConfigDoesNotArmACacheForQUICCallers: ToStdConfig is not TCP-only. TrustTunnel's
// QUIC round-tripper hands its result to http3.Transport.TLSClientConfig, and the VLESS
// XHTTP/3 path builds one for a quic-go dial. quic-go manages its own session tickets --
// the same reason forbids arming a cache inside ca.GetTLSConfig, where arming one
// breaks TUIC v5 authentication deterministically. So the config ToStdConfig returns must
// carry no cache; only the TCP handshake branch of StreamTLSConn attaches one.
func TestToStdConfigDoesNotArmACacheForQUICCallers(t *testing.T) {
	config, err := (&TLSConfig{Host: "quic.hako.test", NextProtos: []string{"h3"}}).ToStdConfig()
	if err != nil {
		t.Fatal(err)
	}
	if config.ClientSessionCache != nil {
		t.Fatal("ToStdConfig armed a session cache; TrustTunnel QUIC and VLESS XHTTP/3 build " +
			"their quic-go TLS config from this and must not get one")
	}
}

// TestSessionCacheBucketsByECHIdentity: two outbounds fronting the same server name through
// different ECH endpoints must not share a bucket. The resolved ECH configuration is
// produced by a resolver invoked after ToStdConfig, so only the per-outbound config object
// distinguishes them -- and because metacubex/tls indexes by ServerName alone, sharing a
// bucket means each overwrites the other's ticket and both keep doing full handshakes.
func TestSessionCacheBucketsByECHIdentity(t *testing.T) {
	first := &ech.Config{}
	second := &ech.Config{}

	base := sessionCacheIdentity(&TLSConfig{Host: "ech.example.com"})
	withFirst := sessionCacheIdentity(&TLSConfig{Host: "ech.example.com", ECH: first})
	withSecond := sessionCacheIdentity(&TLSConfig{Host: "ech.example.com", ECH: second})

	if withFirst == base {
		t.Fatal("an ECH config must change the bucket identity")
	}
	if withFirst == withSecond {
		t.Fatal("two distinct ECH configs share a bucket identity; presence alone is not enough " +
			"to tell two ECH fronts apart")
	}
}
