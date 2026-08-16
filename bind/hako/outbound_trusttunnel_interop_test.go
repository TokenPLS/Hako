package hako

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/adapter"
	"github.com/TokenPLS/Hako/component/ca"
	C "github.com/TokenPLS/Hako/constant"
	IN "github.com/TokenPLS/Hako/listener/inbound"
)

func TestControlledTrustTunnelInterop(t *testing.T) {
	serverCertificate, serverPrivateKey, serverFingerprint, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatalf("generate server certificate: %v", err)
	}
	clientCertificate, clientPrivateKey, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatalf("generate client certificate: %v", err)
	}
	for _, test := range []struct {
		name                 string
		quic                 bool
		congestionController string
	}{
		{name: "HTTP2MTLS"},
		{name: "HTTP3MTLS", quic: true, congestionController: "bbr"},
	} {
		t.Run(test.name, func(t *testing.T) {
			runControlledTrustTunnelVariant(
				t,
				test.quic,
				test.congestionController,
				serverCertificate,
				serverPrivateKey,
				serverFingerprint,
				clientCertificate,
				clientPrivateKey,
			)
		})
	}
}

func runControlledTrustTunnelVariant(
	t *testing.T,
	quic bool,
	congestionController string,
	serverCertificate string,
	serverPrivateKey string,
	serverFingerprint string,
	clientCertificate string,
	clientPrivateKey string,
) {
	t.Helper()
	const username = "controlled-trusttunnel-user"
	const password = "controlled-trusttunnel-password"
	network := []string{"tcp"}
	if quic {
		network = []string{"udp"}
	}
	server, err := IN.NewTrustTunnel(&IN.TrustTunnelOption{
		BaseOption: IN.BaseOption{
			NameStr: "controlled-trusttunnel-inbound",
			Listen:  "127.0.0.1",
			Port:    "0",
		},
		Users:                IN.AuthUsers{{Username: username, Password: password}},
		Certificate:          serverCertificate,
		PrivateKey:           serverPrivateKey,
		ClientAuthCert:       clientCertificate,
		Network:              network,
		CongestionController: congestionController,
	})
	if err != nil {
		t.Fatalf("NewTrustTunnel() error = %v", err)
	}
	if err := server.Listen(&controlledReferenceTunnel{}); err != nil {
		t.Fatalf("TrustTunnel Listen() error = %v", err)
	}
	defer server.Close()
	serverAddress, err := netip.ParseAddrPort(server.Address())
	if err != nil {
		t.Fatalf("parse TrustTunnel address %q: %v", server.Address(), err)
	}
	mapping := map[string]any{
		"name":                  "controlled-trusttunnel-outbound",
		"type":                  "trusttunnel",
		"server":                serverAddress.Addr().String(),
		"port":                  serverAddress.Port(),
		"username":              username,
		"password":              password,
		"udp":                   true,
		"quic":                  quic,
		"congestion-controller": congestionController,
		"fingerprint":           serverFingerprint,
		"certificate":           clientCertificate,
		"private-key":           clientPrivateKey,
	}
	proxy, err := adapter.ParseProxy(mapping)
	if err != nil {
		t.Fatalf("ParseProxy() error = %v", err)
	}
	defer proxy.Close()

	var targetRequests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		targetRequests.Add(1)
		if request.Method != http.MethodHead {
			t.Errorf("target method = %s, want HEAD", request.Method)
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	delay, err := proxy.URLTest(ctx, target.URL, nil)
	cancel()
	if err != nil {
		t.Fatalf("TrustTunnel URLTest() error = %v", err)
	}
	if delay == 0 {
		t.Fatal("TrustTunnel URLTest() returned the failure sentinel delay")
	}
	if count := targetRequests.Load(); count != 1 {
		t.Fatalf("target request count = %d, want 1", count)
	}

	udpTarget, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen for UDP echo target: %v", err)
	}
	defer udpTarget.Close()
	go serveUDPEcho(udpTarget)
	udpAddress := udpTarget.LocalAddr().(*net.UDPAddr)
	udpAddrPort := udpAddress.AddrPort()
	metadata := &C.Metadata{
		NetWork: C.UDP,
		Type:    C.TUN,
		DstIP:   udpAddrPort.Addr(),
		DstPort: udpAddrPort.Port(),
	}
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	packetConnection, err := proxy.ListenPacketContext(ctx, metadata)
	cancel()
	if err != nil {
		t.Fatalf("ListenPacketContext() error = %v", err)
	}
	defer packetConnection.Close()
	transport := "h2"
	if quic {
		transport = "h3"
	}
	payload := []byte("hako-controlled-trusttunnel-udp-" + transport)
	if _, err := packetConnection.WriteTo(payload, udpAddress); err != nil {
		t.Fatalf("WriteTo() error = %v", err)
	}
	buffer := make([]byte, 64*1024)
	type packetResult struct {
		n      int
		source net.Addr
		err    error
	}
	result := make(chan packetResult, 1)
	go func() {
		n, source, err := packetConnection.ReadFrom(buffer)
		result <- packetResult{n: n, source: source, err: err}
	}()
	var n int
	var source net.Addr
	select {
	case response := <-result:
		if response.err != nil {
			t.Fatalf("ReadFrom() error = %v", response.err)
		}
		n, source = response.n, response.source
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for TrustTunnel %s UDP response", transport)
	}
	if !bytes.Equal(buffer[:n], payload) || source.String() != udpAddress.String() {
		t.Fatalf("UDP response = (%q, %v), want (%q, %v)", buffer[:n], source, payload, udpAddress)
	}

	if !quic {
		_, _, wrongFingerprint, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
		if err != nil {
			t.Fatalf("generate wrong fingerprint: %v", err)
		}
		for _, failure := range []struct {
			name        string
			password    string
			fingerprint string
		}{
			{name: "InvalidAuthentication", password: "wrong-password", fingerprint: serverFingerprint},
			{name: "InvalidCertificate", password: password, fingerprint: wrongFingerprint},
		} {
			t.Run(failure.name, func(t *testing.T) {
				failedMapping := cloneAnyTLSMapping(mapping)
				failedMapping["name"] = "controlled-trusttunnel-" + failure.name
				failedMapping["password"] = failure.password
				failedMapping["fingerprint"] = failure.fingerprint
				failedProxy, err := adapter.ParseProxy(failedMapping)
				if err != nil {
					t.Fatalf("ParseProxy() error = %v", err)
				}
				defer failedProxy.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				_, err = failedProxy.URLTest(ctx, target.URL, nil)
				cancel()
				if err == nil {
					t.Fatal("invalid TrustTunnel credentials unexpectedly succeeded")
				}
				if count := targetRequests.Load(); count != 1 {
					t.Fatalf("failed attempt leaked to target; request count = %d", count)
				}
			})
		}
	}
}
