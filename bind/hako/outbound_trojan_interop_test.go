package hako

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/adapter"
	"github.com/TokenPLS/Hako/component/ca"
	C "github.com/TokenPLS/Hako/constant"
	IN "github.com/TokenPLS/Hako/listener/inbound"
)

func TestControlledTrojanInterop(t *testing.T) {
	pinUnifiedDelayOff(t)
	serverCertificate, serverPrivateKey, serverFingerprint, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatalf("generate server certificate: %v", err)
	}
	clientCertificate, clientPrivateKey, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatalf("generate client certificate: %v", err)
	}
	for _, test := range []struct {
		name        string
		network     string
		wsPath      string
		grpcService string
		httpUpgrade bool
	}{
		{name: "TLSMTLS"},
		{name: "WebSocketHTTPUpgrade", network: "ws", wsPath: "/controlled-trojan", httpUpgrade: true},
		{name: "GRPCTLS", network: "grpc", grpcService: "ControlledTrojan"},
	} {
		t.Run(test.name, func(t *testing.T) {
			runControlledTrojanVariant(
				t,
				test.network,
				test.wsPath,
				test.grpcService,
				test.httpUpgrade,
				serverCertificate,
				serverPrivateKey,
				serverFingerprint,
				clientCertificate,
				clientPrivateKey,
			)
		})
	}
}

func runControlledTrojanVariant(
	t *testing.T,
	network string,
	wsPath string,
	grpcService string,
	httpUpgrade bool,
	serverCertificate string,
	serverPrivateKey string,
	serverFingerprint string,
	clientCertificate string,
	clientPrivateKey string,
) {
	t.Helper()
	const password = "controlled-trojan-password"
	server, err := IN.NewTrojan(&IN.TrojanOption{
		BaseOption: IN.BaseOption{
			NameStr: "controlled-trojan-inbound",
			Listen:  "127.0.0.1",
			Port:    "0",
		},
		Users:           []IN.TrojanUser{{Username: "controlled", Password: password}},
		WsPath:          wsPath,
		GrpcServiceName: grpcService,
		Certificate:     serverCertificate,
		PrivateKey:      serverPrivateKey,
		ClientAuthCert:  clientCertificate,
	})
	if err != nil {
		t.Fatalf("NewTrojan() error = %v", err)
	}
	if err := server.Listen(&controlledReferenceTunnel{}); err != nil {
		t.Fatalf("Trojan Listen() error = %v", err)
	}
	defer server.Close()
	serverAddress, err := netip.ParseAddrPort(server.Address())
	if err != nil {
		t.Fatalf("parse Trojan address %q: %v", server.Address(), err)
	}
	mapping := map[string]any{
		"name":        "controlled-trojan-outbound",
		"type":        "trojan",
		"server":      serverAddress.Addr().String(),
		"port":        serverAddress.Port(),
		"password":    password,
		"udp":         true,
		"fingerprint": serverFingerprint,
		"certificate": clientCertificate,
		"private-key": clientPrivateKey,
	}
	if network != "" {
		mapping["network"] = network
	}
	if wsPath != "" {
		mapping["ws-opts"] = map[string]any{
			"path":                         wsPath,
			"v2ray-http-upgrade":           httpUpgrade,
			"v2ray-http-upgrade-fast-open": httpUpgrade,
		}
	}
	if grpcService != "" {
		mapping["grpc-opts"] = map[string]any{"grpc-service-name": grpcService}
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
		t.Fatalf("Trojan URLTest() error = %v", err)
	}
	if delay == 0 {
		t.Fatal("Trojan URLTest() returned the failure sentinel delay")
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
	if err := packetConnection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetDeadline() error = %v", err)
	}
	payload := []byte("hako-controlled-trojan-udp-" + network)
	if _, err := packetConnection.WriteTo(payload, udpAddress); err != nil {
		t.Fatalf("WriteTo() error = %v", err)
	}
	buffer := make([]byte, 64*1024)
	n, source, err := packetConnection.ReadFrom(buffer)
	if err != nil {
		t.Fatalf("ReadFrom() error = %v", err)
	}
	if !bytes.Equal(buffer[:n], payload) || source.String() != udpAddress.String() {
		t.Fatalf("UDP response = (%q, %v), want (%q, %v)", buffer[:n], source, payload, udpAddress)
	}

	if network == "" {
		_, _, wrongFingerprint, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
		if err != nil {
			t.Fatalf("generate wrong fingerprint: %v", err)
		}
		for _, failure := range []struct {
			name        string
			password    string
			fingerprint string
			wantError   string
		}{
			{name: "InvalidPassword", password: "wrong-password", fingerprint: serverFingerprint},
			{name: "InvalidCertificate", password: password, fingerprint: wrongFingerprint, wantError: "certificate"},
		} {
			t.Run(failure.name, func(t *testing.T) {
				failedMapping := cloneAnyTLSMapping(mapping)
				failedMapping["name"] = "controlled-trojan-" + failure.name
				failedMapping["password"] = failure.password
				failedMapping["fingerprint"] = failure.fingerprint
				failedProxy, err := adapter.ParseProxy(failedMapping)
				if err != nil {
					t.Fatalf("ParseProxy() error = %v", err)
				}
				defer failedProxy.Close()
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				_, err = failedProxy.URLTest(ctx, target.URL, nil)
				cancel()
				if err == nil {
					t.Fatal("invalid Trojan credentials unexpectedly succeeded")
				}
				if failure.wantError != "" && !strings.Contains(strings.ToLower(err.Error()), failure.wantError) {
					t.Fatalf("failure error = %v, want %q", err, failure.wantError)
				}
				if count := targetRequests.Load(); count != 1 {
					t.Fatalf("failed attempt leaked to target; request count = %d", count)
				}
			})
		}
	}
}
