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
	"github.com/TokenPLS/Hako/common/utils"
	"github.com/TokenPLS/Hako/component/ca"
	C "github.com/TokenPLS/Hako/constant"
	IN "github.com/TokenPLS/Hako/listener/inbound"
)

func TestControlledTUICInterop(t *testing.T) {
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
		version              int
		udpRelayMode         string
		congestionController string
		reduceRTT            bool
	}{
		{name: "V4NativeCubic", version: 4, udpRelayMode: "native", congestionController: "cubic"},
		{name: "V4QUICNewReno", version: 4, udpRelayMode: "quic", congestionController: "new_reno", reduceRTT: true},
		{name: "V5NativeBBR", version: 5, udpRelayMode: "native", congestionController: "bbr"},
		{name: "V5QUICCubic", version: 5, udpRelayMode: "quic", congestionController: "cubic", reduceRTT: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			runControlledTUICVariant(
				t,
				test.version,
				test.udpRelayMode,
				test.congestionController,
				test.reduceRTT,
				serverCertificate,
				serverPrivateKey,
				serverFingerprint,
				clientCertificate,
				clientPrivateKey,
			)
		})
	}
}

func runControlledTUICVariant(
	t *testing.T,
	version int,
	udpRelayMode string,
	congestionController string,
	reduceRTT bool,
	serverCertificate string,
	serverPrivateKey string,
	serverFingerprint string,
	clientCertificate string,
	clientPrivateKey string,
) {
	t.Helper()
	const token = "controlled-tuic-v4-token"
	const password = "controlled-tuic-v5-password"
	uuid := utils.NewUUIDV4().String()
	server, err := IN.NewTuic(&IN.TuicOption{
		BaseOption: IN.BaseOption{
			NameStr: "controlled-tuic-inbound",
			Listen:  "127.0.0.1",
			Port:    "0",
		},
		Token:                 []string{token},
		Users:                 map[string]string{uuid: password},
		Certificate:           serverCertificate,
		PrivateKey:            serverPrivateKey,
		ClientAuthCert:        clientCertificate,
		CongestionController:  congestionController,
		AuthenticationTimeout: 1000,
	})
	if err != nil {
		t.Fatalf("NewTuic() error = %v", err)
	}
	if err := server.Listen(&controlledReferenceTunnel{}); err != nil {
		t.Fatalf("TUIC Listen() error = %v", err)
	}
	defer server.Close()
	serverAddress, err := netip.ParseAddrPort(server.Address())
	if err != nil {
		t.Fatalf("parse TUIC address %q: %v", server.Address(), err)
	}
	mapping := map[string]any{
		"name":                  "controlled-tuic-outbound",
		"type":                  "tuic",
		"server":                serverAddress.Addr().String(),
		"port":                  serverAddress.Port(),
		"udp-relay-mode":        udpRelayMode,
		"congestion-controller": congestionController,
		"reduce-rtt":            reduceRTT,
		"fast-open":             true,
		"fingerprint":           serverFingerprint,
		"certificate":           clientCertificate,
		"private-key":           clientPrivateKey,
	}
	if version == 4 {
		mapping["token"] = token
	} else {
		mapping["uuid"] = uuid
		mapping["password"] = password
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
		t.Fatalf("TUIC v%d URLTest() error = %v", version, err)
	}
	if delay == 0 {
		t.Fatalf("TUIC v%d URLTest() returned the failure sentinel delay", version)
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
	payload := []byte("hako-controlled-tuic-udp-" + udpRelayMode)
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
		t.Fatalf("timed out waiting for TUIC v%d UDP response", version)
	}
	if !bytes.Equal(buffer[:n], payload) || source.String() != udpAddress.String() {
		t.Fatalf("UDP response = (%q, %v), want (%q, %v)", buffer[:n], source, payload, udpAddress)
	}

	if udpRelayMode == "native" {
		_, _, wrongFingerprint, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
		if err != nil {
			t.Fatalf("generate wrong fingerprint: %v", err)
		}
		for _, failure := range []struct {
			name        string
			credential  string
			fingerprint string
			wantError   string
		}{
			{name: "InvalidAuthentication", credential: "wrong-credential", fingerprint: serverFingerprint},
			{name: "InvalidCertificate", credential: password, fingerprint: wrongFingerprint, wantError: "certificate"},
		} {
			t.Run(failure.name, func(t *testing.T) {
				failedMapping := cloneAnyTLSMapping(mapping)
				failedMapping["name"] = "controlled-tuic-" + failure.name
				failedMapping["fingerprint"] = failure.fingerprint
				if version == 4 {
					failedMapping["token"] = failure.credential
				} else {
					failedMapping["password"] = failure.credential
				}
				failedProxy, err := adapter.ParseProxy(failedMapping)
				if err != nil {
					t.Fatalf("ParseProxy() error = %v", err)
				}
				defer failedProxy.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				_, err = failedProxy.URLTest(ctx, target.URL, nil)
				cancel()
				if err == nil {
					t.Fatalf("invalid TUIC v%d credentials unexpectedly succeeded", version)
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
