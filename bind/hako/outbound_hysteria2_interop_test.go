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

func TestControlledHysteria2Interop(t *testing.T) {
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
		name          string
		obfs          string
		obfsPassword  string
		minPacketSize int
		maxPacketSize int
	}{
		{name: "QUICMTLS"},
		{name: "Salamander", obfs: "salamander", obfsPassword: "controlled-salamander"},
		{name: "Gecko", obfs: "gecko", obfsPassword: "controlled-gecko", minPacketSize: 600, maxPacketSize: 1100},
	} {
		t.Run(test.name, func(t *testing.T) {
			runControlledHysteria2Variant(
				t,
				test.obfs,
				test.obfsPassword,
				test.minPacketSize,
				test.maxPacketSize,
				serverCertificate,
				serverPrivateKey,
				serverFingerprint,
				clientCertificate,
				clientPrivateKey,
			)
		})
	}
}

// controlledInteropDeadline bounds the positive-path waits (URLTest, packet
// listen, UDP echo). These servers are all on 127.0.0.1, so the deadline is a
// hang detector, not a latency budget -- yet at 5s the Gecko variant (obfs
// padding 600-1100) missed it in 1/5 full-suite runs while passing 10/10 in
// isolation, always at exactly 5.00s: scheduler pressure, not the network.
// Green runs never pay this value; only a genuine hang does.
const controlledInteropDeadline = 30 * time.Second

func runControlledHysteria2Variant(
	t *testing.T,
	obfs string,
	obfsPassword string,
	minPacketSize int,
	maxPacketSize int,
	serverCertificate string,
	serverPrivateKey string,
	serverFingerprint string,
	clientCertificate string,
	clientPrivateKey string,
) {
	t.Helper()
	const password = "controlled-hysteria2-password"
	server, err := IN.NewHysteria2(&IN.Hysteria2Option{
		BaseOption: IN.BaseOption{
			NameStr: "controlled-hysteria2-inbound",
			Listen:  "127.0.0.1",
			Port:    "0",
		},
		Users:             map[string]string{"controlled": password},
		Obfs:              obfs,
		ObfsPassword:      obfsPassword,
		ObfsMinPacketSize: minPacketSize,
		ObfsMaxPacketSize: maxPacketSize,
		Certificate:       serverCertificate,
		PrivateKey:        serverPrivateKey,
		ClientAuthCert:    clientCertificate,
	})
	if err != nil {
		t.Fatalf("NewHysteria2() error = %v", err)
	}
	if err := server.Listen(&controlledReferenceTunnel{}); err != nil {
		t.Fatalf("Hysteria2 Listen() error = %v", err)
	}
	defer server.Close()
	serverAddress, err := netip.ParseAddrPort(server.Address())
	if err != nil {
		t.Fatalf("parse Hysteria2 address %q: %v", server.Address(), err)
	}
	mapping := map[string]any{
		"name":                 "controlled-hysteria2-outbound",
		"type":                 "hysteria2",
		"server":               serverAddress.Addr().String(),
		"port":                 serverAddress.Port(),
		"password":             password,
		"obfs":                 obfs,
		"obfs-password":        obfsPassword,
		"obfs-min-packet-size": minPacketSize,
		"obfs-max-packet-size": maxPacketSize,
		"fingerprint":          serverFingerprint,
		"certificate":          clientCertificate,
		"private-key":          clientPrivateKey,
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
	ctx, cancel := context.WithTimeout(context.Background(), controlledInteropDeadline)
	delay, err := proxy.URLTest(ctx, target.URL, nil)
	cancel()
	if err != nil {
		t.Fatalf("Hysteria2 URLTest() error = %v", err)
	}
	if delay == 0 {
		t.Fatal("Hysteria2 URLTest() returned the failure sentinel delay")
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
	ctx, cancel = context.WithTimeout(context.Background(), controlledInteropDeadline)
	packetConnection, err := proxy.ListenPacketContext(ctx, metadata)
	cancel()
	if err != nil {
		t.Fatalf("ListenPacketContext() error = %v", err)
	}
	defer packetConnection.Close()
	payload := []byte("hako-controlled-hysteria2-udp-" + obfs)
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
	case <-time.After(controlledInteropDeadline):
		t.Fatal("timed out waiting for Hysteria2 UDP response")
	}
	if !bytes.Equal(buffer[:n], payload) || source.String() != udpAddress.String() {
		t.Fatalf("UDP response = (%q, %v), want (%q, %v)", buffer[:n], source, payload, udpAddress)
	}

	if obfs == "" {
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
				failedMapping["name"] = "controlled-hysteria2-" + failure.name
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
					t.Fatal("invalid Hysteria2 credentials unexpectedly succeeded")
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
