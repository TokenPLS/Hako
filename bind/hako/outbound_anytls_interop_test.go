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

func TestControlledAnyTLSInterop(t *testing.T) {
	pinUnifiedDelayOff(t)
	serverCertificate, serverPrivateKey, serverFingerprint, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatalf("generate server certificate: %v", err)
	}
	clientCertificate, clientPrivateKey, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatalf("generate client certificate: %v", err)
	}
	_, _, wrongFingerprint, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatalf("generate wrong fingerprint: %v", err)
	}

	const (
		password      = "controlled-anytls-password"
		paddingScheme = "stop=4\n0=40-40\n1=80-80\n2=120-120\n3=160-160"
	)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for AnyTLS: %v", err)
	}
	var acceptedSessions atomic.Int32
	countingListener := &controlledCountingListener{Listener: listener, accepted: &acceptedSessions}
	server, err := IN.NewAnyTLS(&IN.AnyTLSOption{
		BaseOption: IN.BaseOption{
			NameStr: "controlled-anytls-inbound",
			Listen:  "127.0.0.1",
			Port:    "0",
			ListenConfigForAPI: controlledMieruListenConfig{
				listen: func(context.Context, string, string) (net.Listener, error) {
					return countingListener, nil
				},
				listenPacket: func(context.Context, string, string) (net.PacketConn, error) {
					panic("unexpected AnyTLS packet listener")
				},
			},
		},
		Users:          map[string]string{"controlled-user": password},
		Certificate:    serverCertificate,
		PrivateKey:     serverPrivateKey,
		ClientAuthCert: clientCertificate,
		PaddingScheme:  paddingScheme,
	})
	if err != nil {
		t.Fatalf("NewAnyTLS() error = %v", err)
	}
	tunnel := &controlledReferenceTunnel{}
	if err := server.Listen(tunnel); err != nil {
		t.Fatalf("AnyTLS Listen() error = %v", err)
	}
	defer server.Close()
	serverAddress, err := netip.ParseAddrPort(server.Address())
	if err != nil {
		t.Fatalf("parse AnyTLS address %q: %v", server.Address(), err)
	}

	proxyMapping := map[string]any{
		"name":             "controlled-anytls-outbound",
		"type":             "anytls",
		"server":           serverAddress.Addr().String(),
		"port":             serverAddress.Port(),
		"password":         password,
		"fingerprint":      serverFingerprint,
		"certificate":      clientCertificate,
		"private-key":      clientPrivateKey,
		"udp":              true,
		"min-idle-session": 1,
	}
	proxy, err := adapter.ParseProxy(proxyMapping)
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
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	delay, err := proxy.URLTest(ctx, target.URL, nil)
	cancel()
	if err != nil {
		t.Fatalf("AnyTLS URLTest() error = %v", err)
	}
	if delay == 0 {
		t.Fatal("AnyTLS URLTest() returned the failure sentinel delay")
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
	ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
	packetConnection, err := proxy.ListenPacketContext(ctx, metadata)
	cancel()
	if err != nil {
		t.Fatalf("AnyTLS ListenPacketContext() error = %v", err)
	}
	t.Cleanup(func() { _ = packetConnection.Close() })
	if err := packetConnection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetDeadline() error = %v", err)
	}
	payload := []byte("hako-controlled-anytls-udp")
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
	if err := packetConnection.Close(); err != nil {
		t.Fatalf("AnyTLS packet connection close error = %v", err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
	delay, err = proxy.URLTest(ctx, target.URL, nil)
	cancel()
	if err != nil {
		t.Fatalf("AnyTLS reused-session URLTest() error = %v", err)
	}
	if delay == 0 {
		t.Fatal("AnyTLS reused-session URLTest() returned the failure sentinel delay")
	}
	if count := targetRequests.Load(); count != 2 {
		t.Fatalf("target request count after reuse = %d, want 2", count)
	}
	if count := acceptedSessions.Load(); count != 1 {
		t.Fatalf("accepted AnyTLS sessions = %d, want one reused TLS session", count)
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
			mapping := cloneAnyTLSMapping(proxyMapping)
			mapping["name"] = "controlled-anytls-" + failure.name
			mapping["password"] = failure.password
			mapping["fingerprint"] = failure.fingerprint
			failedProxy, err := adapter.ParseProxy(mapping)
			if err != nil {
				t.Fatalf("ParseProxy() error = %v", err)
			}
			defer failedProxy.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			_, err = failedProxy.URLTest(ctx, target.URL, nil)
			cancel()
			if err == nil {
				t.Fatal("invalid AnyTLS credentials unexpectedly succeeded")
			}
			if failure.wantError != "" && !strings.Contains(strings.ToLower(err.Error()), failure.wantError) {
				t.Fatalf("failure error = %v, want %q", err, failure.wantError)
			}
			if count := targetRequests.Load(); count != 2 {
				t.Fatalf("failed attempt leaked to target; request count = %d", count)
			}
		})
	}
}

type controlledCountingListener struct {
	net.Listener
	accepted *atomic.Int32
}

func (listener *controlledCountingListener) Accept() (net.Conn, error) {
	connection, err := listener.Listener.Accept()
	if err == nil {
		listener.accepted.Add(1)
	}
	return connection, err
}

func cloneAnyTLSMapping(source map[string]any) map[string]any {
	result := make(map[string]any, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}
