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
	C "github.com/TokenPLS/Hako/constant"
	IN "github.com/TokenPLS/Hako/listener/inbound"
)

// TestControlledShadowQUICReferenceInterop is the controlled interop evidence for
// the ShadowQUIC outbound that mihomo v1.19.29 introduced. The reference server is
// this core's own ShadowQUIC listener, the same pattern the Hysteria2 realm and
// TUIC interop tests use, driven through adapter.ParseProxy so the config surface
// is exercised too. It covers QUIC, TCP, UDP, JLS authentication (a wrong password
// must fail without reaching the target) and the brutal congestion-control
// negotiation, which transport/shadowquic treats as an optional upgrade that must
// leave the connection usable.
func TestControlledShadowQUICReferenceInterop(t *testing.T) {
	for _, test := range []struct {
		name                 string
		congestionController string
		up                   string
		down                 string
		quicVersion          string
	}{
		{name: "V1Cubic", congestionController: "cubic", quicVersion: "v1"},
		{name: "V2BrutalFallback", congestionController: "brutal", up: "50 Mbps", down: "100 Mbps", quicVersion: "v2"},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			runControlledShadowQUICVariant(t, test.quicVersion, test.congestionController, test.up, test.down)
		})
	}
}

func runControlledShadowQUICVariant(t *testing.T, quicVersion, congestionController, up, down string) {
	t.Helper()
	const username = "controlled-shadowquic-user"
	const password = "controlled-shadowquic-password"

	server, err := IN.NewShadowQuic(&IN.ShadowQuicOption{
		BaseOption: IN.BaseOption{
			NameStr: "controlled-shadowquic-inbound",
			Listen:  "127.0.0.1",
			Port:    "0",
		},
		ALPN:                 []string{"h3"},
		QUICVersions:         []string{quicVersion},
		ZeroRTT:              true,
		MaxIdleTime:          30000,
		MaxDatagramFrameSize: 1400,
		Users:                []IN.ShadowQuicUser{{Username: username, Password: password}},
		// An authenticated session must never reach the JLS upstream; point it at a
		// closed port so any fallthrough would fail loudly instead of succeeding.
		JLSUpstream: IN.ShadowQuicJLSUpstream{Addr: "127.0.0.1:1"},
	})
	if err != nil {
		t.Fatalf("NewShadowQuic() error = %v", err)
	}
	if err := server.Listen(&controlledReferenceTunnel{}); err != nil {
		t.Fatalf("ShadowQUIC Listen() error = %v", err)
	}
	defer server.Close()

	address, err := netip.ParseAddrPort(server.Address())
	if err != nil {
		t.Fatalf("parse ShadowQUIC address %q: %v", server.Address(), err)
	}

	mapping := map[string]any{
		"name":                    "controlled-shadowquic-outbound",
		"type":                    "shadowquic",
		"server":                  address.Addr().String(),
		"port":                    int(address.Port()),
		"username":                username,
		"password":                password,
		"alpn":                    []string{"h3"},
		"quic-versions":           []string{quicVersion},
		"zero-rtt":                true,
		"max-datagram-frame-size": 1400,
		"congestion-controller":   congestionController,
	}
	if up != "" {
		mapping["up"] = up
	}
	if down != "" {
		mapping["down"] = down
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

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	delay, err := proxy.URLTest(ctx, target.URL, nil)
	cancel()
	if err != nil {
		t.Fatalf("ShadowQUIC %s URLTest() error = %v", congestionController, err)
	}
	if delay == 0 {
		t.Fatalf("ShadowQUIC %s URLTest() returned the failure sentinel delay", congestionController)
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
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	packetConnection, err := proxy.ListenPacketContext(ctx, &C.Metadata{
		NetWork: C.UDP,
		Type:    C.TUN,
		DstIP:   udpAddrPort.Addr(),
		DstPort: udpAddrPort.Port(),
	})
	cancel()
	if err != nil {
		t.Fatalf("ListenPacketContext() error = %v", err)
	}
	defer packetConnection.Close()
	payload := []byte("hako-controlled-shadowquic-udp-" + congestionController)
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
	select {
	case response := <-result:
		if response.err != nil {
			t.Fatalf("ReadFrom() error = %v", response.err)
		}
		if !bytes.Equal(buffer[:response.n], payload) || response.source.String() != udpAddress.String() {
			t.Fatalf("UDP response = (%q, %v), want (%q, %v)", buffer[:response.n], response.source, payload, udpAddress)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for ShadowQUIC UDP response")
	}

	t.Run("InvalidJLSCredentials", func(t *testing.T) {
		failed := make(map[string]any, len(mapping))
		for key, value := range mapping {
			failed[key] = value
		}
		failed["name"] = "controlled-shadowquic-invalid"
		failed["password"] = "wrong-shadowquic-password"
		failedProxy, err := adapter.ParseProxy(failed)
		if err != nil {
			t.Fatalf("ParseProxy() error = %v", err)
		}
		defer failedProxy.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err = failedProxy.URLTest(ctx, target.URL, nil)
		cancel()
		if err == nil {
			t.Fatal("invalid ShadowQUIC credentials unexpectedly succeeded")
		}
		if strings.Contains(strings.ToLower(err.Error()), "no such host") {
			t.Fatalf("unexpected resolution failure instead of an authentication failure: %v", err)
		}
		if count := targetRequests.Load(); count != 1 {
			t.Fatalf("failed attempt leaked to target; request count = %d", count)
		}
	})
}
