package hako

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/adapter"
	"github.com/TokenPLS/Hako/component/resolver"
	C "github.com/TokenPLS/Hako/constant"
)

func TestControlledDirectTCPInterop(t *testing.T) {
	for _, test := range []struct {
		name    string
		network string
		address string
		version string
	}{
		{name: "IPv4", network: "tcp4", address: "127.0.0.1:0", version: "ipv4"},
		{name: "IPv6", network: "tcp6", address: "[::1]:0", version: "ipv6"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.version == "ipv6" {
				// The production config executor derives this process-wide policy
				// from top-level `ipv6: true`. ParseProxy alone intentionally does
				// not alter runtime DNS policy, so reproduce that prerequisite here.
				originalDisableIPv6 := resolver.DisableIPv6
				resolver.DisableIPv6 = false
				defer func() { resolver.DisableIPv6 = originalDisableIPv6 }()
			}

			listener, err := net.Listen(test.network, test.address)
			if err != nil {
				t.Skipf("%s loopback is unavailable: %v", test.name, err)
			}
			target := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.Method != http.MethodHead {
					t.Errorf("target method = %s, want HEAD", request.Method)
				}
				writer.WriteHeader(http.StatusNoContent)
			}))
			target.Listener = listener
			target.Start()
			t.Cleanup(target.Close)

			proxy, err := adapter.ParseProxy(map[string]any{
				"name":       "controlled-direct-" + test.name,
				"type":       "direct",
				"ip-version": test.version,
			})
			if err != nil {
				t.Fatalf("ParseProxy() error = %v", err)
			}
			t.Cleanup(func() { _ = proxy.Close() })

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			delay, err := proxy.URLTest(ctx, target.URL, nil)
			if err != nil {
				t.Fatalf("direct URLTest() error = %v", err)
			}
			if delay == 0 {
				t.Fatal("direct URLTest() returned the failure sentinel delay")
			}
		})
	}
}

func TestControlledDirectUDPInterop(t *testing.T) {
	for _, test := range []struct {
		name    string
		network string
		address string
		version string
	}{
		{name: "IPv4", network: "udp4", address: "127.0.0.1:0", version: "ipv4"},
		{name: "IPv6", network: "udp6", address: "[::1]:0", version: "ipv6"},
	} {
		t.Run(test.name, func(t *testing.T) {
			address, err := net.ResolveUDPAddr(test.network, test.address)
			if err != nil {
				t.Fatalf("ResolveUDPAddr() error = %v", err)
			}
			target, err := net.ListenUDP(test.network, address)
			if err != nil {
				t.Skipf("%s loopback is unavailable: %v", test.name, err)
			}
			t.Cleanup(func() { _ = target.Close() })
			go serveUDPEcho(target)

			proxy, err := adapter.ParseProxy(map[string]any{
				"name":       "controlled-direct-udp-" + test.name,
				"type":       "direct",
				"ip-version": test.version,
			})
			if err != nil {
				t.Fatalf("ParseProxy() error = %v", err)
			}
			t.Cleanup(func() { _ = proxy.Close() })

			targetAddress := target.LocalAddr().(*net.UDPAddr)
			targetAddrPort := targetAddress.AddrPort()
			metadata := &C.Metadata{
				NetWork: C.UDP,
				Type:    C.TUN,
				DstIP:   targetAddrPort.Addr(),
				DstPort: targetAddrPort.Port(),
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			packetConnection, err := proxy.ListenPacketContext(ctx, metadata)
			if err != nil {
				t.Fatalf("ListenPacketContext() error = %v", err)
			}
			defer packetConnection.Close()
			if err := packetConnection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatalf("SetDeadline() error = %v", err)
			}

			payload := []byte("hako-controlled-direct-udp-" + test.name)
			if _, err := packetConnection.WriteTo(payload, targetAddress); err != nil {
				t.Fatalf("WriteTo() error = %v", err)
			}
			buffer := make([]byte, 64*1024)
			n, source, err := packetConnection.ReadFrom(buffer)
			if err != nil {
				t.Fatalf("ReadFrom() error = %v", err)
			}
			if !bytes.Equal(buffer[:n], payload) {
				t.Fatalf("UDP echo payload = %q, want %q", buffer[:n], payload)
			}
			if source.String() != targetAddress.String() {
				t.Fatalf("UDP echo source = %s, want %s", source, targetAddress)
			}
		})
	}
}
