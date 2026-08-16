package hako

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/adapter"
	C "github.com/TokenPLS/Hako/constant"
)

func TestControlledSOCKS5SingBoxReferenceInterop(t *testing.T) {
	referenceBinary := os.Getenv(singBoxReferenceBinaryEnvironment)
	if referenceBinary == "" {
		t.Skip(singBoxReferenceBinaryEnvironment + " is not set")
	}
	verifySingBoxReferenceBinary(t, referenceBinary)

	const (
		username = "controlled-socks5-user"
		password = "controlled-socks5-password"
	)
	serverPort := reserveControlledTCPPort(t)
	temporaryDirectory := t.TempDir()
	serverConfig, err := json.Marshal(map[string]any{
		"log": map[string]any{"level": "info", "timestamp": false},
		"inbounds": []map[string]any{{
			"type":        "socks",
			"tag":         "controlled-socks5-in",
			"listen":      "127.0.0.1",
			"listen_port": serverPort,
			"users":       []map[string]any{{"username": username, "password": password}},
		}},
		"outbounds": []map[string]any{{"type": "direct", "tag": "direct"}},
		"route":     map[string]any{"final": "direct"},
	})
	if err != nil {
		t.Fatalf("marshal sing-box SOCKS5 config: %v", err)
	}
	configPath := filepath.Join(temporaryDirectory, "server.json")
	if err := os.WriteFile(configPath, serverConfig, 0o600); err != nil {
		t.Fatalf("write sing-box SOCKS5 config: %v", err)
	}
	serverLogs := startControlledSingBoxReference(t, referenceBinary, configPath)

	newProxy := func(t *testing.T, name, credential string) C.Proxy {
		t.Helper()
		proxy, err := adapter.ParseProxy(map[string]any{
			"name":     name,
			"type":     "socks5",
			"server":   "127.0.0.1",
			"port":     serverPort,
			"username": username,
			"password": credential,
			"udp":      true,
		})
		if err != nil {
			t.Fatalf("ParseProxy() error = %v", err)
		}
		t.Cleanup(func() { _ = proxy.Close() })
		return proxy
	}
	proxy := newProxy(t, "controlled-socks5-sing-box", password)

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
		t.Fatalf("SOCKS5 sing-box URLTest() error = %v\nsing-box logs:\n%s", err, serverLogs.String())
	}
	if delay == 0 {
		t.Fatal("SOCKS5 sing-box URLTest() returned the failure sentinel delay")
	}
	if count := targetRequests.Load(); count != 1 {
		t.Fatalf("SOCKS5 sing-box target request count = %d, want 1", count)
	}

	udpTarget, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen for SOCKS5 UDP echo target: %v", err)
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
		t.Fatalf("SOCKS5 sing-box UDP session failed: %v\nsing-box logs:\n%s", err, serverLogs.String())
	}
	if err := packetConnection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		_ = packetConnection.Close()
		t.Fatalf("SOCKS5 sing-box UDP deadline failed: %v", err)
	}
	payload := []byte("hako-controlled-socks5-sing-box-udp")
	if _, err := packetConnection.WriteTo(payload, udpAddress); err != nil {
		_ = packetConnection.Close()
		t.Fatalf("SOCKS5 sing-box UDP write failed: %v", err)
	}
	buffer := make([]byte, 64*1024)
	count, source, err := packetConnection.ReadFrom(buffer)
	closeError := packetConnection.Close()
	if err != nil {
		t.Fatalf("SOCKS5 sing-box UDP read failed: %v\nsing-box logs:\n%s", err, serverLogs.String())
	}
	if closeError != nil && !errors.Is(closeError, net.ErrClosed) {
		t.Fatalf("SOCKS5 sing-box UDP close failed: %v", closeError)
	}
	if !bytes.Equal(buffer[:count], payload) || source.String() != udpAddress.String() {
		t.Fatal("SOCKS5 sing-box UDP response did not match the request")
	}

	failedProxy := newProxy(t, "controlled-socks5-sing-box-invalid-password", "invalid-socks5-password")
	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	_, err = failedProxy.URLTest(ctx, target.URL, nil)
	cancel()
	if err == nil {
		t.Fatal("SOCKS5 sing-box invalid password unexpectedly succeeded")
	}
	if count := targetRequests.Load(); count != 1 {
		t.Fatalf("SOCKS5 sing-box failed attempt leaked to target; request count = %d", count)
	}
}
