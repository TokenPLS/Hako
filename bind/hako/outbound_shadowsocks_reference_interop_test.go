package hako

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/adapter"
	C "github.com/TokenPLS/Hako/constant"
)

func TestControlledShadowsocksSingBoxReferenceInterop(t *testing.T) {
	referenceBinary := os.Getenv(singBoxReferenceBinaryEnvironment)
	if referenceBinary == "" {
		t.Skip(singBoxReferenceBinaryEnvironment + " is not set")
	}
	verifySingBoxReferenceBinary(t, referenceBinary)

	for _, variant := range []struct {
		name            string
		cipher          string
		password        string
		invalidPassword string
	}{
		{
			name:            "AEAD",
			cipher:          "aes-128-gcm",
			password:        "controlled-shadowsocks-reference-password",
			invalidPassword: "invalid-shadowsocks-reference-password",
		},
		{
			name:            "2022AES128",
			cipher:          "2022-blake3-aes-128-gcm",
			password:        base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x31}, 16)),
			invalidPassword: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x41}, 16)),
		},
		{
			name:            "2022ChaCha20",
			cipher:          "2022-blake3-chacha20-poly1305",
			password:        base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x32}, 32)),
			invalidPassword: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32)),
		},
	} {
		t.Run(variant.name, func(t *testing.T) {
			runControlledShadowsocksSingBoxReferenceVariant(
				t,
				referenceBinary,
				variant.cipher,
				variant.password,
				variant.invalidPassword,
			)
		})
	}
}

func runControlledShadowsocksSingBoxReferenceVariant(t *testing.T, binary, cipher, password, invalidPassword string) {
	t.Helper()
	port := reserveControlledTCPAndUDPPort(t)
	temporaryDirectory := t.TempDir()
	serverConfig, err := json.Marshal(map[string]any{
		"log": map[string]any{"level": "info", "timestamp": false},
		"inbounds": []map[string]any{{
			"type":        "shadowsocks",
			"tag":         "controlled-shadowsocks-in",
			"listen":      "127.0.0.1",
			"listen_port": port,
			"method":      cipher,
			"password":    password,
		}},
		"outbounds": []map[string]any{{"type": "direct", "tag": "direct"}},
		"route":     map[string]any{"final": "direct"},
	})
	if err != nil {
		t.Fatalf("marshal sing-box Shadowsocks config: %v", err)
	}
	configPath := filepath.Join(temporaryDirectory, "server.json")
	if err := os.WriteFile(configPath, serverConfig, 0o600); err != nil {
		t.Fatalf("write sing-box Shadowsocks config: %v", err)
	}
	serverLogs := startControlledSingBoxReference(t, binary, configPath)

	proxyMapping := map[string]any{
		"name":     "controlled-shadowsocks-sing-box-" + cipher,
		"type":     "ss",
		"server":   "127.0.0.1",
		"port":     port,
		"password": password,
		"cipher":   cipher,
		"udp":      true,
	}
	proxy, err := adapter.ParseProxy(proxyMapping)
	if err != nil {
		t.Fatalf("ParseProxy() error = %v", err)
	}
	defer proxy.Close()

	targetReached := make(chan struct{}, 2)
	target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		targetReached <- struct{}{}
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
		t.Fatalf("Shadowsocks %s sing-box URLTest() error = %v\nsing-box logs:\n%s", cipher, err, serverLogs.String())
	}
	if delay == 0 {
		t.Fatalf("Shadowsocks %s sing-box URLTest() returned the failure sentinel delay", cipher)
	}
	select {
	case <-targetReached:
	case <-time.After(time.Second):
		t.Fatalf("Shadowsocks %s request did not reach the target", cipher)
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
		t.Fatalf("Shadowsocks %s sing-box UDP session failed: %v\nsing-box logs:\n%s", cipher, err, serverLogs.String())
	}
	if err := packetConnection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		_ = packetConnection.Close()
		t.Fatalf("Shadowsocks %s sing-box UDP deadline failed: %v", cipher, err)
	}
	payload := []byte("hako-controlled-shadowsocks-sing-box-udp-" + cipher)
	if _, err := packetConnection.WriteTo(payload, udpAddress); err != nil {
		_ = packetConnection.Close()
		t.Fatalf("Shadowsocks %s sing-box UDP write failed: %v", cipher, err)
	}
	buffer := make([]byte, 64*1024)
	count, source, err := packetConnection.ReadFrom(buffer)
	closeError := packetConnection.Close()
	if err != nil {
		t.Fatalf("Shadowsocks %s sing-box UDP read failed: %v\nsing-box logs:\n%s", cipher, err, serverLogs.String())
	}
	if closeError != nil {
		t.Fatalf("Shadowsocks %s sing-box UDP close failed: %v", cipher, closeError)
	}
	if !bytes.Equal(buffer[:count], payload) || source.String() != udpAddress.String() {
		t.Fatalf("Shadowsocks %s sing-box UDP response did not match the request", cipher)
	}

	failedMapping := make(map[string]any, len(proxyMapping))
	for key, value := range proxyMapping {
		failedMapping[key] = value
	}
	failedMapping["name"] = "controlled-shadowsocks-sing-box-invalid-credential-" + cipher
	failedMapping["password"] = invalidPassword
	failedProxy, err := adapter.ParseProxy(failedMapping)
	if err != nil {
		t.Fatalf("ParseProxy() invalid credential error = %v", err)
	}
	defer failedProxy.Close()
	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	_, err = failedProxy.URLTest(ctx, target.URL, nil)
	cancel()
	if err == nil {
		t.Fatalf("invalid Shadowsocks %s credential unexpectedly succeeded", cipher)
	}
	select {
	case <-targetReached:
		t.Fatalf("invalid Shadowsocks %s credential leaked to the target", cipher)
	case <-time.After(50 * time.Millisecond):
	}
}

func reserveControlledTCPAndUDPPort(t *testing.T) int {
	t.Helper()
	for attempt := 0; attempt < 10; attempt++ {
		listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatalf("reserve controlled TCP port: %v", err)
		}
		port := listener.Addr().(*net.TCPAddr).Port
		packetConnection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		if err != nil {
			_ = listener.Close()
			continue
		}
		if err := packetConnection.Close(); err != nil {
			_ = listener.Close()
			t.Fatalf("release reserved UDP port: %v", err)
		}
		if err := listener.Close(); err != nil {
			t.Fatalf("release reserved TCP port: %v", err)
		}
		return port
	}
	t.Fatal("failed to reserve a shared TCP and UDP port")
	return 0
}
