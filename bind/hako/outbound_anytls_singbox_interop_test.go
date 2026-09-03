package hako

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/adapter"
	"github.com/TokenPLS/Hako/component/ca"
	C "github.com/TokenPLS/Hako/constant"
)

func TestControlledAnyTLSSingBoxReferenceInterop(t *testing.T) {
	referenceBinary := os.Getenv(singBoxReferenceBinaryEnvironment)
	if referenceBinary == "" {
		t.Skip(singBoxReferenceBinaryEnvironment + " is not set")
	}
	verifySingBoxReferenceBinary(t, referenceBinary)

	certificate, privateKey, fingerprint, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatalf("generate sing-box AnyTLS certificate: %v", err)
	}
	temporaryDirectory := t.TempDir()
	certificatePath := filepath.Join(temporaryDirectory, "server.pem")
	privateKeyPath := filepath.Join(temporaryDirectory, "server.key")
	if err := os.WriteFile(certificatePath, []byte(certificate), 0o600); err != nil {
		t.Fatalf("write sing-box AnyTLS certificate: %v", err)
	}
	if err := os.WriteFile(privateKeyPath, []byte(privateKey), 0o600); err != nil {
		t.Fatalf("write sing-box AnyTLS private key: %v", err)
	}
	const (
		password   = "controlled-anytls-sing-box-password"
		serverName = "controlled-anytls.example"
	)
	serverPort := reserveControlledTCPPort(t)
	serverConfig, err := json.Marshal(map[string]any{
		"log": map[string]any{"level": "info", "timestamp": false},
		"inbounds": []map[string]any{{
			"type":        "anytls",
			"tag":         "controlled-anytls-in",
			"listen":      "127.0.0.1",
			"listen_port": serverPort,
			"users":       []map[string]any{{"name": "controlled", "password": password}},
			"padding_scheme": []string{
				"stop=4",
				"0=40-40",
				"1=80-80",
				"2=120-120",
				"3=160-160",
			},
			"tls": map[string]any{
				"enabled":          true,
				"server_name":      serverName,
				"certificate_path": certificatePath,
				"key_path":         privateKeyPath,
			},
		}},
		"outbounds": []map[string]any{{"type": "direct", "tag": "direct"}},
		"route":     map[string]any{"final": "direct"},
	})
	if err != nil {
		t.Fatalf("marshal sing-box AnyTLS config: %v", err)
	}
	configPath := filepath.Join(temporaryDirectory, "server.json")
	if err := os.WriteFile(configPath, serverConfig, 0o600); err != nil {
		t.Fatalf("write sing-box AnyTLS config: %v", err)
	}
	serverLogs := startControlledSingBoxReference(t, referenceBinary, configPath)

	mapping := map[string]any{
		"name":             "controlled-anytls-sing-box",
		"type":             "anytls",
		"server":           "127.0.0.1",
		"port":             serverPort,
		"password":         password,
		"sni":              serverName,
		"fingerprint":      fingerprint,
		"udp":              true,
		"min-idle-session": 1,
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
		t.Fatalf("AnyTLS sing-box URLTest() error = %v\nsing-box logs:\n%s", err, serverLogs.String())
	}
	if delay == 0 {
		t.Fatal("AnyTLS sing-box URLTest() returned the failure sentinel delay")
	}
	if count := targetRequests.Load(); count != 1 {
		t.Fatalf("AnyTLS sing-box target request count = %d, want 1", count)
	}

	udpTarget, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen for AnyTLS UDP echo target: %v", err)
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
		t.Fatalf("AnyTLS sing-box UDP session failed: %v\nsing-box logs:\n%s", err, serverLogs.String())
	}
	if err := packetConnection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		_ = packetConnection.Close()
		t.Fatalf("AnyTLS sing-box UDP deadline failed: %v", err)
	}
	payload := []byte("hako-controlled-anytls-sing-box-udp")
	if _, err := packetConnection.WriteTo(payload, udpAddress); err != nil {
		_ = packetConnection.Close()
		t.Fatalf("AnyTLS sing-box UDP write failed: %v", err)
	}
	buffer := make([]byte, 64*1024)
	count, source, err := packetConnection.ReadFrom(buffer)
	closeError := packetConnection.Close()
	if err != nil {
		t.Fatalf("AnyTLS sing-box UDP read failed: %v\nsing-box logs:\n%s", err, serverLogs.String())
	}
	if closeError != nil {
		t.Fatalf("AnyTLS sing-box UDP close failed: %v", closeError)
	}
	if !bytes.Equal(buffer[:count], payload) || source.String() != udpAddress.String() {
		t.Fatal("AnyTLS sing-box UDP response did not match the request")
	}

	_, _, wrongFingerprint, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatalf("generate wrong AnyTLS fingerprint: %v", err)
	}
	failedMapping := cloneAnyTLSMapping(mapping)
	failedMapping["name"] = "controlled-anytls-sing-box-invalid-certificate"
	failedMapping["fingerprint"] = wrongFingerprint
	failedMapping["min-idle-session"] = 0
	failedProxy, err := adapter.ParseProxy(failedMapping)
	if err != nil {
		t.Fatalf("ParseProxy() invalid certificate variant error = %v", err)
	}
	defer failedProxy.Close()
	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	_, err = failedProxy.URLTest(ctx, target.URL, nil)
	cancel()
	if err == nil {
		t.Fatal("AnyTLS sing-box invalid certificate unexpectedly succeeded")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "certificate") {
		t.Fatalf("AnyTLS sing-box failure error = %v, want certificate failure", err)
	}
	if count := targetRequests.Load(); count != 1 {
		t.Fatalf("AnyTLS sing-box failed attempt leaked to target; request count = %d", count)
	}

	// TestControlledAnyTLSInterop retains the invalid-password fail-closed
	// behavior gate. Repeating that case against sing-box exposes an upstream
	// mihomo close/write race in transport/anytls/session.Stream; do not claim
	// that independent negative path race-clean until upstream fixes it.
}
