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
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/adapter"
	"github.com/TokenPLS/Hako/component/ca"
	C "github.com/TokenPLS/Hako/constant"
)

func TestControlledHysteria2SingBoxReferenceInterop(t *testing.T) {
	referenceBinary := os.Getenv(singBoxReferenceBinaryEnvironment)
	if referenceBinary == "" {
		t.Skip(singBoxReferenceBinaryEnvironment + " is not set")
	}
	verifySingBoxReferenceBinary(t, referenceBinary)

	for _, variant := range []struct {
		name         string
		obfs         string
		obfsPassword string
	}{
		{name: "Plain"},
		{name: "Salamander", obfs: "salamander", obfsPassword: "controlled-hysteria2-salamander"},
	} {
		t.Run(variant.name, func(t *testing.T) {
			runControlledHysteria2SingBoxReferenceVariant(t, referenceBinary, variant.obfs, variant.obfsPassword)
		})
	}
}

func runControlledHysteria2SingBoxReferenceVariant(t *testing.T, binary, obfs, obfsPassword string) {
	t.Helper()
	certificate, privateKey, fingerprint, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatalf("generate sing-box Hysteria2 certificate: %v", err)
	}
	temporaryDirectory := t.TempDir()
	certificatePath := filepath.Join(temporaryDirectory, "server.pem")
	privateKeyPath := filepath.Join(temporaryDirectory, "server.key")
	if err := os.WriteFile(certificatePath, []byte(certificate), 0o600); err != nil {
		t.Fatalf("write sing-box Hysteria2 certificate: %v", err)
	}
	if err := os.WriteFile(privateKeyPath, []byte(privateKey), 0o600); err != nil {
		t.Fatalf("write sing-box Hysteria2 private key: %v", err)
	}
	const password = "controlled-hysteria2-reference-password"
	serverPort := reserveControlledUDPPort(t)
	inbound := map[string]any{
		"type":        "hysteria2",
		"tag":         "controlled-hysteria2-in",
		"listen":      "127.0.0.1",
		"listen_port": serverPort,
		"up_mbps":     100,
		"down_mbps":   100,
		"users":       []map[string]any{{"name": "controlled", "password": password}},
		"tls": map[string]any{
			"enabled":          true,
			"server_name":      "controlled-hysteria2.example",
			"certificate_path": certificatePath,
			"key_path":         privateKeyPath,
		},
	}
	if obfs != "" {
		inbound["obfs"] = map[string]any{"type": obfs, "password": obfsPassword}
	}
	serverConfig, err := json.Marshal(map[string]any{
		"log":       map[string]any{"level": "info", "timestamp": false},
		"inbounds":  []map[string]any{inbound},
		"outbounds": []map[string]any{{"type": "direct", "tag": "direct"}},
		"route":     map[string]any{"final": "direct"},
	})
	if err != nil {
		t.Fatalf("marshal sing-box Hysteria2 config: %v", err)
	}
	configPath := filepath.Join(temporaryDirectory, "server.json")
	if err := os.WriteFile(configPath, serverConfig, 0o600); err != nil {
		t.Fatalf("write sing-box Hysteria2 config: %v", err)
	}
	serverLogs := startControlledSingBoxReference(t, binary, configPath)

	mapping := map[string]any{
		"name":          "controlled-hysteria2-sing-box",
		"type":          "hysteria2",
		"server":        "127.0.0.1",
		"port":          serverPort,
		"password":      password,
		"obfs":          obfs,
		"obfs-password": obfsPassword,
		"sni":           "controlled-hysteria2.example",
		"fingerprint":   fingerprint,
		"up":            "100 Mbps",
		"down":          "100 Mbps",
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
		t.Fatalf("Hysteria2 sing-box URLTest() error = %v\nsing-box logs:\n%s", err, serverLogs.String())
	}
	if delay == 0 {
		t.Fatal("Hysteria2 sing-box URLTest() returned the failure sentinel delay")
	}
	if count := targetRequests.Load(); count != 1 {
		t.Fatalf("Hysteria2 sing-box target request count = %d, want 1", count)
	}

	udpTarget, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen for Hysteria2 UDP echo target: %v", err)
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
		t.Fatalf("Hysteria2 sing-box UDP session failed: %v\nsing-box logs:\n%s", err, serverLogs.String())
	}
	payload := []byte("hako-controlled-hysteria2-sing-box-udp-" + obfs)
	if _, err := packetConnection.WriteTo(payload, udpAddress); err != nil {
		_ = packetConnection.Close()
		t.Fatalf("Hysteria2 sing-box UDP write failed: %v", err)
	}
	buffer := make([]byte, 64*1024)
	type packetResult struct {
		count  int
		source net.Addr
		err    error
	}
	result := make(chan packetResult, 1)
	go func() {
		count, source, err := packetConnection.ReadFrom(buffer)
		result <- packetResult{count: count, source: source, err: err}
	}()
	var count int
	var source net.Addr
	select {
	case response := <-result:
		if response.err != nil {
			_ = packetConnection.Close()
			t.Fatalf("Hysteria2 sing-box UDP read failed: %v\nsing-box logs:\n%s", response.err, serverLogs.String())
		}
		count, source = response.count, response.source
	case <-time.After(5 * time.Second):
		_ = packetConnection.Close()
		select {
		case <-result:
		case <-time.After(time.Second):
		}
		t.Fatalf("Hysteria2 sing-box UDP read timed out\nsing-box logs:\n%s", serverLogs.String())
	}
	closeError := packetConnection.Close()
	if closeError != nil {
		t.Fatalf("Hysteria2 sing-box UDP close failed: %v", closeError)
	}
	if !bytes.Equal(buffer[:count], payload) || source.String() != udpAddress.String() {
		t.Fatal("Hysteria2 sing-box UDP response did not match the request")
	}

	_, _, wrongFingerprint, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatalf("generate wrong Hysteria2 fingerprint: %v", err)
	}
	type failureCase struct {
		name        string
		field       string
		value       string
		wantMessage string
	}
	failures := []failureCase{
		{name: "InvalidPassword", field: "password", value: "invalid-hysteria2-password"},
		{name: "InvalidCertificate", field: "fingerprint", value: wrongFingerprint, wantMessage: "certificate"},
	}
	if obfs != "" {
		failures = append(failures, failureCase{name: "InvalidObfs", field: "obfs-password", value: "invalid-hysteria2-obfs"})
	}
	for _, failure := range failures {
		t.Run(failure.name, func(t *testing.T) {
			failedMapping := cloneAnyTLSMapping(mapping)
			failedMapping["name"] = "controlled-hysteria2-sing-box-" + failure.name
			failedMapping[failure.field] = failure.value
			failedProxy, err := adapter.ParseProxy(failedMapping)
			if err != nil {
				t.Fatalf("ParseProxy() failure variant error = %v", err)
			}
			defer failedProxy.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_, err = failedProxy.URLTest(ctx, target.URL, nil)
			cancel()
			if err == nil {
				t.Fatalf("Hysteria2 sing-box %s unexpectedly succeeded", failure.name)
			}
			// QUIC may withhold a peer TLS alert until the handshake context expires.
			// The succeeding control request above and target count below still prove fail-closed isolation.
			if failure.wantMessage != "" &&
				!strings.Contains(strings.ToLower(err.Error()), failure.wantMessage) &&
				!errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("Hysteria2 sing-box failure error = %v, want %q or handshake deadline", err, failure.wantMessage)
			}
			if count := targetRequests.Load(); count != 1 {
				t.Fatalf("Hysteria2 sing-box failed attempt leaked to target; request count = %d", count)
			}
		})
	}
}
