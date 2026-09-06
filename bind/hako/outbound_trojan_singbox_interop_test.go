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

func TestControlledTrojanSingBoxReferenceInterop(t *testing.T) {
	referenceBinary := os.Getenv(singBoxReferenceBinaryEnvironment)
	if referenceBinary == "" {
		t.Skip(singBoxReferenceBinaryEnvironment + " is not set")
	}
	verifySingBoxReferenceBinary(t, referenceBinary)

	certificate, privateKey, fingerprint, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatalf("generate sing-box Trojan certificate: %v", err)
	}
	temporaryDirectory := t.TempDir()
	certificatePath := filepath.Join(temporaryDirectory, "server.pem")
	privateKeyPath := filepath.Join(temporaryDirectory, "server.key")
	if err := os.WriteFile(certificatePath, []byte(certificate), 0o600); err != nil {
		t.Fatalf("write sing-box Trojan certificate: %v", err)
	}
	if err := os.WriteFile(privateKeyPath, []byte(privateKey), 0o600); err != nil {
		t.Fatalf("write sing-box Trojan private key: %v", err)
	}
	const (
		password   = "controlled-trojan-sing-box-password"
		serverName = "controlled-trojan.example"
	)
	serverPort := reserveControlledTCPPort(t)
	serverConfig, err := json.Marshal(map[string]any{
		"log": map[string]any{"level": "info", "timestamp": false},
		"inbounds": []map[string]any{{
			"type":        "trojan",
			"tag":         "controlled-trojan-in",
			"listen":      "127.0.0.1",
			"listen_port": serverPort,
			"users":       []map[string]any{{"name": "controlled", "password": password}},
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
		t.Fatalf("marshal sing-box Trojan config: %v", err)
	}
	configPath := filepath.Join(temporaryDirectory, "server.json")
	if err := os.WriteFile(configPath, serverConfig, 0o600); err != nil {
		t.Fatalf("write sing-box Trojan config: %v", err)
	}
	serverLogs := startControlledSingBoxReference(t, referenceBinary, configPath)

	mapping := map[string]any{
		"name":        "controlled-trojan-sing-box",
		"type":        "trojan",
		"server":      "127.0.0.1",
		"port":        serverPort,
		"password":    password,
		"udp":         true,
		"sni":         serverName,
		"fingerprint": fingerprint,
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
		t.Fatalf("Trojan sing-box URLTest() error = %v\nsing-box logs:\n%s", err, serverLogs.String())
	}
	if delay == 0 {
		t.Fatal("Trojan sing-box URLTest() returned the failure sentinel delay")
	}
	if count := targetRequests.Load(); count != 1 {
		t.Fatalf("Trojan sing-box target request count = %d, want 1", count)
	}

	udpTarget, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen for Trojan UDP echo target: %v", err)
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
		t.Fatalf("Trojan sing-box UDP session failed: %v\nsing-box logs:\n%s", err, serverLogs.String())
	}
	if err := packetConnection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		_ = packetConnection.Close()
		t.Fatalf("Trojan sing-box UDP deadline failed: %v", err)
	}
	payload := []byte("hako-controlled-trojan-sing-box-udp")
	if _, err := packetConnection.WriteTo(payload, udpAddress); err != nil {
		_ = packetConnection.Close()
		t.Fatalf("Trojan sing-box UDP write failed: %v", err)
	}
	buffer := make([]byte, 64*1024)
	count, source, err := packetConnection.ReadFrom(buffer)
	closeError := packetConnection.Close()
	if err != nil {
		t.Fatalf("Trojan sing-box UDP read failed: %v\nsing-box logs:\n%s", err, serverLogs.String())
	}
	if closeError != nil {
		t.Fatalf("Trojan sing-box UDP close failed: %v", closeError)
	}
	if !bytes.Equal(buffer[:count], payload) || source.String() != udpAddress.String() {
		t.Fatal("Trojan sing-box UDP response did not match the request")
	}

	_, _, wrongFingerprint, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatalf("generate wrong Trojan fingerprint: %v", err)
	}
	for _, failure := range []struct {
		name        string
		password    string
		fingerprint string
		wantMessage string
	}{
		{name: "InvalidPassword", password: "invalid-trojan-password", fingerprint: fingerprint},
		{name: "InvalidCertificate", password: password, fingerprint: wrongFingerprint, wantMessage: "certificate"},
	} {
		t.Run(failure.name, func(t *testing.T) {
			failedMapping := cloneAnyTLSMapping(mapping)
			failedMapping["name"] = "controlled-trojan-sing-box-" + failure.name
			failedMapping["password"] = failure.password
			failedMapping["fingerprint"] = failure.fingerprint
			failedProxy, err := adapter.ParseProxy(failedMapping)
			if err != nil {
				t.Fatalf("ParseProxy() failure variant error = %v", err)
			}
			defer failedProxy.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_, err = failedProxy.URLTest(ctx, target.URL, nil)
			cancel()
			if err == nil {
				t.Fatalf("Trojan sing-box %s unexpectedly succeeded", failure.name)
			}
			if failure.wantMessage != "" && !strings.Contains(strings.ToLower(err.Error()), failure.wantMessage) {
				t.Fatalf("Trojan sing-box failure error = %v, want %q", err, failure.wantMessage)
			}
			if count := targetRequests.Load(); count != 1 {
				t.Fatalf("Trojan sing-box failed attempt leaked to target; request count = %d", count)
			}
		})
	}
}
