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
	"github.com/TokenPLS/Hako/common/utils"
	"github.com/TokenPLS/Hako/component/ca"
	C "github.com/TokenPLS/Hako/constant"
)

func TestControlledTUICSingBoxReferenceInterop(t *testing.T) {
	referenceBinary := os.Getenv(singBoxReferenceBinaryEnvironment)
	if referenceBinary == "" {
		t.Skip(singBoxReferenceBinaryEnvironment + " is not set")
	}
	verifySingBoxReferenceBinary(t, referenceBinary)

	certificate, privateKey, fingerprint, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatalf("generate sing-box TUIC certificate: %v", err)
	}
	temporaryDirectory := t.TempDir()
	certificatePath := filepath.Join(temporaryDirectory, "server.pem")
	privateKeyPath := filepath.Join(temporaryDirectory, "server.key")
	if err := os.WriteFile(certificatePath, []byte(certificate), 0o600); err != nil {
		t.Fatalf("write sing-box TUIC certificate: %v", err)
	}
	if err := os.WriteFile(privateKeyPath, []byte(privateKey), 0o600); err != nil {
		t.Fatalf("write sing-box TUIC private key: %v", err)
	}
	uuid := utils.NewUUIDV4().String()
	const (
		password   = "controlled-tuic-sing-box-password"
		serverName = "controlled-tuic.example"
	)
	serverPort := reserveControlledUDPPort(t)
	serverConfig, err := json.Marshal(map[string]any{
		"log": map[string]any{"level": "info", "timestamp": false},
		"inbounds": []map[string]any{{
			"type":               "tuic",
			"tag":                "controlled-tuic-in",
			"listen":             "127.0.0.1",
			"listen_port":        serverPort,
			"users":              []map[string]any{{"name": "controlled", "uuid": uuid, "password": password}},
			"congestion_control": "bbr",
			"auth_timeout":       "3s",
			"zero_rtt_handshake": false,
			"heartbeat":          "1s",
			"tls": map[string]any{
				"enabled":          true,
				"server_name":      serverName,
				"alpn":             []string{"h3"},
				"certificate_path": certificatePath,
				"key_path":         privateKeyPath,
			},
		}},
		"outbounds": []map[string]any{{"type": "direct", "tag": "direct"}},
		"route":     map[string]any{"final": "direct"},
	})
	if err != nil {
		t.Fatalf("marshal sing-box TUIC config: %v", err)
	}
	configPath := filepath.Join(temporaryDirectory, "server.json")
	if err := os.WriteFile(configPath, serverConfig, 0o600); err != nil {
		t.Fatalf("write sing-box TUIC config: %v", err)
	}
	serverLogs := startControlledSingBoxReference(t, referenceBinary, configPath)

	var targetRequests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		targetRequests.Add(1)
		if request.Method != http.MethodHead {
			t.Errorf("target method = %s, want HEAD", request.Method)
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()

	newProxy := func(t *testing.T, name, relayMode, credential, certificateFingerprint string) C.Proxy {
		t.Helper()
		proxy, err := adapter.ParseProxy(map[string]any{
			"name":                  name,
			"type":                  "tuic",
			"server":                "127.0.0.1",
			"port":                  serverPort,
			"uuid":                  uuid,
			"password":              credential,
			"udp-relay-mode":        relayMode,
			"congestion-controller": "bbr",
			"sni":                   serverName,
			"fingerprint":           certificateFingerprint,
		})
		if err != nil {
			t.Fatalf("ParseProxy() error = %v", err)
		}
		t.Cleanup(func() { _ = proxy.Close() })
		return proxy
	}

	for _, relayMode := range []string{"native", "quic"} {
		t.Run(relayMode, func(t *testing.T) {
			proxy := newProxy(t, "controlled-tuic-sing-box-"+relayMode, relayMode, password, fingerprint)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			delay, err := proxy.URLTest(ctx, target.URL, nil)
			cancel()
			if err != nil {
				t.Fatalf("TUIC sing-box %s URLTest() error = %v\nsing-box logs:\n%s", relayMode, err, serverLogs.String())
			}
			if delay == 0 {
				t.Fatalf("TUIC sing-box %s URLTest() returned the failure sentinel delay", relayMode)
			}

			udpTarget, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatalf("listen for TUIC UDP echo target: %v", err)
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
				t.Fatalf("TUIC sing-box %s UDP session failed: %v\nsing-box logs:\n%s", relayMode, err, serverLogs.String())
			}
			if err := packetConnection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				_ = packetConnection.Close()
				t.Fatalf("TUIC sing-box %s UDP deadline failed: %v", relayMode, err)
			}
			payload := []byte("hako-controlled-tuic-sing-box-udp-" + relayMode)
			if _, err := packetConnection.WriteTo(payload, udpAddress); err != nil {
				_ = packetConnection.Close()
				t.Fatalf("TUIC sing-box %s UDP write failed: %v", relayMode, err)
			}
			buffer := make([]byte, 64*1024)
			count, source, err := packetConnection.ReadFrom(buffer)
			closeError := packetConnection.Close()
			if err != nil {
				t.Fatalf("TUIC sing-box %s UDP read failed: %v\nsing-box logs:\n%s", relayMode, err, serverLogs.String())
			}
			if closeError != nil {
				t.Fatalf("TUIC sing-box %s UDP close failed: %v", relayMode, closeError)
			}
			if !bytes.Equal(buffer[:count], payload) || source.String() != udpAddress.String() {
				t.Fatalf("TUIC sing-box %s UDP response did not match the request", relayMode)
			}
		})
	}
	if count := targetRequests.Load(); count != 2 {
		t.Fatalf("TUIC sing-box target request count = %d, want 2", count)
	}

	_, _, wrongFingerprint, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatalf("generate wrong TUIC fingerprint: %v", err)
	}
	for _, failure := range []struct {
		name        string
		password    string
		fingerprint string
		wantMessage string
	}{
		{name: "InvalidPassword", password: "invalid-tuic-password", fingerprint: fingerprint},
		{name: "InvalidCertificate", password: password, fingerprint: wrongFingerprint, wantMessage: "certificate"},
	} {
		t.Run(failure.name, func(t *testing.T) {
			failedProxy := newProxy(t, "controlled-tuic-sing-box-"+failure.name, "native", failure.password, failure.fingerprint)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_, err := failedProxy.URLTest(ctx, target.URL, nil)
			cancel()
			if err == nil {
				t.Fatalf("TUIC sing-box %s unexpectedly succeeded", failure.name)
			}
			if failure.wantMessage != "" && !strings.Contains(strings.ToLower(err.Error()), failure.wantMessage) {
				t.Fatalf("TUIC sing-box failure error = %v, want %q", err, failure.wantMessage)
			}
			if count := targetRequests.Load(); count != 2 {
				t.Fatalf("TUIC sing-box failed attempt leaked to target; request count = %d", count)
			}
		})
	}
}
