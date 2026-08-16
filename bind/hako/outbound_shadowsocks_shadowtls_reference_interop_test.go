package hako

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/adapter"
	"github.com/TokenPLS/Hako/component/ca"
	C "github.com/TokenPLS/Hako/constant"
)

func TestControlledShadowsocksShadowTLSSingBoxReferenceInterop(t *testing.T) {
	referenceBinary := os.Getenv(singBoxReferenceBinaryEnvironment)
	if referenceBinary == "" {
		t.Skip(singBoxReferenceBinaryEnvironment + " is not set")
	}
	verifySingBoxReferenceBinary(t, referenceBinary)

	for _, version := range []int{1, 2, 3} {
		t.Run("Version"+strconv.Itoa(version), func(t *testing.T) {
			runControlledShadowsocksShadowTLSSingBoxReferenceVariant(t, referenceBinary, version)
		})
	}
}

func runControlledShadowsocksShadowTLSSingBoxReferenceVariant(t *testing.T, binary string, version int) {
	t.Helper()
	camouflageAddress, camouflageFingerprint, camouflageConnections := startControlledShadowTLSCamouflage(t)
	camouflageHost, camouflagePortText, err := net.SplitHostPort(camouflageAddress)
	if err != nil {
		t.Fatalf("parse ShadowTLS camouflage address: %v", err)
	}
	camouflagePort, err := strconv.Atoi(camouflagePortText)
	if err != nil {
		t.Fatalf("parse ShadowTLS camouflage port: %v", err)
	}
	serverPort := reserveControlledTCPPort(t)
	shadowsocksPort := reserveControlledTCPAndUDPPort(t)
	const (
		serverName        = "controlled-shadowtls.example"
		shadowsocksCipher = "aes-128-gcm"
		shadowsocksSecret = "controlled-shadowtls-shadowsocks-secret"
		shadowTLSSecret   = "controlled-shadowtls-secret"
	)
	shadowTLSInbound := map[string]any{
		"type":        "shadowtls",
		"tag":         "controlled-shadowtls-in",
		"listen":      "127.0.0.1",
		"listen_port": serverPort,
		"detour":      "controlled-shadowsocks-in",
		"version":     version,
		"handshake": map[string]any{
			"server":      camouflageHost,
			"server_port": camouflagePort,
		},
	}
	switch version {
	case 1:
	case 2:
		shadowTLSInbound["password"] = shadowTLSSecret
	case 3:
		shadowTLSInbound["users"] = []map[string]any{{"name": "controlled", "password": shadowTLSSecret}}
	default:
		t.Fatalf("unsupported ShadowTLS version %d", version)
	}
	serverConfig, err := json.Marshal(map[string]any{
		"log": map[string]any{"level": "info", "timestamp": false},
		"inbounds": []map[string]any{
			shadowTLSInbound,
			{
				"type":        "shadowsocks",
				"tag":         "controlled-shadowsocks-in",
				"listen":      "127.0.0.1",
				"listen_port": shadowsocksPort,
				"method":      shadowsocksCipher,
				"password":    shadowsocksSecret,
			},
		},
		"outbounds": []map[string]any{{"type": "direct", "tag": "direct"}},
		"route":     map[string]any{"final": "direct"},
	})
	if err != nil {
		t.Fatalf("marshal sing-box ShadowTLS config: %v", err)
	}
	configPath := filepath.Join(t.TempDir(), "server.json")
	if err := os.WriteFile(configPath, serverConfig, 0o600); err != nil {
		t.Fatalf("write sing-box ShadowTLS config: %v", err)
	}
	serverLogs := startControlledSingBoxReference(t, binary, configPath)

	newProxy := func(t *testing.T, name, shadowsocksPassword, shadowTLSPassword string) C.Proxy {
		t.Helper()
		pluginOptions := map[string]any{
			"host":        serverName,
			"fingerprint": camouflageFingerprint,
			"version":     version,
			"alpn":        []string{"http/1.1"},
		}
		if version >= 2 {
			pluginOptions["password"] = shadowTLSPassword
		}
		proxy, err := adapter.ParseProxy(map[string]any{
			"name":               name,
			"type":               "ss",
			"server":             "127.0.0.1",
			"port":               serverPort,
			"password":           shadowsocksPassword,
			"cipher":             shadowsocksCipher,
			"plugin":             "shadow-tls",
			"plugin-opts":        pluginOptions,
			"client-fingerprint": "chrome",
		})
		if err != nil {
			t.Fatalf("ParseProxy() error = %v", err)
		}
		t.Cleanup(func() { _ = proxy.Close() })
		return proxy
	}

	targetRequests := atomic.Int32{}
	target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		targetRequests.Add(1)
		if request.Method != http.MethodHead {
			t.Errorf("target method = %s, want HEAD", request.Method)
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	proxy := newProxy(t, "controlled-shadowtls", shadowsocksSecret, shadowTLSSecret)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	delay, err := proxy.URLTest(ctx, target.URL, nil)
	cancel()
	if err != nil {
		t.Fatalf("ShadowTLS v%d sing-box URLTest() error = %v\nsing-box logs:\n%s", version, err, serverLogs.String())
	}
	if delay == 0 {
		t.Fatalf("ShadowTLS v%d sing-box URLTest() returned the failure sentinel delay", version)
	}
	if count := targetRequests.Load(); count != 1 {
		t.Fatalf("ShadowTLS v%d target request count = %d, want 1", version, count)
	}
	if count := camouflageConnections.Load(); count == 0 {
		t.Fatalf("ShadowTLS v%d never connected to the controlled TLS camouflage server", version)
	}

	invalidShadowsocksPassword := shadowsocksSecret
	invalidShadowTLSPassword := shadowTLSSecret
	if version == 1 {
		invalidShadowsocksPassword = "invalid-shadowtls-shadowsocks-secret"
	} else {
		invalidShadowTLSPassword = "invalid-shadowtls-secret"
	}
	failedProxy := newProxy(t, "controlled-shadowtls-invalid", invalidShadowsocksPassword, invalidShadowTLSPassword)
	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	_, err = failedProxy.URLTest(ctx, target.URL, nil)
	cancel()
	if err == nil {
		t.Fatalf("invalid ShadowTLS v%d credential unexpectedly succeeded", version)
	}
	if count := targetRequests.Load(); count != 1 {
		t.Fatalf("invalid ShadowTLS v%d credential leaked to target; request count = %d", version, count)
	}
}

func startControlledShadowTLSCamouflage(t *testing.T) (string, string, *atomic.Int32) {
	t.Helper()
	certificatePEM, privateKeyPEM, fingerprint, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatalf("generate ShadowTLS camouflage certificate: %v", err)
	}
	certificate, err := tls.X509KeyPair([]byte(certificatePEM), []byte(privateKeyPEM))
	if err != nil {
		t.Fatalf("parse ShadowTLS camouflage certificate: %v", err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for ShadowTLS camouflage: %v", err)
	}
	tlsListener := tls.NewListener(listener, &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	})
	connections := new(atomic.Int32)
	server := &http.Server{
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.WriteHeader(http.StatusNoContent)
		}),
		ConnState: func(_ net.Conn, state http.ConnState) {
			if state == http.StateNew {
				connections.Add(1)
			}
		},
		ErrorLog: log.New(io.Discard, "", 0),
	}
	go func() { _ = server.Serve(tlsListener) }()
	t.Cleanup(func() { _ = server.Close() })
	return listener.Addr().String(), fingerprint, connections
}
