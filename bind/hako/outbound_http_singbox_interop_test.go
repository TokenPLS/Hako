package hako

import (
	"context"
	"encoding/json"
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

func TestControlledHTTPConnectSingBoxReferenceInterop(t *testing.T) {
	referenceBinary := os.Getenv(singBoxReferenceBinaryEnvironment)
	if referenceBinary == "" {
		t.Skip(singBoxReferenceBinaryEnvironment + " is not set")
	}
	verifySingBoxReferenceBinary(t, referenceBinary)

	const (
		username = "controlled-http-user"
		password = "controlled-http-password"
	)
	serverPort := reserveControlledTCPPort(t)
	temporaryDirectory := t.TempDir()
	serverConfig, err := json.Marshal(map[string]any{
		"log": map[string]any{"level": "info", "timestamp": false},
		"inbounds": []map[string]any{{
			"type":        "http",
			"tag":         "controlled-http-in",
			"listen":      "127.0.0.1",
			"listen_port": serverPort,
			"users":       []map[string]any{{"username": username, "password": password}},
		}},
		"outbounds": []map[string]any{{"type": "direct", "tag": "direct"}},
		"route":     map[string]any{"final": "direct"},
	})
	if err != nil {
		t.Fatalf("marshal sing-box HTTP config: %v", err)
	}
	configPath := filepath.Join(temporaryDirectory, "server.json")
	if err := os.WriteFile(configPath, serverConfig, 0o600); err != nil {
		t.Fatalf("write sing-box HTTP config: %v", err)
	}
	serverLogs := startControlledSingBoxReference(t, referenceBinary, configPath)

	newProxy := func(t *testing.T, name, credential string) C.Proxy {
		t.Helper()
		proxy, err := adapter.ParseProxy(map[string]any{
			"name":     name,
			"type":     "http",
			"server":   "127.0.0.1",
			"port":     serverPort,
			"username": username,
			"password": credential,
		})
		if err != nil {
			t.Fatalf("ParseProxy() error = %v", err)
		}
		t.Cleanup(func() { _ = proxy.Close() })
		return proxy
	}

	var targetRequests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		targetRequests.Add(1)
		if request.Method != http.MethodHead {
			t.Errorf("target method = %s, want HEAD", request.Method)
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()

	proxy := newProxy(t, "controlled-http-sing-box", password)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	delay, err := proxy.URLTest(ctx, target.URL, nil)
	cancel()
	if err != nil {
		t.Fatalf("HTTP CONNECT sing-box URLTest() error = %v\nsing-box logs:\n%s", err, serverLogs.String())
	}
	if delay == 0 {
		t.Fatal("HTTP CONNECT sing-box URLTest() returned the failure sentinel delay")
	}
	if count := targetRequests.Load(); count != 1 {
		t.Fatalf("HTTP CONNECT sing-box target request count = %d, want 1", count)
	}

	failedProxy := newProxy(t, "controlled-http-sing-box-invalid-password", "invalid-http-password")
	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	_, err = failedProxy.URLTest(ctx, target.URL, nil)
	cancel()
	if err == nil {
		t.Fatal("HTTP CONNECT sing-box invalid password unexpectedly succeeded")
	}
	if count := targetRequests.Load(); count != 1 {
		t.Fatalf("HTTP CONNECT sing-box failed attempt leaked to target; request count = %d", count)
	}
}
