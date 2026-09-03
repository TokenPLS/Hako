package hako

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/component/ca"
	"github.com/TokenPLS/Hako/tunnel"
	"gopkg.in/yaml.v3"
)

func TestControlledDialerProxyChainInterop(t *testing.T) {
	pinUnifiedDelayOff(t)
	serverCertificate, serverPrivateKey, serverFingerprint, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatalf("generate gost relay certificate: %v", err)
	}
	clientCertificate, clientPrivateKey, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatalf("generate gost relay client certificate: %v", err)
	}
	const (
		gostUsername = "controlled-chain-gost-user"
		gostPassword = "controlled-chain-gost-password"
		httpUsername = "controlled-chain-http-user"
		httpPassword = "controlled-chain-http-password"
	)
	var acceptedRelayRequests atomic.Int32
	gostAddress := startControlledGostRelayServer(
		t,
		serverCertificate,
		serverPrivateKey,
		clientCertificate,
		gostUsername,
		gostPassword,
		&acceptedRelayRequests,
		nil,
	)
	gostHost, gostPortText, err := net.SplitHostPort(gostAddress)
	if err != nil {
		t.Fatalf("split gost relay address: %v", err)
	}
	gostPort, err := strconv.Atoi(gostPortText)
	if err != nil {
		t.Fatalf("parse gost relay port: %v", err)
	}
	httpProxy, httpPort := startHTTPConnectServer(t, httpUsername, httpPassword)
	t.Cleanup(func() { _ = httpProxy.Close() })

	var targetRequests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		targetRequests.Add(1)
		if request.Method != http.MethodHead {
			t.Errorf("target method = %s, want HEAD", request.Method)
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(target.Close)

	configYAML, err := yaml.Marshal(map[string]any{
		"mode":      "rule",
		"log-level": "info",
		// This fixture counts exactly one HEAD per probe; the applied config
		// must say so itself, or the factory default flips the global on.
		"unified-delay": false,
		"dns": map[string]any{
			"enable":     true,
			"nameserver": []string{"8.8.8.8"},
		},
		"proxies": []map[string]any{
			{
				"name":        "controlled-chain-gost",
				"type":        "gost-relay",
				"server":      gostHost,
				"port":        gostPort,
				"tls":         true,
				"username":    gostUsername,
				"password":    gostPassword,
				"fingerprint": serverFingerprint,
				"certificate": clientCertificate,
				"private-key": clientPrivateKey,
			},
			{
				"name":        "controlled-chain-gost-invalid",
				"type":        "gost-relay",
				"server":      gostHost,
				"port":        gostPort,
				"tls":         true,
				"username":    gostUsername,
				"password":    "wrong-password",
				"fingerprint": serverFingerprint,
				"certificate": clientCertificate,
				"private-key": clientPrivateKey,
			},
			{
				"name":         "controlled-chain-http",
				"type":         "http",
				"server":       "127.0.0.1",
				"port":         httpPort,
				"username":     httpUsername,
				"password":     httpPassword,
				"dialer-proxy": "controlled-chain-gost",
			},
			{
				"name":         "controlled-chain-http-invalid",
				"type":         "http",
				"server":       "127.0.0.1",
				"port":         httpPort,
				"username":     httpUsername,
				"password":     httpPassword,
				"dialer-proxy": "controlled-chain-gost-invalid",
			},
		},
		"rules": []string{"MATCH,DIRECT"},
	})
	if err != nil {
		t.Fatalf("marshal chain config: %v", err)
	}
	if err := Setup(testOptions(t)); err != nil {
		t.Fatal(err)
	}
	service, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	if err := service.Start(string(configYAML)); err != nil {
		t.Fatalf("start chained core: %v", err)
	}

	proxy := tunnel.Proxies()["controlled-chain-http"]
	if proxy == nil {
		t.Fatal("chained HTTP proxy is missing")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	delay, err := proxy.URLTest(ctx, target.URL, nil)
	cancel()
	if err != nil {
		t.Fatalf("chained URLTest() error = %v", err)
	}
	if delay == 0 {
		t.Fatal("chained URLTest() returned the failure sentinel delay")
	}
	if count := acceptedRelayRequests.Load(); count != 1 {
		t.Fatalf("accepted first-hop relay requests = %d, want 1", count)
	}
	if count := targetRequests.Load(); count != 1 {
		t.Fatalf("target requests = %d, want 1", count)
	}

	invalidProxy := tunnel.Proxies()["controlled-chain-http-invalid"]
	if invalidProxy == nil {
		t.Fatal("invalid chained HTTP proxy is missing")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
	_, err = invalidProxy.URLTest(ctx, target.URL, nil)
	cancel()
	if err == nil {
		t.Fatal("invalid first-hop credentials unexpectedly reached the target")
	}
	if count := acceptedRelayRequests.Load(); count != 1 {
		t.Fatalf("invalid first hop was accepted; relay request count = %d", count)
	}
	if count := targetRequests.Load(); count != 1 {
		t.Fatalf("invalid chain leaked to target; request count = %d", count)
	}
}
