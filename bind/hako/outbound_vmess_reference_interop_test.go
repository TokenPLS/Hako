package hako

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/adapter"
	"github.com/TokenPLS/Hako/common/utils"
	"github.com/TokenPLS/Hako/component/ca"
	C "github.com/TokenPLS/Hako/constant"
)

const (
	v2rayReferenceBinaryEnvironment = "HAKO_V2RAY_REFERENCE_BIN"
	v2rayReferenceModule            = "github.com/v2fly/v2ray-core/v5"
	v2rayReferenceVersion           = "v5.51.2"
	v2rayReferenceModuleSum         = "h1:YRDJlMhlCutNv6sHakrpP1LMY/FZZmexT4FK10QSVYw="
)

func TestControlledVMessV2RayReferenceInterop(t *testing.T) {
	referenceBinary := os.Getenv(v2rayReferenceBinaryEnvironment)
	if referenceBinary == "" {
		t.Skip(v2rayReferenceBinaryEnvironment + " is not set")
	}
	verifyV2RayReferenceBinary(t, referenceBinary)

	for _, variant := range []struct {
		name      string
		network   string
		transport string
		path      string
		host      string
		useTLS    bool
	}{
		{name: "HTTPHeader", network: "http", transport: "tcp", path: "/controlled-vmess-http", host: "controlled-http.example"},
		{name: "HTTP2TLS", network: "h2", transport: "h2", path: "/controlled-vmess-h2", host: "controlled-h2.example", useTLS: true},
	} {
		t.Run(variant.name, func(t *testing.T) {
			runControlledVMessV2RayReferenceVariant(t, referenceBinary, variant.network, variant.transport, variant.path, variant.host, variant.useTLS)
		})
	}
}

func verifyV2RayReferenceBinary(t *testing.T, binary string) {
	t.Helper()
	info, err := buildinfo.ReadFile(binary)
	if err != nil {
		t.Fatalf("read V2Ray reference build info: %v", err)
	}
	verified := false
	modules := append([]*debug.Module{&info.Main}, info.Deps...)
	for _, module := range modules {
		if module != nil && module.Path == v2rayReferenceModule && module.Version == v2rayReferenceVersion && module.Sum == v2rayReferenceModuleSum {
			verified = true
			break
		}
	}
	if !verified {
		t.Fatalf("V2Ray reference must contain %s %s with the pinned module sum", v2rayReferenceModule, v2rayReferenceVersion)
	}
	output, err := exec.Command(binary, "version").CombinedOutput()
	if err != nil {
		t.Fatalf("V2Ray reference version command failed: %v", err)
	}
	if !strings.HasPrefix(string(output), "V2Ray 5.51.2 ") {
		t.Fatalf("V2Ray reference reported an unexpected version")
	}
}

func runControlledVMessV2RayReferenceVariant(t *testing.T, referenceBinary, network, transport, path, host string, useTLS bool) {
	t.Helper()
	uuid := utils.NewUUIDV4().String()
	serverCertificate, serverPrivateKey, serverFingerprint, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatalf("generate V2Ray reference certificate: %v", err)
	}
	certificateDirectory := t.TempDir()
	certificatePath := filepath.Join(certificateDirectory, "server.crt")
	privateKeyPath := filepath.Join(certificateDirectory, "server.key")
	if err := os.WriteFile(certificatePath, []byte(serverCertificate), 0o600); err != nil {
		t.Fatalf("write V2Ray reference certificate: %v", err)
	}
	if err := os.WriteFile(privateKeyPath, []byte(serverPrivateKey), 0o600); err != nil {
		t.Fatalf("write V2Ray reference private key: %v", err)
	}
	port := reserveControlledTCPPort(t)
	config := controlledV2RayVMessServerConfig(t, port, uuid, transport, path, host, useTLS, certificatePath, privateKeyPath)
	logs := startControlledV2RayReference(t, referenceBinary, config, net.JoinHostPort("127.0.0.1", fmt.Sprint(port)))

	proxyMapping := map[string]any{
		"name":    "controlled-vmess-v2ray-" + network,
		"type":    "vmess",
		"server":  "127.0.0.1",
		"port":    port,
		"uuid":    uuid,
		"alterId": 0,
		"cipher":  "auto",
		"udp":     true,
		"network": network,
	}
	switch network {
	case "http":
		proxyMapping["http-opts"] = map[string]any{
			"method": "GET",
			"path":   []string{path},
			"headers": map[string][]string{
				"Host":       {host},
				"Connection": {"keep-alive"},
			},
		}
	case "h2":
		proxyMapping["tls"] = true
		proxyMapping["servername"] = host
		proxyMapping["fingerprint"] = serverFingerprint
		proxyMapping["h2-opts"] = map[string]any{"host": []string{host}, "path": path}
	default:
		t.Fatalf("unsupported V2Ray reference variant %q", network)
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
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	delay, err := proxy.URLTest(ctx, target.URL, nil)
	cancel()
	if err != nil {
		t.Fatalf("VMess %s V2Ray URLTest() error = %v\nV2Ray logs:\n%s", network, err, logs.String())
	}
	if delay == 0 {
		t.Fatalf("VMess %s V2Ray URLTest() returned the failure sentinel delay", network)
	}
	select {
	case <-targetReached:
	case <-time.After(time.Second):
		t.Fatalf("VMess %s request did not reach the target", network)
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
	ctx, cancel = context.WithTimeout(context.Background(), 8*time.Second)
	packetConnection, err := proxy.ListenPacketContext(ctx, metadata)
	cancel()
	if err != nil {
		t.Fatalf("VMess %s V2Ray UDP session failed: %v\nV2Ray logs:\n%s", network, err, logs.String())
	}
	defer packetConnection.Close()
	if err := packetConnection.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
		t.Fatalf("VMess %s V2Ray UDP deadline failed: %v", network, err)
	}
	payload := []byte("hako-controlled-vmess-v2ray-udp-" + network)
	if _, err := packetConnection.WriteTo(payload, udpAddress); err != nil {
		t.Fatalf("VMess %s V2Ray UDP write failed: %v", network, err)
	}
	buffer := make([]byte, 64*1024)
	count, source, err := packetConnection.ReadFrom(buffer)
	if err != nil {
		t.Fatalf("VMess %s V2Ray UDP read failed: %v\nV2Ray logs:\n%s", network, err, logs.String())
	}
	if !bytes.Equal(buffer[:count], payload) || source.String() != udpAddress.String() {
		t.Fatalf("VMess %s V2Ray UDP response did not match the request", network)
	}

	failedMapping := cloneAnyTLSMapping(proxyMapping)
	failedMapping["name"] = "controlled-vmess-v2ray-invalid-uuid-" + network
	failedMapping["uuid"] = utils.NewUUIDV4().String()
	failedProxy, err := adapter.ParseProxy(failedMapping)
	if err != nil {
		t.Fatalf("ParseProxy() invalid UUID error = %v", err)
	}
	defer failedProxy.Close()
	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	_, err = failedProxy.URLTest(ctx, target.URL, nil)
	cancel()
	if err == nil {
		t.Fatalf("invalid VMess %s UUID unexpectedly succeeded", network)
	}
	select {
	case <-targetReached:
		t.Fatalf("invalid VMess %s UUID leaked to the target", network)
	case <-time.After(50 * time.Millisecond):
	}
}

func controlledV2RayVMessServerConfig(t *testing.T, port int, uuid, transport, path, host string, useTLS bool, certificatePath, privateKeyPath string) []byte {
	t.Helper()
	streamSettings := map[string]any{"transport": transport}
	switch transport {
	case "tcp":
		streamSettings["transportSettings"] = map[string]any{
			"headerSettings": map[string]any{
				"@type": "types.v2fly.org/v2ray.core.transport.internet.headers.http.Config",
				"request": map[string]any{
					"method": map[string]any{"value": "GET"},
					"uri":    []string{path},
					"header": []map[string]any{
						{"name": "Host", "value": []string{host}},
						{"name": "Connection", "value": []string{"keep-alive"}},
					},
				},
				"response": map[string]any{
					"status": map[string]any{"code": "200", "reason": "OK"},
					"header": []map[string]any{{"name": "Connection", "value": []string{"keep-alive"}}},
				},
			},
		}
	case "h2":
		streamSettings["transportSettings"] = map[string]any{"host": []string{host}, "path": path}
	default:
		t.Fatalf("unsupported V2Ray reference transport %q", transport)
	}
	if useTLS {
		streamSettings["security"] = "tls"
		streamSettings["securitySettings"] = map[string]any{
			"certificate": []map[string]any{{
				"usage":           "ENCIPHERMENT",
				"certificateFile": certificatePath,
				"keyFile":         privateKeyPath,
			}},
		}
	}
	config := map[string]any{
		"log": map[string]any{"error": map[string]any{"type": "Console", "level": "Warning"}},
		"inbounds": []map[string]any{{
			"protocol":       "vmess",
			"listen":         "127.0.0.1",
			"port":           port,
			"settings":       map[string]any{"users": []string{uuid}},
			"streamSettings": streamSettings,
		}},
		"outbounds": []map[string]any{{"protocol": "freedom", "tag": "direct"}},
	}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("marshal V2Ray reference config: %v", err)
	}
	return data
}

func startControlledV2RayReference(t *testing.T, binary string, config []byte, address string) *synchronizedReferenceLogs {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	command := exec.CommandContext(ctx, binary, "run", "-format=jsonv5")
	logs := &synchronizedReferenceLogs{}
	command.Stdin = bytes.NewReader(config)
	command.Stdout = logs
	command.Stderr = logs
	if err := command.Start(); err != nil {
		cancel()
		t.Fatalf("start V2Ray reference: %v", err)
	}
	done := make(chan struct{})
	var waitError error
	go func() {
		waitError = command.Wait()
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = command.Process.Kill()
			<-done
		}
	})

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return logs
		}
		select {
		case <-done:
			t.Fatalf("V2Ray reference exited before listening: %v\n%s", waitError, logs.String())
		default:
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("V2Ray reference did not listen on time\n%s", logs.String())
	return nil
}
