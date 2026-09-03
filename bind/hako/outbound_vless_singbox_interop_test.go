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

func TestControlledVLESSSingBoxReferenceInterop(t *testing.T) {
	referenceBinary := os.Getenv(singBoxReferenceBinaryEnvironment)
	if referenceBinary == "" {
		t.Skip(singBoxReferenceBinaryEnvironment + " is not set")
	}
	verifySingBoxReferenceBinary(t, referenceBinary)

	certificate, privateKey, fingerprint, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatalf("generate sing-box VLESS certificate: %v", err)
	}
	temporaryDirectory := t.TempDir()
	certificatePath := filepath.Join(temporaryDirectory, "server.pem")
	privateKeyPath := filepath.Join(temporaryDirectory, "server.key")
	if err := os.WriteFile(certificatePath, []byte(certificate), 0o600); err != nil {
		t.Fatalf("write sing-box VLESS certificate: %v", err)
	}
	if err := os.WriteFile(privateKeyPath, []byte(privateKey), 0o600); err != nil {
		t.Fatalf("write sing-box VLESS private key: %v", err)
	}
	uuid := utils.NewUUIDV4().String()
	const serverName = "controlled-vless.example"
	serverPort := reserveControlledTCPPort(t)
	serverConfig, err := json.Marshal(map[string]any{
		"log": map[string]any{"level": "info", "timestamp": false},
		"inbounds": []map[string]any{{
			"type":        "vless",
			"tag":         "controlled-vless-in",
			"listen":      "127.0.0.1",
			"listen_port": serverPort,
			"users":       []map[string]any{{"name": "controlled", "uuid": uuid}},
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
		t.Fatalf("marshal sing-box VLESS config: %v", err)
	}
	configPath := filepath.Join(temporaryDirectory, "server.json")
	if err := os.WriteFile(configPath, serverConfig, 0o600); err != nil {
		t.Fatalf("write sing-box VLESS config: %v", err)
	}
	serverLogs := startControlledSingBoxReference(t, referenceBinary, configPath)

	mapping := map[string]any{
		"name":        "controlled-vless-sing-box",
		"type":        "vless",
		"server":      "127.0.0.1",
		"port":        serverPort,
		"uuid":        uuid,
		"tls":         true,
		"udp":         true,
		"servername":  serverName,
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
		t.Fatalf("VLESS sing-box URLTest() error = %v\nsing-box logs:\n%s", err, serverLogs.String())
	}
	if delay == 0 {
		t.Fatal("VLESS sing-box URLTest() returned the failure sentinel delay")
	}
	if count := targetRequests.Load(); count != 1 {
		t.Fatalf("VLESS sing-box target request count = %d, want 1", count)
	}

	udpTarget, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen for VLESS UDP echo target: %v", err)
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
		t.Fatalf("VLESS sing-box UDP session failed: %v\nsing-box logs:\n%s", err, serverLogs.String())
	}
	if err := packetConnection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		_ = packetConnection.Close()
		t.Fatalf("VLESS sing-box UDP deadline failed: %v", err)
	}
	payload := []byte("hako-controlled-vless-sing-box-udp")
	if _, err := packetConnection.WriteTo(payload, udpAddress); err != nil {
		_ = packetConnection.Close()
		t.Fatalf("VLESS sing-box UDP write failed: %v", err)
	}
	buffer := make([]byte, 64*1024)
	count, source, err := packetConnection.ReadFrom(buffer)
	closeError := packetConnection.Close()
	if err != nil {
		t.Fatalf("VLESS sing-box UDP read failed: %v\nsing-box logs:\n%s", err, serverLogs.String())
	}
	if closeError != nil {
		t.Fatalf("VLESS sing-box UDP close failed: %v", closeError)
	}
	if !bytes.Equal(buffer[:count], payload) || source.String() != udpAddress.String() {
		t.Fatal("VLESS sing-box UDP response did not match the request")
	}

	_, _, wrongFingerprint, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatalf("generate wrong VLESS fingerprint: %v", err)
	}
	for _, failure := range []struct {
		name        string
		uuid        string
		fingerprint string
		wantMessage string
	}{
		{name: "InvalidUUID", uuid: utils.NewUUIDV4().String(), fingerprint: fingerprint},
		{name: "InvalidCertificate", uuid: uuid, fingerprint: wrongFingerprint, wantMessage: "certificate"},
	} {
		t.Run(failure.name, func(t *testing.T) {
			failedMapping := cloneAnyTLSMapping(mapping)
			failedMapping["name"] = "controlled-vless-sing-box-" + failure.name
			failedMapping["uuid"] = failure.uuid
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
				t.Fatalf("VLESS sing-box %s unexpectedly succeeded", failure.name)
			}
			if failure.wantMessage != "" && !strings.Contains(strings.ToLower(err.Error()), failure.wantMessage) {
				t.Fatalf("VLESS sing-box failure error = %v, want %q", err, failure.wantMessage)
			}
			if count := targetRequests.Load(); count != 1 {
				t.Fatalf("VLESS sing-box failed attempt leaked to target; request count = %d", count)
			}
		})
	}
}
