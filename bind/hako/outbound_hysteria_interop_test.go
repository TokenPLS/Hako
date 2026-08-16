package hako

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/adapter"
	"github.com/TokenPLS/Hako/component/ca"
	C "github.com/TokenPLS/Hako/constant"
)

const (
	singBoxReferenceBinaryEnvironment = "HAKO_SING_BOX_REFERENCE_BIN"
	singBoxReferenceModule            = "github.com/sagernet/sing-box"
	singBoxReferenceVersion           = "v1.13.12"
	singBoxReferenceModuleSum         = "h1:U7znhM2VRq76ZdN4X5eRKdaUxHJNHMGKpo2csKqGTsg="
)

func TestControlledHysteriaTCPInterop(t *testing.T) {
	referenceBinary := os.Getenv(singBoxReferenceBinaryEnvironment)
	if referenceBinary == "" {
		t.Skip(singBoxReferenceBinaryEnvironment + " is not set")
	}
	verifySingBoxReferenceBinary(t, referenceBinary)
	runControlledHysteriaTCPInterop(t, referenceBinary)
}

func verifySingBoxReferenceBinary(t *testing.T, referenceBinary string) {
	t.Helper()
	info, err := buildinfo.ReadFile(referenceBinary)
	if err != nil {
		t.Fatalf("read sing-box reference build info: %v", err)
	}
	if info.Main.Path != singBoxReferenceModule || info.Main.Version != singBoxReferenceVersion || info.Main.Sum != singBoxReferenceModuleSum {
		t.Fatalf(
			"sing-box reference must be %s %s with the pinned module sum; got %s %s %s",
			singBoxReferenceModule,
			singBoxReferenceVersion,
			info.Main.Path,
			info.Main.Version,
			info.Main.Sum,
		)
	}
	versionOutput, err := exec.Command(referenceBinary, "version").CombinedOutput()
	if err != nil {
		t.Fatalf("read sing-box reference version: %v: %s", err, versionOutput)
	}
	wantVersionPrefix := "sing-box version " + strings.TrimPrefix(singBoxReferenceVersion, "v") + "\n"
	if !strings.HasPrefix(string(versionOutput), wantVersionPrefix) {
		t.Fatalf("unexpected sing-box reference version: %s", versionOutput)
	}
}

func runControlledHysteriaTCPInterop(t *testing.T, referenceBinary string) {
	certificate, privateKey, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatalf("generate Hysteria server certificate: %v", err)
	}
	temporaryDirectory := t.TempDir()
	certificatePath := temporaryDirectory + "/server.pem"
	privateKeyPath := temporaryDirectory + "/server.key"
	if err := os.WriteFile(certificatePath, []byte(certificate), 0o600); err != nil {
		t.Fatalf("write Hysteria server certificate: %v", err)
	}
	if err := os.WriteFile(privateKeyPath, []byte(privateKey), 0o600); err != nil {
		t.Fatalf("write Hysteria server private key: %v", err)
	}

	serverPort := reserveControlledUDPPort(t)
	const (
		authentication = "controlled-hysteria-auth"
		obfuscation    = "controlled-hysteria-obfs"
	)
	serverConfig, err := json.Marshal(map[string]any{
		"log": map[string]any{"level": "info", "timestamp": false},
		"inbounds": []map[string]any{{
			"type":        "hysteria",
			"tag":         "controlled-hysteria-in",
			"listen":      "127.0.0.1",
			"listen_port": serverPort,
			"up_mbps":     100,
			"down_mbps":   100,
			"users":       []map[string]any{{"auth_str": authentication}},
			"obfs":        obfuscation,
			"tls": map[string]any{
				"enabled":          true,
				"server_name":      "controlled.hysteria.test",
				"certificate_path": certificatePath,
				"key_path":         privateKeyPath,
			},
		}},
		"outbounds": []map[string]any{{"type": "direct", "tag": "direct"}},
		"route":     map[string]any{"final": "direct"},
	})
	if err != nil {
		t.Fatalf("marshal sing-box Hysteria config: %v", err)
	}
	configPath := temporaryDirectory + "/server.json"
	if err := os.WriteFile(configPath, serverConfig, 0o600); err != nil {
		t.Fatalf("write sing-box Hysteria config: %v", err)
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
	t.Cleanup(target.Close)
	newProxy := func(t *testing.T, name, auth, obfs string) C.Proxy {
		t.Helper()
		proxy, err := adapter.ParseProxy(map[string]any{
			"name":             name,
			"type":             "hysteria",
			"server":           "127.0.0.1",
			"port":             serverPort,
			"protocol":         "udp",
			"up":               "100 Mbps",
			"down":             "100 Mbps",
			"auth-str":         auth,
			"obfs":             obfs,
			"sni":              "controlled.hysteria.test",
			"skip-cert-verify": true,
		})
		if err != nil {
			t.Fatalf("ParseProxy() error = %v", err)
		}
		t.Cleanup(func() { _ = proxy.Close() })
		return proxy
	}
	proxy := newProxy(t, "controlled-hysteria", authentication, obfuscation)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	delay, err := proxy.URLTest(ctx, target.URL, nil)
	cancel()
	if err != nil {
		t.Fatalf("Hysteria URLTest() error = %v\nsing-box logs:\n%s", err, serverLogs.String())
	}
	if delay == 0 {
		t.Fatal("Hysteria URLTest() returned the failure sentinel delay")
	}
	if count := targetRequests.Load(); count != 1 {
		t.Fatalf("target request count = %d, want 1", count)
	}

	udpTarget, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen for Hysteria UDP echo target: %v", err)
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
		t.Fatalf("Hysteria UDP session failed: %v\nsing-box logs:\n%s", err, serverLogs.String())
	}
	if err := packetConnection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		_ = packetConnection.Close()
		t.Fatalf("Hysteria UDP deadline failed: %v", err)
	}
	payload := []byte("hako-controlled-hysteria-sing-box-udp")
	if _, err := packetConnection.WriteTo(payload, udpAddress); err != nil {
		_ = packetConnection.Close()
		t.Fatalf("Hysteria UDP write failed: %v", err)
	}
	buffer := make([]byte, 64*1024)
	count, source, err := packetConnection.ReadFrom(buffer)
	closeError := packetConnection.Close()
	if err != nil {
		t.Fatalf("Hysteria UDP read failed: %v\nsing-box logs:\n%s", err, serverLogs.String())
	}
	if closeError != nil {
		t.Fatalf("Hysteria UDP close failed: %v", closeError)
	}
	if !bytes.Equal(buffer[:count], payload) || source.String() != udpAddress.String() {
		t.Fatal("Hysteria UDP response did not match the request")
	}

	for _, failure := range []struct {
		name string
		auth string
		obfs string
	}{
		{name: "InvalidAuth", auth: "wrong-auth", obfs: obfuscation},
		{name: "InvalidObfs", auth: authentication, obfs: "wrong-obfs"},
	} {
		t.Run(failure.name, func(t *testing.T) {
			failedProxy := newProxy(t, "controlled-hysteria-"+failure.name, failure.auth, failure.obfs)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_, err := failedProxy.URLTest(ctx, target.URL, nil)
			cancel()
			if err == nil {
				t.Fatalf("invalid Hysteria %s unexpectedly succeeded", failure.name)
			}
			if count := targetRequests.Load(); count != 1 {
				t.Fatalf("invalid Hysteria attempt leaked to target; request count = %d", count)
			}
		})
	}
}

func reserveControlledUDPPort(t *testing.T) int {
	t.Helper()
	connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("reserve UDP port: %v", err)
	}
	port := connection.LocalAddr().(*net.UDPAddr).Port
	if err := connection.Close(); err != nil {
		t.Fatalf("release reserved UDP port: %v", err)
	}
	return port
}

type synchronizedReferenceLogs struct {
	sync.Mutex
	buffer bytes.Buffer
}

func (l *synchronizedReferenceLogs) Write(payload []byte) (int, error) {
	l.Lock()
	defer l.Unlock()
	return l.buffer.Write(payload)
}

func (l *synchronizedReferenceLogs) String() string {
	l.Lock()
	defer l.Unlock()
	return l.buffer.String()
}

func startControlledSingBoxReference(t *testing.T, binary, configPath string) *synchronizedReferenceLogs {
	t.Helper()
	logs := new(synchronizedReferenceLogs)
	command := exec.Command(binary, "run", "-c", configPath)
	command.Stdout = logs
	command.Stderr = logs
	if err := command.Start(); err != nil {
		t.Fatalf("start sing-box reference: %v", err)
	}
	processDone := make(chan error, 1)
	go func() { processDone <- command.Wait() }()
	t.Cleanup(func() {
		if command.Process == nil {
			return
		}
		_ = command.Process.Signal(os.Interrupt)
		select {
		case <-processDone:
		case <-time.After(2 * time.Second):
			_ = command.Process.Kill()
			<-processDone
		}
	})

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(logs.String(), "sing-box started") {
			return logs
		}
		select {
		case err := <-processDone:
			t.Fatalf("sing-box reference exited before startup: %v\n%s", err, logs.String())
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("sing-box reference startup timed out\n%s", logs.String())
	return nil
}
