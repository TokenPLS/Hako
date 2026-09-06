package hako

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/adapter"
	C "github.com/TokenPLS/Hako/constant"
)

const (
	ssrReferenceEnvironment = "HAKO_SSR_REFERENCE_BIN"
	ssrReferenceRepository  = "https://github.com/ssrlive/shadowsocksr.git"
	ssrReferenceCommit      = "51c8ae4d7805b19542e39d42092ce4032752f837"
	ssrReferenceVersion     = "3.1.2"
	ssrReferenceMSSVariable = "HAKO_SSR_REFERENCE_CANONICAL_MSS"
	ssrReferenceMSS         = "1460"
)

type synchronizedSSRLog struct {
	mutex sync.Mutex
	data  bytes.Buffer
}

func (l *synchronizedSSRLog) Write(data []byte) (int, error) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	return l.data.Write(data)
}

func (l *synchronizedSSRLog) category() string {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	content := l.data.String()
	for _, candidate := range []struct {
		fragment string
		category string
	}{
		{"data uncorrect auth", "auth-header"},
		{"checksum error", "checksum"},
		{"wrong timestamp", "timestamp"},
		{"auth fail", "anti-replay"},
		{"wrong crc", "frame-mac"},
		{"over size", "frame-length"},
		{"connect error", "target-connect"},
	} {
		if strings.Contains(content, candidate.fragment) {
			return candidate.category
		}
	}
	if start := strings.LastIndex(content, "TCP MSS = "); start >= 0 {
		value := content[start+len("TCP MSS = "):]
		if end := strings.IndexByte(value, '\n'); end >= 0 {
			value = value[:end]
		}
		if mss, err := strconv.Atoi(strings.TrimSpace(value)); err == nil && mss > 8192 {
			return "loopback-tcp-mss"
		}
	}
	return "none"
}

func TestSSRReferenceInterop(t *testing.T) {
	reference := os.Getenv(ssrReferenceEnvironment)
	if reference == "" {
		t.Skip(ssrReferenceEnvironment + " is not set")
	}
	verifySSRReference(t, reference)

	tcpURL, udpAddress, tcpRequests, udpRequests := startSSRReferenceTargets(t)
	password := randomLabSecret(t)
	serverAddress, referenceLog := startSSRReference(t, reference, password)
	host, portText, err := net.SplitHostPort(serverAddress)
	if err != nil {
		t.Fatal("SSR reference address was invalid")
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal("SSR reference port was invalid")
	}
	proxyMapping := func(candidatePassword string, obfuscation string) map[string]any {
		return map[string]any{
			"name":     "controlled-ssr-client",
			"type":     "ssr",
			"server":   host,
			"port":     port,
			"password": candidatePassword,
			"cipher":   "aes-128-ctr",
			"protocol": "auth_aes128_md5",
			"obfs":     obfuscation,
			"udp":      true,
		}
	}

	proxy, err := adapter.ParseProxy(proxyMapping(password, "http_simple"))
	if err != nil {
		t.Fatalf("SSR construct failed: %s", externalInteropErrorCategory(err))
	}
	assertSSRReferenceTCP(t, proxy, tcpURL, referenceLog)
	assertSSRReferenceUDP(t, proxy, udpAddress)
	if tcpRequests.Load() == 0 || udpRequests.Load() == 0 {
		t.Fatal("SSR reference target did not observe both transports")
	}
	if err := proxy.Close(); err != nil {
		t.Fatalf("SSR close failed: %s", externalInteropErrorCategory(err))
	}

	beforeFailures := tcpRequests.Load()
	assertSSRReferenceFailure(t, proxyMapping(randomLabSecret(t), "http_simple"), tcpURL, "password")
	assertSSRReferenceFailure(t, proxyMapping(password, "plain"), tcpURL, "obfuscation")
	if tcpRequests.Load() != beforeFailures {
		t.Fatal("SSR rejected variants changed the target request count")
	}
}

func verifySSRReference(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&0o111 == 0 {
		t.Fatal("SSR reference is not an executable regular file")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, _ := exec.CommandContext(ctx, path, "--version").CombinedOutput()
	if len(output) == 0 || len(output) > 1<<20 ||
		!bytes.Contains(output, []byte("ShadowsocksR "+ssrReferenceVersion)) {
		t.Fatal("SSR reference version does not match the pinned source")
	}
}

func startSSRReference(t *testing.T, reference string, password string) (string, *synchronizedSSRLog) {
	t.Helper()
	address := reserveSSRReferenceAddress(t)
	_, portText, _ := net.SplitHostPort(address)
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal("SSR reference port was invalid")
	}
	config := map[string]any{
		"server":         "127.0.0.1",
		"server_port":    port,
		"password":       password,
		"timeout":        30,
		"method":         "aes-128-ctr",
		"protocol":       "auth_aes128_md5",
		"protocol_param": "",
		"obfs":           "http_simple",
		"obfs_param":     "",
		"fast_open":      false,
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal("SSR reference config encoding failed")
	}
	configPath := filepath.Join(t.TempDir(), "ssr-reference.json")
	if err := os.WriteFile(configPath, encoded, 0o600); err != nil {
		t.Fatal("SSR reference config creation failed")
	}

	processContext, cancelProcess := context.WithCancel(context.Background())
	referenceLog := &synchronizedSSRLog{}
	// The pinned Python reference derives protocol padding from TCP_MAXSEG.
	// Loopback advertises a synthetic MSS above the SSR frame limit on macOS,
	// unlike a real network path, so its wrapper bounds only that observation.
	command := exec.CommandContext(processContext, reference, "-c", configPath, "--forbidden-ip", "192.0.2.0/24", "-v")
	command.Env = append(os.Environ(), ssrReferenceMSSVariable+"="+ssrReferenceMSS)
	command.Stdout = io.Discard
	command.Stderr = referenceLog
	if err := command.Start(); err != nil {
		cancelProcess()
		t.Fatal("SSR reference could not start")
	}
	processDone := make(chan struct{})
	go func() {
		_ = command.Wait()
		close(processDone)
	}()
	t.Cleanup(func() {
		cancelProcess()
		select {
		case <-processDone:
		case <-time.After(5 * time.Second):
			if command.Process != nil {
				_ = command.Process.Kill()
			}
			<-processDone
		}
	})

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-processDone:
			t.Fatalf("SSR reference exited before becoming ready: %s", referenceLog.category())
		default:
		}
		connection, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return address, referenceLog
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("SSR reference readiness timed out")
	return "", referenceLog
}

func reserveSSRReferenceAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal("SSR reference port reservation failed")
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal("SSR reference port release failed")
	}
	return address
}

func startSSRReferenceTargets(t *testing.T) (string, string, *atomic.Int64, *atomic.Int64) {
	t.Helper()
	tcpListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal("SSR TCP target listen failed")
	}
	udpConnection, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		_ = tcpListener.Close()
		t.Fatal("SSR UDP target listen failed")
	}
	t.Cleanup(func() {
		_ = udpConnection.Close()
		_ = tcpListener.Close()
	})

	tcpRequests := &atomic.Int64{}
	udpRequests := &atomic.Int64{}
	httpServer := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			tcpRequests.Add(1)
			writer.WriteHeader(http.StatusNoContent)
		}),
	}
	go func() { _ = httpServer.Serve(tcpListener) }()
	go func() {
		buffer := make([]byte, 64*1024)
		for {
			count, remote, err := udpConnection.ReadFrom(buffer)
			if err != nil {
				return
			}
			udpRequests.Add(1)
			_, _ = udpConnection.WriteTo(buffer[:count], remote)
		}
	}()
	return "http://" + tcpListener.Addr().String() + "/generate_204",
		udpConnection.LocalAddr().String(), tcpRequests, udpRequests
}

func assertSSRReferenceTCP(t *testing.T, proxy C.Proxy, targetURL string, referenceLog *synchronizedSSRLog) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	delay, err := proxy.URLTest(ctx, targetURL, nil)
	cancel()
	if err != nil {
		t.Fatalf("SSR TCP interop failed: %s (reference=%s)", externalInteropErrorCategory(err), referenceLog.category())
	}
	if delay == 0 {
		t.Fatal("SSR TCP interop returned the failure sentinel delay")
	}
}

func assertSSRReferenceUDP(t *testing.T, proxy C.Proxy, targetAddress string) {
	t.Helper()
	udpAddress, err := net.ResolveUDPAddr("udp4", targetAddress)
	if err != nil {
		t.Fatal("SSR UDP target resolution failed")
	}
	address, ok := netip.AddrFromSlice(udpAddress.IP)
	if !ok {
		t.Fatal("SSR UDP target address was invalid")
	}
	metadata := &C.Metadata{
		NetWork: C.UDP,
		Type:    C.TUN,
		DstIP:   address.Unmap(),
		DstPort: uint16(udpAddress.Port),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	packetConnection, err := proxy.ListenPacketContext(ctx, metadata)
	cancel()
	if err != nil {
		t.Fatalf("SSR UDP session failed: %s", externalInteropErrorCategory(err))
	}
	defer packetConnection.Close()
	if err := packetConnection.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatalf("SSR UDP deadline failed: %s", externalInteropErrorCategory(err))
	}
	payload := []byte("hako-ssr-reference")
	if _, err := packetConnection.WriteTo(payload, udpAddress); err != nil {
		t.Fatalf("SSR UDP write failed: %s", externalInteropErrorCategory(err))
	}
	buffer := make([]byte, 64*1024)
	count, source, err := packetConnection.ReadFrom(buffer)
	if err != nil {
		t.Fatalf("SSR UDP read failed: %s", externalInteropErrorCategory(err))
	}
	if !bytes.Equal(buffer[:count], payload) || source.String() != udpAddress.String() {
		t.Fatal("SSR UDP echo response did not match the request")
	}
}

func assertSSRReferenceFailure(t *testing.T, mapping map[string]any, targetURL string, variant string) {
	t.Helper()
	proxy, err := adapter.ParseProxy(mapping)
	if err != nil {
		t.Fatalf("SSR %s failure variant construct failed: %s", variant, externalInteropErrorCategory(err))
	}
	defer proxy.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_, err = proxy.URLTest(ctx, targetURL, nil)
	cancel()
	if err == nil {
		t.Fatalf("SSR %s failure variant unexpectedly succeeded", variant)
	}
}

func randomLabSecret(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal("lab secret generation failed")
	}
	return hex.EncodeToString(raw)
}
