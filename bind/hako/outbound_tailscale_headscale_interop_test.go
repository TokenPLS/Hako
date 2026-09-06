//go:build with_gvisor && !no_tailscale

package hako

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/adapter"
	C "github.com/TokenPLS/Hako/constant"
	"github.com/metacubex/tailscale/tsnet"
)

const (
	headscaleReferenceEnvironment = "HAKO_HEADSCALE_REFERENCE_BIN"
	headscaleReferenceModule      = "github.com/juanfont/headscale"
	headscaleReferenceVersion     = "v0.28.0"
	headscaleReferenceModuleSum   = "h1:1lz1wj1NhKH2Y+U6URaVochCMrBsb+IUNDjQdwKn37Q="
)

func TestTailscaleHeadscaleInterop(t *testing.T) {
	reference := os.Getenv(headscaleReferenceEnvironment)
	if reference == "" {
		t.Skip(headscaleReferenceEnvironment + " is not set")
	}
	verifyHeadscaleReference(t, reference)

	controlURL, configPath := startHeadscaleReference(t, reference)
	userID := createHeadscaleUser(t, reference, configPath)
	targetKey := createHeadscalePreauthKey(t, reference, configPath, userID)
	clientKey := createHeadscalePreauthKey(t, reference, configPath, userID)

	target, targetName, tcpPort, udpPort, tcpRequests, udpRequests := startTailnetTarget(
		t,
		controlURL,
		targetKey,
	)
	t.Cleanup(func() { _ = target.Close() })

	proxyMapping := func(stateDirectory string, authKey string) map[string]any {
		return map[string]any{
			"name":        "controlled-tailnet-client",
			"type":        "tailscale",
			"hostname":    "hako-lab-client",
			"auth-key":    authKey,
			"control-url": controlURL,
			"state-dir":   stateDirectory,
			"ephemeral":   true,
			"udp":         true,
		}
	}

	firstProxy, err := adapter.ParseProxy(proxyMapping(shortTestDirectory(t, "hako-ts-client-"), clientKey))
	if err != nil {
		t.Fatalf("tailscale construct failed: %s", externalInteropErrorCategory(err))
	}
	tcpURL := "http://" + net.JoinHostPort(targetName, strconv.Itoa(tcpPort)) + "/generate_204"
	udpAddress := net.JoinHostPort(targetName, strconv.Itoa(udpPort))
	assertTailscaleTCP(t, firstProxy, tcpURL)
	assertTailscaleUDP(t, firstProxy, udpAddress)
	if tcpRequests.Load() == 0 || udpRequests.Load() == 0 {
		t.Fatal("tailscale target did not observe both transports")
	}
	if err := firstProxy.Close(); err != nil {
		t.Fatalf("tailscale first close failed: %s", externalInteropErrorCategory(err))
	}

	secondProxy, err := adapter.ParseProxy(proxyMapping(shortTestDirectory(t, "hako-ts-rejoin-"), clientKey))
	if err != nil {
		t.Fatalf("tailscale reconnect construct failed: %s", externalInteropErrorCategory(err))
	}
	assertTailscaleTCP(t, secondProxy, tcpURL)
	if err := secondProxy.Close(); err != nil {
		t.Fatalf("tailscale reconnect close failed: %s", externalInteropErrorCategory(err))
	}

	beforeInvalid := tcpRequests.Load()
	invalidProxy, err := adapter.ParseProxy(proxyMapping(shortTestDirectory(t, "hako-ts-invalid-"), "hskey-auth-invalid"))
	if err != nil {
		t.Fatalf("tailscale invalid-auth construct failed: %s", externalInteropErrorCategory(err))
	}
	invalidContext, invalidCancel := context.WithTimeout(context.Background(), 10*time.Second)
	_, invalidError := invalidProxy.URLTest(invalidContext, tcpURL, nil)
	invalidCancel()
	_ = invalidProxy.Close()
	if invalidError == nil {
		t.Fatal("tailscale invalid auth key unexpectedly reached the target")
	}
	if tcpRequests.Load() != beforeInvalid {
		t.Fatal("tailscale invalid auth key changed the target request count")
	}
}

func verifyHeadscaleReference(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&0o111 == 0 {
		t.Fatal("headscale reference is not an executable regular file")
	}
	build, err := buildinfo.ReadFile(path)
	if err != nil {
		t.Fatal("headscale reference build information is unavailable")
	}
	if build.Path != headscaleReferenceModule+"/cmd/headscale" || build.Main.Path != headscaleReferenceModule ||
		build.Main.Version != headscaleReferenceVersion || build.Main.Sum != headscaleReferenceModuleSum {
		t.Fatal("headscale reference module identity does not match the pinned release")
	}
}

func startHeadscaleReference(t *testing.T, reference string) (string, string) {
	t.Helper()
	root := shortTestDirectory(t, "hako-hs-")
	stateDirectory := filepath.Join(root, "state")
	if err := os.MkdirAll(stateDirectory, 0o700); err != nil {
		t.Fatal("headscale state directory creation failed")
	}
	controlAddress := reserveLoopbackAddress(t)
	grpcAddress := reserveLoopbackAddress(t)
	controlURL := "http://" + controlAddress
	configPath := filepath.Join(root, "config.yaml")
	config := fmt.Sprintf(`server_url: %s
listen_addr: %s
metrics_listen_addr: ""
grpc_listen_addr: %s
grpc_allow_insecure: false
noise:
  private_key_path: %s
prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
  allocation: sequential
derp:
  server:
    enabled: true
    region_id: 999
    region_code: hako-lab
    region_name: Hako Lab
    verify_clients: true
    stun_listen_addr: 127.0.0.1:0
    private_key_path: %s
    automatically_add_embedded_derp_region: true
    ipv4: 127.0.0.1
    ipv6: "::1"
  urls: []
  paths: []
  auto_update_enabled: false
  update_frequency: 24h
disable_check_updates: true
ephemeral_node_inactivity_timeout: 30m
database:
  type: sqlite
  debug: false
  gorm:
    prepare_stmt: true
    parameterized_queries: true
    skip_err_record_not_found: true
    slow_threshold: 1000
  sqlite:
    path: %s
    write_ahead_log: true
    wal_autocheckpoint: 1000
acme_url: https://acme-v02.api.letsencrypt.org/directory
acme_email: ""
tls_letsencrypt_hostname: ""
tls_letsencrypt_cache_dir: %s
tls_letsencrypt_challenge_type: HTTP-01
tls_letsencrypt_listen: ":http"
tls_cert_path: ""
tls_key_path: ""
log:
  level: warn
  format: text
policy:
  mode: file
  path: ""
dns:
  magic_dns: true
  base_domain: hako-lab.test
  override_local_dns: false
  nameservers:
    global: []
    split: {}
  search_domains: []
  extra_records: []
unix_socket: %s
unix_socket_permission: "0700"
logtail:
  enabled: false
randomize_client_port: false
taildrop:
  enabled: false
`,
		strconv.Quote(controlURL),
		strconv.Quote(controlAddress),
		strconv.Quote(grpcAddress),
		strconv.Quote(filepath.Join(stateDirectory, "noise_private.key")),
		strconv.Quote(filepath.Join(stateDirectory, "derp_private.key")),
		strconv.Quote(filepath.Join(stateDirectory, "db.sqlite")),
		strconv.Quote(filepath.Join(stateDirectory, "cache")),
		strconv.Quote(filepath.Join(stateDirectory, "headscale.sock")),
	)
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal("headscale config creation failed")
	}

	processContext, cancelProcess := context.WithCancel(context.Background())
	command := exec.CommandContext(processContext, reference, "-c", configPath, "serve")
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		cancelProcess()
		t.Fatal("headscale reference could not start")
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

	healthClient := &http.Client{
		Timeout:   time.Second,
		Transport: &http.Transport{Proxy: nil},
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-processDone:
			t.Fatal("headscale reference exited before becoming ready")
		default:
		}
		response, err := healthClient.Get(controlURL + "/health")
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode >= 200 && response.StatusCode < 300 {
				return controlURL, configPath
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("headscale reference readiness timed out")
	return "", ""
}

func reserveLoopbackAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal("loopback port reservation failed")
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal("loopback port release failed")
	}
	return address
}

func shortTestDirectory(t *testing.T, pattern string) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", pattern)
	if err != nil {
		t.Fatal("short test directory creation failed")
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return directory
}

func runHeadscaleJSON(t *testing.T, reference string, configPath string, arguments ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	commandArguments := append([]string{"-c", configPath}, arguments...)
	command := exec.CommandContext(ctx, reference, commandArguments...)
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		t.Fatal("headscale control command failed")
	}
	if output.Len() == 0 || output.Len() > 1<<20 {
		t.Fatal("headscale control command returned invalid JSON size")
	}
	return output.Bytes()
}

func createHeadscaleUser(t *testing.T, reference string, configPath string) uint64 {
	t.Helper()
	var result struct {
		ID uint64 `json:"id"`
	}
	if err := json.Unmarshal(
		runHeadscaleJSON(t, reference, configPath, "users", "create", "hako-lab", "-o", "json"),
		&result,
	); err != nil || result.ID == 0 {
		t.Fatal("headscale user response was invalid")
	}
	return result.ID
}

func createHeadscalePreauthKey(t *testing.T, reference string, configPath string, userID uint64) string {
	t.Helper()
	var result struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(
		runHeadscaleJSON(
			t,
			reference,
			configPath,
			"preauthkeys",
			"create",
			"--user",
			strconv.FormatUint(userID, 10),
			"--reusable",
			"--ephemeral",
			"-o",
			"json",
		),
		&result,
	); err != nil || !strings.HasPrefix(result.Key, "hskey-auth-") {
		t.Fatal("headscale preauth response was invalid")
	}
	return result.Key
}

func startTailnetTarget(
	t *testing.T,
	controlURL string,
	authKey string,
) (*tsnet.Server, string, int, int, *atomic.Int64, *atomic.Int64) {
	t.Helper()
	const targetHostname = "hako-lab-target"
	target := &tsnet.Server{
		Dir:        shortTestDirectory(t, "hako-ts-target-"),
		Hostname:   targetHostname,
		AuthKey:    authKey,
		ControlURL: controlURL,
		Ephemeral:  true,
		Logf:       func(string, ...any) {},
		UserLogf:   func(string, ...any) {},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if _, err := target.Up(ctx); err != nil {
		_ = target.Close()
		t.Fatalf("tailscale target startup failed: %s", externalInteropErrorCategory(err))
	}
	v4, _ := target.TailscaleIPs()
	if !v4.IsValid() {
		_ = target.Close()
		t.Fatal("tailscale target did not receive an IPv4 address")
	}
	tcpListener, err := target.Listen("tcp", ":0")
	if err != nil {
		_ = target.Close()
		t.Fatalf("tailscale target TCP listen failed: %s", externalInteropErrorCategory(err))
	}
	udpConnection, err := target.ListenPacket("udp", net.JoinHostPort(v4.String(), "0"))
	if err != nil {
		_ = tcpListener.Close()
		_ = target.Close()
		t.Fatalf("tailscale target UDP listen failed: %s", externalInteropErrorCategory(err))
	}
	t.Cleanup(func() {
		_ = udpConnection.Close()
		_ = tcpListener.Close()
	})

	tcpPort := addressPort(t, tcpListener.Addr())
	udpPort := addressPort(t, udpConnection.LocalAddr())
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
	return target, targetHostname + ".hako-lab.test", tcpPort, udpPort, tcpRequests, udpRequests
}

func addressPort(t *testing.T, address net.Addr) int {
	t.Helper()
	_, portText, err := net.SplitHostPort(address.String())
	if err != nil {
		t.Fatal("tailnet listener address was invalid")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		t.Fatal("tailnet listener port was invalid")
	}
	return int(port)
}

func assertTailscaleTCP(t *testing.T, proxy C.Proxy, targetURL string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	delay, err := proxy.URLTest(ctx, targetURL, nil)
	cancel()
	if err != nil {
		t.Fatalf("tailscale TCP/DNS interop failed: %s", externalInteropErrorCategory(err))
	}
	if delay == 0 {
		t.Fatal("tailscale TCP/DNS interop returned the failure sentinel delay")
	}
}

func assertTailscaleUDP(t *testing.T, proxy C.Proxy, targetAddress string) {
	t.Helper()
	host, portText, err := net.SplitHostPort(targetAddress)
	if err != nil {
		t.Fatal("tailscale UDP target was invalid")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		t.Fatal("tailscale UDP target port was invalid")
	}
	metadata := &C.Metadata{
		NetWork: C.UDP,
		Type:    C.TUN,
		Host:    host,
		DstPort: uint16(port),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	packetConnection, err := proxy.ListenPacketContext(ctx, metadata)
	cancel()
	if err != nil {
		t.Fatalf("tailscale UDP/DNS session failed: %s", externalInteropErrorCategory(err))
	}
	defer packetConnection.Close()
	if err := packetConnection.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("tailscale UDP deadline failed: %s", externalInteropErrorCategory(err))
	}
	resolved := netip.AddrPortFrom(metadata.DstIP, metadata.DstPort)
	if !resolved.IsValid() {
		t.Fatal("tailscale UDP/DNS did not resolve the target")
	}
	payload := []byte("hako-headscale-interop")
	if _, err := packetConnection.WriteTo(payload, net.UDPAddrFromAddrPort(resolved)); err != nil {
		t.Fatalf("tailscale UDP write failed: %s", externalInteropErrorCategory(err))
	}
	buffer := make([]byte, 64*1024)
	count, _, err := packetConnection.ReadFrom(buffer)
	if err != nil {
		t.Fatalf("tailscale UDP read failed: %s", externalInteropErrorCategory(err))
	}
	if !bytes.Equal(buffer[:count], payload) {
		t.Fatal("tailscale UDP echo response did not match the request")
	}
}
