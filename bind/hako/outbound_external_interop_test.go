package hako

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/adapter"
	C "github.com/TokenPLS/Hako/constant"
	"gopkg.in/yaml.v3"
)

const (
	externalOutboundFixturesEnvironment = "HAKO_EXTERNAL_OUTBOUND_FIXTURES"
	externalOutboundFixtureLimit        = 1 << 20
)

type externalOutboundFixture struct {
	Type           string         `yaml:"type"`
	Proxy          map[string]any `yaml:"proxy"`
	TCPURL         string         `yaml:"tcp-url"`
	UDPEchoAddress string         `yaml:"udp-echo-address"`
	TimeoutSeconds int            `yaml:"timeout-seconds"`
}

func TestExternalOutboundInterop(t *testing.T) {
	rawPaths := os.Getenv(externalOutboundFixturesEnvironment)
	if rawPaths == "" {
		t.Skip(externalOutboundFixturesEnvironment + " is not set")
	}
	paths := filepath.SplitList(rawPaths)
	if len(paths) == 0 {
		t.Fatal("external outbound fixture list is empty")
	}
	for index, path := range paths {
		fixture, err := loadExternalOutboundFixture(path)
		if err != nil {
			t.Fatalf("external fixture %d is invalid: %s", index, externalInteropErrorCategory(err))
		}
		t.Run(fmt.Sprintf("%02d-%s", index, fixture.Type), func(t *testing.T) {
			runExternalOutboundFixture(t, fixture)
		})
	}
}

func TestExternalOutboundFixtureValidation(t *testing.T) {
	valid := []byte(`
type: ssr
proxy:
  name: private-node
  type: ssr
  server: 192.0.2.1
  port: 443
  password: not-a-secret
  cipher: aes-128-ctr
  obfs: plain
  protocol: origin
  udp: true
tcp-url: https://example.com/generate_204
udp-echo-address: 192.0.2.2:10000
timeout-seconds: 15
`)
	path := filepath.Join(t.TempDir(), "fixture.yaml")
	if err := os.WriteFile(path, valid, 0o600); err != nil {
		t.Fatal(err)
	}
	fixture, err := loadExternalOutboundFixture(path)
	if err != nil {
		t.Fatal(err)
	}
	if fixture.Type != "ssr" || fixture.TimeoutSeconds != 15 {
		t.Fatalf("fixture = %#v", fixture)
	}

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadExternalOutboundFixture(path); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("insecure fixture error = %v", err)
	}

	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(t.TempDir(), "fixture-link.yaml")
	if err := os.Symlink(path, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := loadExternalOutboundFixture(symlink); err == nil || !strings.Contains(err.Error(), "regular") {
		t.Fatalf("symlink fixture error = %v", err)
	}

	tailscale := []byte(`
type: tailscale
proxy:
  name: private-tailnet
  type: tailscale
  auth-key: private-auth-key
  control-url: https://control.example.test
  ephemeral: true
  udp: true
tcp-url: http://100.64.0.2:8080/generate_204
udp-echo-address: 100.64.0.2:10000
timeout-seconds: 30
`)
	tailscalePath := filepath.Join(t.TempDir(), "tailscale.yaml")
	if err := os.WriteFile(tailscalePath, tailscale, 0o600); err != nil {
		t.Fatal(err)
	}
	tailscaleFixture, err := loadExternalOutboundFixture(tailscalePath)
	if err != nil {
		t.Fatalf("tailscale fixture error = %v", err)
	}
	tailscaleFixture.Proxy["state-dir"] = "/private/persistent-state"
	tailscaleFixture.Proxy["ephemeral"] = false
	mapping := externalProxyMapping(t, tailscaleFixture)
	if mapping["state-dir"] == tailscaleFixture.Proxy["state-dir"] {
		t.Fatal("tailscale lab fixture retained persistent state-dir")
	}
	if ephemeral, _ := mapping["ephemeral"].(bool); !ephemeral {
		t.Fatal("tailscale lab fixture was not forced ephemeral")
	}
}

func loadExternalOutboundFixture(path string) (*externalOutboundFixture, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, errors.New("fixture unavailable")
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("fixture must be a regular file")
	}
	if info.Mode().Perm() != 0o600 {
		return nil, errors.New("fixture permissions must be 0600")
	}
	if info.Size() <= 0 || info.Size() > externalOutboundFixtureLimit {
		return nil, errors.New("fixture size is outside the allowed range")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("fixture unavailable")
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return nil, errors.New("fixture changed while opening")
	}
	if openedInfo.Mode().Perm() != 0o600 || openedInfo.Size() != info.Size() {
		return nil, errors.New("fixture changed while opening")
	}
	decoder := yaml.NewDecoder(io.LimitReader(file, externalOutboundFixtureLimit+1))
	decoder.KnownFields(true)
	var fixture externalOutboundFixture
	if err := decoder.Decode(&fixture); err != nil {
		return nil, errors.New("fixture YAML is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("fixture contains trailing YAML documents")
	}
	if fixture.Type != "ssr" && fixture.Type != "hysteria" && fixture.Type != "openvpn" && fixture.Type != "tailscale" {
		return nil, errors.New("fixture protocol type is not an external-gate protocol")
	}
	proxyType, _ := fixture.Proxy["type"].(string)
	if proxyType != fixture.Type {
		return nil, errors.New("fixture proxy type does not match the declared type")
	}
	if name, _ := fixture.Proxy["name"].(string); strings.TrimSpace(name) == "" {
		return nil, errors.New("fixture proxy name is missing")
	}
	targetURL, err := url.Parse(fixture.TCPURL)
	if err != nil || targetURL.Host == "" || (targetURL.Scheme != "http" && targetURL.Scheme != "https") {
		return nil, errors.New("fixture TCP URL is invalid")
	}
	if _, _, err := net.SplitHostPort(fixture.UDPEchoAddress); err != nil {
		return nil, errors.New("fixture UDP echo address is invalid")
	}
	if fixture.TimeoutSeconds == 0 {
		fixture.TimeoutSeconds = 15
	}
	if fixture.TimeoutSeconds < 1 || fixture.TimeoutSeconds > 60 {
		return nil, errors.New("fixture timeout is outside 1...60 seconds")
	}
	return &fixture, nil
}

func runExternalOutboundFixture(t *testing.T, fixture *externalOutboundFixture) {
	t.Helper()
	proxyMapping := externalProxyMapping(t, fixture)
	proxy, err := adapter.ParseProxy(proxyMapping)
	if err != nil {
		t.Fatalf("%s construct failed: %s", fixture.Type, externalInteropErrorCategory(err))
	}
	t.Cleanup(func() { _ = proxy.Close() })
	timeout := time.Duration(fixture.TimeoutSeconds) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	delay, err := proxy.URLTest(ctx, fixture.TCPURL, nil)
	cancel()
	if err != nil {
		t.Fatalf("%s TCP interop failed: %s", fixture.Type, externalInteropErrorCategory(err))
	}
	if delay == 0 {
		t.Fatalf("%s TCP interop returned the failure sentinel delay", fixture.Type)
	}

	udpAddress, err := net.ResolveUDPAddr("udp", fixture.UDPEchoAddress)
	if err != nil {
		t.Fatalf("%s UDP target resolution failed: %s", fixture.Type, externalInteropErrorCategory(err))
	}
	metadata := &C.Metadata{NetWork: C.UDP, Type: C.TUN, DstPort: uint16(udpAddress.Port)}
	if address, ok := netip.AddrFromSlice(udpAddress.IP); ok {
		metadata.DstIP = address.Unmap()
	} else {
		host, _, _ := net.SplitHostPort(fixture.UDPEchoAddress)
		metadata.Host = host
	}
	ctx, cancel = context.WithTimeout(context.Background(), timeout)
	packetConnection, err := proxy.ListenPacketContext(ctx, metadata)
	cancel()
	if err != nil {
		t.Fatalf("%s UDP session failed: %s", fixture.Type, externalInteropErrorCategory(err))
	}
	defer packetConnection.Close()
	if err := packetConnection.SetDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatalf("%s UDP deadline failed: %s", fixture.Type, externalInteropErrorCategory(err))
	}
	payload := []byte("hako-external-interop-udp")
	if _, err := packetConnection.WriteTo(payload, udpAddress); err != nil {
		t.Fatalf("%s UDP write failed: %s", fixture.Type, externalInteropErrorCategory(err))
	}
	buffer := make([]byte, 64*1024)
	count, source, err := packetConnection.ReadFrom(buffer)
	if err != nil {
		t.Fatalf("%s UDP read failed: %s", fixture.Type, externalInteropErrorCategory(err))
	}
	if !bytes.Equal(buffer[:count], payload) || source.String() != udpAddress.String() {
		t.Fatalf("%s UDP echo response did not match the request", fixture.Type)
	}
}

func externalProxyMapping(t *testing.T, fixture *externalOutboundFixture) map[string]any {
	t.Helper()
	proxyMapping := make(map[string]any, len(fixture.Proxy)+2)
	for key, value := range fixture.Proxy {
		proxyMapping[key] = value
	}
	if fixture.Type == "tailscale" {
		// A lab credential must never cause durable Tailscale state to escape the
		// test lifetime, even if the private fixture accidentally requests it.
		proxyMapping["state-dir"] = t.TempDir()
		proxyMapping["ephemeral"] = true
	}
	return proxyMapping
}

func externalInteropErrorCategory(err error) string {
	if err == nil {
		return "none"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return "timeout"
	}
	message := strings.ToLower(err.Error())
	for category, fragments := range map[string][]string{
		"authentication": {"auth", "credential", "password"},
		"certificate":    {"certificate", "x509", "tls"},
		"connection":     {"connect", "refused", "reset", "closed"},
		"configuration":  {"config", "parse", "invalid", "unsupported"},
		"dns":            {"resolve", "lookup", "dns"},
	} {
		for _, fragment := range fragments {
			if strings.Contains(message, fragment) {
				return category
			}
		}
	}
	return "protocol"
}
