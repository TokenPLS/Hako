package hako

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/TokenPLS/Hako/tunnel"
)

// A proxy node this pinned core cannot parse. yaml.Unmarshal accepts any mapping
// into ProxySchema.Proxies; adapter.ParseProxy rejects the unknown type. mihomo
// applies the provider filter before ParseProxy, so a filtered-out node like this is
// never parsed, and a filter-passing parse error is non-fatal at load.
const unparsableProxyType = "hako-nonexistent-proto"

func proxyPayload(nodes ...string) []byte {
	var buffer bytes.Buffer
	buffer.WriteString("proxies:\n")
	for _, node := range nodes {
		buffer.WriteString("  - ")
		buffer.WriteString(node)
		buffer.WriteString("\n")
	}
	return buffer.Bytes()
}

// Runtime staging (parseNodes=false) does NOT parse nodes: it defers parseability
// and the provider filter to mihomo, so a node this core cannot parse never fails
// staging. This is the over-constraint fix -- a pinned core lagging a subscription's
// newest proxy type no longer rejects the whole provider.
func TestSanitizeProxyProviderRuntimeDefersParseToMihomo(t *testing.T) {
	payload := proxyPayload(
		"{name: Good, type: direct}",
		fmt.Sprintf("{name: FutureProto, type: %s}", unparsableProxyType),
	)
	prepared, stripped, err := sanitizeProxyProviderPayloadForIOS("", payload, false)
	if err != nil {
		t.Fatalf("runtime staging must not parse-fail on an unparsable node: %v", err)
	}
	if len(stripped) != 0 {
		t.Fatalf("unexpected egress strip: %v", stripped)
	}
	if !bytes.Equal(prepared, payload) {
		t.Fatalf("runtime staging must pass the payload through unchanged:\n got: %q\nwant: %q", prepared, payload)
	}
}

// The standalone client pre-fetch check (parseNodes=true) still parses every node,
// so a malformed subscription is rejected before the App stores it.
func TestSanitizeProxyProviderStandaloneParseValidates(t *testing.T) {
	payload := proxyPayload(
		"{name: Good, type: direct}",
		fmt.Sprintf("{name: FutureProto, type: %s}", unparsableProxyType),
	)
	if _, _, err := sanitizeProxyProviderPayloadForIOS("", payload, true); err == nil {
		t.Fatal("the standalone pre-fetch check must reject an unparsable node")
	}
}

// The mandatory NE egress strip covers EVERY node even in runtime mode, because
// mihomo -- not Hako -- decides which nodes the filter keeps, so any node left in the
// copy could become the live node and must already be egress-safe.
func TestSanitizeProxyProviderRuntimeStripsEgressOnEveryNode(t *testing.T) {
	payload := proxyPayload(
		"{name: A, type: direct}",
		"{name: B, type: direct, interface-name: en0}",
	)
	prepared, stripped, err := sanitizeProxyProviderPayloadForIOS("", payload, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(stripped) == 0 {
		t.Fatal("an egress override must be stripped even in runtime (non-parsing) mode")
	}
	if bytes.Contains(prepared, []byte("interface-name")) {
		t.Fatalf("egress override survived in the runtime copy: %q", prepared)
	}
}

// A clean payload passes through byte-for-byte in runtime mode so staging can
// hard-link the published revision instead of copying it.
func TestSanitizeProxyProviderRuntimeCleanPassthrough(t *testing.T) {
	payload := proxyPayload("{name: A, type: direct}", "{name: B, type: direct}")
	prepared, stripped, err := sanitizeProxyProviderPayloadForIOS("", payload, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(stripped) != 0 {
		t.Fatalf("unexpected egress strip: %v", stripped)
	}
	if !bytes.Equal(prepared, payload) {
		t.Fatalf("clean payload must pass through byte-for-byte: %q", prepared)
	}
}

// End-to-end: a file proxy-provider whose filter excludes a node this core cannot
// parse must let Start succeed, with the surviving node loaded. mihomo applies
// '^Good$' before ParseProxy, so the excluded node is never parsed.
func TestProxyProviderFilterExcludesUnparsableNodeStarts(t *testing.T) {
	options := testOptions(t)
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	published := filepath.Join(options.WorkingPath, "published-filtered.yaml")
	payload := proxyPayload(
		"{name: Good, type: direct}",
		fmt.Sprintf("{name: FutureProto, type: %s}", unparsableProxyType),
	)
	if err := os.WriteFile(published, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	content := fmt.Sprintf(`
dns:
  enable: true
  nameserver: [8.8.8.8]
proxy-providers:
  filtered:
    type: file
    path: %q
    filter: '^Good$'
proxy-groups:
  - name: Controlled
    type: select
    use: [filtered]
rules:
  - MATCH,Controlled
`, published)
	service, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Start(content); err != nil {
		t.Fatalf("a filter-excluded unparsable node must not fail Start: %v", err)
	}
	t.Cleanup(func() { _ = service.Close() })
	if got := tunnel.Providers()["filtered"].Count(); got != 1 {
		t.Fatalf("runtime proxy provider count = %d, want 1 (mihomo filters out the excluded node)", got)
	}
}

// End-to-end: a filter-PASSING node this core cannot parse is non-fatal, matching
// upstream (hub/executor loadProvider logs the Initial() error and keeps running).
// Start succeeds; the provider loads empty and the group falls back to DIRECT.
func TestProxyProviderUnparsableNodeIsNonFatalAtStart(t *testing.T) {
	options := testOptions(t)
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	published := filepath.Join(options.WorkingPath, "published-degraded.yaml")
	payload := proxyPayload(
		"{name: Good, type: direct}",
		fmt.Sprintf("{name: FutureProto, type: %s}", unparsableProxyType),
	)
	if err := os.WriteFile(published, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	content := fmt.Sprintf(`
dns:
  enable: true
  nameserver: [8.8.8.8]
proxy-providers:
  degraded:
    type: file
    path: %q
proxy-groups:
  - name: Controlled
    type: select
    proxies: [DIRECT]
    use: [degraded]
rules:
  - MATCH,Controlled
`, published)
	service, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Start(content); err != nil {
		t.Fatalf("an unparsable provider node must be non-fatal at Start (upstream parity): %v", err)
	}
	t.Cleanup(func() { _ = service.Close() })
}
