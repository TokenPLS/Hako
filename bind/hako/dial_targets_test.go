package hako

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The provider's own payload. Its node is NOT in `proxies:`, which is the whole point:
// tunnel.Proxies() is built from the `proxies:` section and the groups, and a provider's
// members go to providersMap instead (config/config.go). A reader whose nodes all come
// from a subscription has an empty answer unless the providers are walked too.
const dialTargetsProviderPayload = `proxies:
  - {name: fromProvider, type: socks5, server: 10.0.0.2, port: 1081}
`

const dialTargetsYAML = `
mode: rule
log-level: info
proxies:
  - {name: declared, type: socks5, server: 10.0.0.1, port: 1080}
  - {name: chained, type: socks5, server: 10.0.0.3, port: 1082, dialer-proxy: declared}
proxy-providers:
  air:
    type: file
    path: ./nodes.yaml
    health-check: {enable: false, url: "http://captive.apple.com", interval: 600}
proxy-groups:
  - {name: Top, type: select, use: [air], proxies: [declared, chained, DIRECT]}
rules:
  - MATCH,Top
`

// startDialTargetsCore stages the provider payload where the running core will read it,
// then starts a core on the configuration above.
func startDialTargetsCore(t *testing.T) {
	t.Helper()
	options := testOptions(t)
	if err := os.MkdirAll(options.WorkingPath, 0o755); err != nil {
		t.Fatal(err)
	}
	payload := filepath.Join(options.WorkingPath, "nodes.yaml")
	if err := os.WriteFile(payload, []byte(dialTargetsProviderPayload), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Setup(options); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	service, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	t.Cleanup(func() { _ = service.Close() })
	if err := service.Start(dialTargetsYAML); err != nil {
		t.Fatalf("Start: %v", err)
	}
}

func decodeDialTargets(t *testing.T, payload string) map[string]map[string]any {
	t.Helper()
	var decoded struct {
		Targets []map[string]any `json:"targets"`
	}
	if err := json.Unmarshal([]byte(payload), &decoded); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, payload)
	}
	byName := map[string]map[string]any{}
	for _, target := range decoded.Targets {
		name, _ := target["name"].(string)
		byName[name] = target
	}
	return byName
}

// The case this exists for: a reader's DNS probe wants every host this configuration will
// dial, and today it re-reads the working config and hand-parses each provider file to get
// them. Addr() is what the adapter itself dials, so it cannot disagree with the dialer the
// way a YAML scan for `server:` can -- that scan has to guess a field per dialect (vmess
// vnext[].address, wireguard peers, the ssr/snell aliases) and silently misses a batch when
// it guesses wrong.
func TestDialTargetsNamesEveryNodeIncludingAProvidersOwn(t *testing.T) {
	startDialTargetsCore(t)
	targets := decodeDialTargets(t, DialTargetsJSON())

	declared, ok := targets["declared"]
	if !ok {
		t.Fatalf("the `proxies:` section's node is missing:\n%s", DialTargetsJSON())
	}
	if declared["addr"] != "10.0.0.1:1080" {
		t.Fatalf("declared addr = %v, want 10.0.0.1:1080", declared["addr"])
	}
	if declared["host"] != "10.0.0.1" {
		t.Fatalf("declared host = %v, want 10.0.0.1", declared["host"])
	}
	if declared["port"] != float64(1080) {
		t.Fatalf("declared port = %v, want 1080", declared["port"])
	}
	if declared["type"] != "Socks5" {
		t.Fatalf("declared type = %v, want the adapter's own type string", declared["type"])
	}
	if provider, present := declared["provider"]; present {
		t.Fatalf("a node from `proxies:` has no provider, got %v", provider)
	}

	fromProvider, ok := targets["fromProvider"]
	if !ok {
		t.Fatalf("the provider's own node is missing -- tunnel.Proxies() alone does not hold it:\n%s", DialTargetsJSON())
	}
	if fromProvider["addr"] != "10.0.0.2:1081" {
		t.Fatalf("provider node addr = %v, want 10.0.0.2:1081", fromProvider["addr"])
	}
	if fromProvider["provider"] != "air" {
		t.Fatalf("provider node provider = %v, want air", fromProvider["provider"])
	}
}

// A node dialled through another node is reachable, but its own host is resolved by that
// upstream, not by this device -- so a local DNS probe against it reads as a false red. The
// row has to carry the fact that makes the probe decision, or the caller is forced to parse
// a second document and join it by name.
func TestADialerProxyNodeSaysSoOnItsOwnRow(t *testing.T) {
	startDialTargetsCore(t)
	targets := decodeDialTargets(t, DialTargetsJSON())

	chained, ok := targets["chained"]
	if !ok {
		t.Fatalf("missing chained node:\n%s", DialTargetsJSON())
	}
	if chained["dialerProxy"] != "declared" {
		t.Fatalf("dialerProxy = %v, want declared", chained["dialerProxy"])
	}
	if declared := targets["declared"]; declared["dialerProxy"] != nil {
		t.Fatalf("a node with no dialer-proxy must not carry the key, got %v", declared["dialerProxy"])
	}
}

// Groups, DIRECT and REJECT are in the same table and have no address of their own. Emitting
// them would put rows in front of a prober that it can only ever skip, and "no addr" is not
// a target -- it is the absence of one.
func TestDialTargetsLeavesOutWhatHasNoAddressToDial(t *testing.T) {
	startDialTargetsCore(t)
	targets := decodeDialTargets(t, DialTargetsJSON())
	for _, name := range []string{"Top", "DIRECT", "REJECT", "GLOBAL"} {
		if _, present := targets[name]; present {
			t.Fatalf("%q has no address of its own and must not be a dial target:\n%s", name, DialTargetsJSON())
		}
	}
}

// Map iteration in Go is randomised. A list that reorders itself between calls reads as
// change to anything that diffs it, and a reader watching a probe run would see rows move
// under them for no reason.
func TestDialTargetsAreInAStableOrder(t *testing.T) {
	startDialTargetsCore(t)
	first := DialTargetsJSON()
	for attempt := 0; attempt < 8; attempt++ {
		if again := DialTargetsJSON(); again != first {
			t.Fatalf("order is not stable:\n%s\n%s", first, again)
		}
	}
}
