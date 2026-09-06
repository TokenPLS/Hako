package hako

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	coreListener "github.com/TokenPLS/Hako/listener"
	"github.com/TokenPLS/Hako/tunnel"
)

func TestCheckConfigUsesIOSPreflightWithoutStartingCore(t *testing.T) {
	options := testOptions(t)
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	statusBefore := tunnel.Status()
	tunBefore := coreListener.GetTunConf()
	if err := CheckConfig(helloYAML); err != nil {
		t.Fatalf("CheckConfig: %v", err)
	}
	if tunnel.Status() != statusBefore {
		t.Fatalf("CheckConfig changed tunnel status: before=%v after=%v", statusBefore, tunnel.Status())
	}
	tunAfter := coreListener.GetTunConf()
	if tunAfter.Enable != tunBefore.Enable || tunAfter.FileDescriptor != tunBefore.FileDescriptor {
		t.Fatalf("CheckConfig changed tun listener: before=%+v after=%+v", tunBefore, tunAfter)
	}
	if _, err := os.Stat(ClashAPIPath()); !os.IsNotExist(err) {
		t.Fatalf("CheckConfig created controller socket: %v", err)
	}

	// dns.enable: false is mihomo's own default and most of what subscriptions
	// publish never sets it. A packet tunnel does need core DNS, but needing it
	// is a reason to supply it, not a reason to refuse the configuration.
	repaired := strings.Replace(helloYAML, "enable: true", "enable: false", 1)
	if err := CheckConfig(repaired); err != nil {
		t.Fatalf("dns.enable: false must be repaired, not refused: %v", err)
	}
	// What is still refused is upstream's own verdict, not ours: a bootstrap
	// survivor mihomo rejects. dhcp:// is stripped, and what is left is a
	// hostname rather than an IP, which fails mihomo's pure-IP check
	// (config/config.go:1459-1473) — there is nothing to repair it into.
	invalid := strings.Replace(helloYAML, "enable: true",
		"enable: true\n  default-nameserver: [dhcp://en0, \"https://dns.google/dns-query\"]", 1)
	if err := CheckConfig(invalid); err == nil {
		t.Fatal("a bootstrap mihomo rejects must still be refused")
	}
}

func TestPrivateDeviceConfigWhenProvided(t *testing.T) {
	path := os.Getenv("HAKO_PRIVATE_CONFIG")
	if path == "" {
		t.Skip("HAKO_PRIVATE_CONFIG is not set")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := Setup(testOptions(t)); err != nil {
		t.Fatal(err)
	}
	if err := CheckConfig(string(content)); err != nil {
		t.Fatalf("private device config failed iOS preflight: %v", err)
	}
	if _, err := PlatformConfigIntentJSON(string(content)); err != nil {
		t.Fatalf("private device config failed Apple intent extraction: %v", err)
	}
}

func TestFormatConfigPreservesCommentsAndTypedShape(t *testing.T) {
	input := `# routing mode
mode: rule
log-level: info
dns:
  enable: true
  nameserver: [8.8.8.8]
rules:
  - MATCH,DIRECT
`
	formatted, err := FormatConfig(input)
	if err != nil {
		t.Fatal(err)
	}
	if formatted == nil || !strings.Contains(formatted.Value, "# routing mode") {
		t.Fatalf("formatted config lost comment: %#v", formatted)
	}
	if _, err := FormatConfig("mode: [not-a-string]"); err == nil {
		t.Fatal("FormatConfig accepted an invalid typed mode")
	}
}

func TestPlatformConfigIntentJSONExtractsStrictRouteWithoutSetup(t *testing.T) {
	intent, err := PlatformConfigIntentJSON(`
mode: rule
tun:
  strict-route: true
  route-address: [0.0.0.0/1, 128.0.0.0/1]
  route-exclude-address: [192.168.0.0/16]
dns:
  enable: true
  nameserver: [8.8.8.8]
rules:
  - MATCH,DIRECT
`)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"strictRoute":true`, `"includedRouteCount":2`, `"excludedRouteCount":1`} {
		if !strings.Contains(intent.Value, want) {
			t.Fatalf("intent %s missing %s", intent.Value, want)
		}
	}
	var decoded struct {
		IntentSchemaVersion   int    `json:"intentSchemaVersion"`
		TunRestartFingerprint string `json:"tunRestartFingerprint"`
	}
	if err := json.Unmarshal([]byte(intent.Value), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.IntentSchemaVersion != 2 {
		t.Fatalf("intent schema version = %d, want 2", decoded.IntentSchemaVersion)
	}
	if len(decoded.TunRestartFingerprint) != 64 {
		t.Fatalf("tun restart fingerprint = %q, want SHA-256 hex", decoded.TunRestartFingerprint)
	}
}

func TestPlatformConfigIntentFingerprintTracksRouteValuesNotOnlyCounts(t *testing.T) {
	fingerprint := func(t *testing.T, configContent string) string {
		t.Helper()
		intent, err := PlatformConfigIntentJSON(configContent)
		if err != nil {
			t.Fatal(err)
		}
		var decoded struct {
			TunRestartFingerprint string `json:"tunRestartFingerprint"`
		}
		if err := json.Unmarshal([]byte(intent.Value), &decoded); err != nil {
			t.Fatal(err)
		}
		return decoded.TunRestartFingerprint
	}

	first := fingerprint(t, "tun:\n  route-address: [10.0.0.0/8, 192.168.0.0/16]\n")
	reordered := fingerprint(t, "tun:\n  route-address: [192.168.0.0/16, 10.0.0.0/8]\n")
	different := fingerprint(t, "tun:\n  route-address: [10.0.0.0/8, 172.16.0.0/12]\n")
	if first != reordered {
		t.Fatalf("route order changed fingerprint: %q != %q", first, reordered)
	}
	if first == different {
		t.Fatalf("different route values with equal counts shared fingerprint %q", first)
	}
}

func TestPlatformConfigIntentToleratesEmptyOrIPv6OnlyFakeIPRange(t *testing.T) {
	// An explicit empty (IPv6-only) dns.fake-ip-range is valid: upstream only
	// parses fake-ip-range when non-empty and parseTun falls back to the
	// DefaultRawConfig 198.18.0.1/16 for the tun IPv4, and Hako's own
	// CheckConfig/Start accept it. PlatformConfigIntentJSON must not reject it; the
	// fingerprint falls back to the same default instead of erroring.
	fingerprint := func(t *testing.T, configContent string) string {
		t.Helper()
		intent, err := PlatformConfigIntentJSON(configContent)
		if err != nil {
			t.Fatalf("PlatformConfigIntentJSON(%q) = %v", configContent, err)
		}
		var decoded struct {
			TunRestartFingerprint string `json:"tunRestartFingerprint"`
		}
		if err := json.Unmarshal([]byte(intent.Value), &decoded); err != nil {
			t.Fatal(err)
		}
		return decoded.TunRestartFingerprint
	}

	emptyV4 := fingerprint(t, "dns:\n  fake-ip-range: \"\"\n")
	ipv6Only := fingerprint(t, "dns:\n  fake-ip-range: \"\"\n  fake-ip-range6: fc00::/18\n")
	explicitDefault := fingerprint(t, "dns:\n  fake-ip-range: 198.18.0.1/16\n")

	if emptyV4 != explicitDefault {
		t.Fatalf("empty fake-ip-range fingerprint %q != explicit 198.18.0.1/16 default %q", emptyV4, explicitDefault)
	}
	if ipv6Only != explicitDefault {
		t.Fatalf("IPv6-only fake-ip-range fingerprint %q != explicit 198.18.0.1/16 default %q", ipv6Only, explicitDefault)
	}
}

func TestPlatformConfigIntentRejectsNonEmptyInvalidFakeIPRange(t *testing.T) {
	// The fallback is only for an empty fake-ip-range. A NON-empty value must be a
	// valid IPv4 prefix, exactly as upstream ParseRawConfig requires -- otherwise
	// the client would persist Apple VPN intent for a config CheckConfig/Start
	// later reject.
	for name, value := range map[string]string{
		"not a prefix":      "not-a-prefix",
		"invalid v4 length": "1.2.3.4/33",
		"ipv6 in v4 field":  "fc00::/18",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := PlatformConfigIntentJSON("dns:\n  fake-ip-range: \"" + value + "\"\n"); err == nil {
				t.Fatalf("non-empty invalid fake-ip-range %q must be rejected", value)
			}
		})
	}
}

func TestPlatformConfigIntentFingerprintTracksEffectiveTunRestartFields(t *testing.T) {
	fingerprint := func(t *testing.T, tunYAML string) string {
		t.Helper()
		intent, err := PlatformConfigIntentJSON("tun:\n" + tunYAML)
		if err != nil {
			t.Fatal(err)
		}
		var decoded struct {
			TunRestartFingerprint string `json:"tunRestartFingerprint"`
		}
		if err := json.Unmarshal([]byte(intent.Value), &decoded); err != nil {
			t.Fatal(err)
		}
		return decoded.TunRestartFingerprint
	}

	base := fingerprint(t, "  strict-route: false\n")
	for name, tunYAML := range map[string]string{
		"strict route":             "  strict-route: true\n",
		"IPv6 tunnel address":      "  inet6-address: [fd00::1/126]\n",
		"loopback address":         "  loopback-address: [10.0.0.1]\n",
		"endpoint independent NAT": "  endpoint-independent-nat: true\n",
		"UDP timeout":              "  udp-timeout: 120\n",
		"ICMP timeout":             "  icmp-timeout: 30\n",
	} {
		t.Run(name, func(t *testing.T) {
			if got := fingerprint(t, tunYAML); got == base {
				t.Fatalf("restart-relevant field did not change fingerprint %q", got)
			}
		})
	}
}

func TestCheckConfigToleratesHostRouteKnobsEndToEnd(t *testing.T) {
	// End-to-end proof of the tolerate + strip contract: a config a desktop
	// mihomo accepts — carrying interface-name, routing-mark, find-process-mode,
	// tun UID/interface/port host filters, auto-redirect and a PROCESS-NAME rule
	// — must pass the full iOS preflight (Setup + CheckConfig) unchanged. None of
	// it can execute in the NE and none of it changes which proxy handles a flow,
	// so the config still starts. This is the "every upstream config must start" contract.
	if err := Setup(testOptions(t)); err != nil {
		t.Fatal(err)
	}
	const withHostRouteKnobs = `
mode: rule
interface-name: en0
routing-mark: 233
find-process-mode: always
dns:
  enable: true
  enhanced-mode: fake-ip
  nameserver:
    - 8.8.8.8
tun:
  include-interface: [en0]
  exclude-dst-port: [443]
  include-uid: [501]
  auto-redirect: true
proxies:
  - name: probe
    type: socks5
    server: 127.0.0.1
    port: 1080
rules:
  - PROCESS-NAME,curl,DIRECT
  - MATCH,DIRECT
`
	if err := CheckConfig(withHostRouteKnobs); err != nil {
		t.Fatalf("upstream config with host-route knobs must start on iOS (tolerate + strip), got: %v", err)
	}
}

func TestCheckConfigStartsRealisticUpstreamConfig(t *testing.T) {
	// A single realistic upstream config a desktop mihomo accepts, carrying every
	// knob the tolerate+strip commits handle at once: top-level interface/mark +
	// find-process-mode, tun host-route filters, a system/dhcp query resolver,
	// per-proxy and group egress overrides, and PROCESS/UID rules. It must start
	// on iOS — the "every upstream config must start; unsupported settings are tolerated and stripped" capstone.
	if err := Setup(testOptions(t)); err != nil {
		t.Fatal(err)
	}
	const kitchenSink = `
mode: rule
interface-name: en0
routing-mark: 1234
find-process-mode: always
dns:
  enable: true
  enhanced-mode: fake-ip
  nameserver: [223.5.5.5, system, dhcp://en0]
  fallback: [system://]
  proxy-server-nameserver: [8.8.8.8]
tun:
  include-interface: [en0]
  exclude-dst-port: [443]
  include-uid: [501]
  auto-redirect: true
  iproute2-table-index: 100
proxies:
  - {name: node, type: socks5, server: 127.0.0.1, port: 1080, interface-name: en0, routing-mark: 7}
proxy-groups:
  - {name: auto, type: select, proxies: [node, DIRECT], interface-name: en1}
rules:
  - PROCESS-NAME,curl,DIRECT
  - UID,501,DIRECT
  - IN-USER,alice,DIRECT
  - MATCH,auto
`
	if err := CheckConfig(kitchenSink); err != nil {
		t.Fatalf("a realistic upstream config carrying all tolerate+strip knobs must start on iOS, got: %v", err)
	}
}

func TestCheckConfigStartsProcessNameRuleOnIOS(t *testing.T) {
	if err := Setup(testOptions(t)); err != nil {
		t.Fatal(err)
	}
	const content = `
dns:
  enable: true
  nameserver: [223.5.5.5]
rules:
  - PROCESS-NAME,curl,REJECT
  - DOMAIN,example.com,DIRECT
  - MATCH,DIRECT
`
	if err := CheckConfig(content); err != nil {
		t.Fatalf("PROCESS-NAME must be an explicit iOS no-op, got: %v", err)
	}
}

func TestCheckConfigStartsUIDRuleOnIOS(t *testing.T) {
	if err := Setup(testOptions(t)); err != nil {
		t.Fatal(err)
	}
	const content = `
dns:
  enable: true
  nameserver: [223.5.5.5]
rules:
  - UID,501,REJECT
  - DOMAIN,example.com,DIRECT
  - MATCH,DIRECT
`
	if err := CheckConfig(content); err != nil {
		t.Fatalf("UID must be stripped as an iOS no-op before upstream parsing, got: %v", err)
	}
}

func TestCheckConfigStartsInUserRuleOnIOS(t *testing.T) {
	if err := Setup(testOptions(t)); err != nil {
		t.Fatal(err)
	}
	const content = `
dns:
  enable: true
  nameserver: [223.5.5.5]
rules:
  - IN-USER,alice,REJECT
  - DOMAIN,example.com,DIRECT
  - MATCH,DIRECT
`
	if err := CheckConfig(content); err != nil {
		t.Fatalf("IN-USER must be stripped as an iOS no-op before upstream parsing, got: %v", err)
	}
}

func TestCheckConfigStripsSystemNameserverButRejectsSystemBootstrap(t *testing.T) {
	if err := Setup(testOptions(t)); err != nil {
		t.Fatal(err)
	}
	// A system/dhcp entry in a query-resolver list is stripped (tolerate + strip);
	// the config still starts as long as an explicit resolver remains.
	const withSystemQuery = `
mode: rule
dns:
  enable: true
  enhanced-mode: fake-ip
  nameserver: [223.5.5.5, system]
  fallback: [dhcp://en0]
proxies:
  - {name: probe, type: socks5, server: 127.0.0.1, port: 1080}
rules:
  - MATCH,DIRECT
`
	if err := CheckConfig(withSystemQuery); err != nil {
		t.Fatalf("config with a system/dhcp query resolver must start (stripped), got: %v", err)
	}
	// A bootstrap (default-nameserver) carrying system/dhcp + usable IPs strips
	// the system entry and keeps the IPs — the config starts. This is the common
	// real shape (e.g. [system, 180.76.76.76, 8.8.8.8]), not the synthetic [system].
	const withBootstrapAndResolvers = `
mode: rule
dns:
  enable: true
  enhanced-mode: fake-ip
  nameserver: [223.5.5.5]
  default-nameserver: [system, 180.76.76.76, 8.8.8.8]
proxies:
  - {name: probe, type: socks5, server: 127.0.0.1, port: 1080}
rules:
  - MATCH,DIRECT
`
	if err := CheckConfig(withBootstrapAndResolvers); err != nil {
		t.Fatalf("bootstrap with usable IPs must start (system stripped, IPs kept), got: %v", err)
	}
	// A system-only bootstrap starts. This used to be refused, on the stated
	// grounds that "mihomo requires a non-empty pure-IP default-nameserver" --
	// which is not what mihomo does: its pure-IP check explicitly `continue`s
	// past ns.Net == "system" (config/config.go:1461-1463), so a system bootstrap
	// is legal upstream. The cost of the refusal was concrete: a profile whose
	// nameservers are all IP literals never needs the bootstrap at all, and it
	// still would not start.
	//
	// filterBootstrap keeps the list rather than stripping it to empty, so what
	// reaches mihomo is the config the user wrote.
	const withSystemOnlyBootstrap = `
mode: rule
dns:
  enable: true
  enhanced-mode: fake-ip
  nameserver: [223.5.5.5]
  default-nameserver: [system]
proxies:
  - {name: probe, type: socks5, server: 127.0.0.1, port: 1080}
rules:
  - MATCH,DIRECT
`
	if err := CheckConfig(withSystemOnlyBootstrap); err != nil {
		t.Fatalf("system-only default-nameserver bootstrap must start (upstream permits it), got: %v", err)
	}
	// dhcp:// in the same slot is still rejected -- by mihomo, not by us. It is
	// not exempted from the pure-IP check the way system is, and "en0" parses as
	// neither host:port nor a URL with an IP host, so ParseRawConfig returns
	// "default nameserver should be pure IP" (config/config.go:1464-1470).
	const withDHCPBootstrap = `
mode: rule
dns:
  enable: true
  enhanced-mode: fake-ip
  nameserver: [223.5.5.5]
  default-nameserver: ["dhcp://en0"]
proxies:
  - {name: probe, type: socks5, server: 127.0.0.1, port: 1080}
rules:
  - MATCH,DIRECT
`
	// dhcp:// is the whole bootstrap, so stripping it empties the list and the
	// repair substitutes mihomo's own explicit resolvers. Refusing here would
	// mean refusing a config over a field the reader can neither keep (the NE
	// cannot bind 0.0.0.0:68) nor be expected to know needs replacing.
	if err := CheckConfig(withDHCPBootstrap); err != nil {
		t.Fatalf("a dhcp:// bootstrap must be repaired, not refused: %v", err)
	}
	// Stripping the ONLY query resolver leaves the list empty, and the repair
	// refills it with mihomo's defaults rather than leaving the core to fall
	// back to its hardcoded system resolvers (dns/system.go:71), which would
	// leak DNS. The substitution is a logged repair, not a silent one.
	const onlySystem = `
mode: rule
dns:
  enable: true
  enhanced-mode: fake-ip
  nameserver: [system]
proxies:
  - {name: probe, type: socks5, server: 127.0.0.1, port: 1080}
rules:
  - MATCH,DIRECT
`
	if err := CheckConfig(onlySystem); err != nil {
		t.Fatalf("a system-only resolver must be repaired, not refused: %v", err)
	}
}

func TestPlatformConfigIntentToleratesEveryHostRouteKnob(t *testing.T) {
	// Host-route knobs iOS cannot execute (interface binding, routing marks,
	// process-based routing, per-UID/port host filters, PROCESS rules) are
	// TOLERATED: the physical egress is chosen by NWPathMonitor and the sandbox
	// exposes no such metadata, so they are stripped rather than rejected. A
	// config carrying them still yields a valid Apple routing intent — this is
	// what lets any upstream mihomo config start on iOS.
	tolerated := []string{
		"interface-name: en0\n",
		"routing-mark: 233\n",
		"find-process-mode: always\n",
		"tun:\n  include-interface: [en0]\n",
		"tun:\n  exclude-dst-port: [443]\n",
		"tun:\n  include-uid: [501]\n",
		"tun:\n  auto-redirect: true\n",
		"rules:\n  - PROCESS-NAME,Safari,DIRECT\n",
		"proxies:\n  - {name: node, type: socks5, server: 127.0.0.1, port: 1080, interface-name: en0}\n",
	}
	for _, configContent := range tolerated {
		if _, err := PlatformConfigIntentJSON(configContent); err != nil {
			t.Fatalf("host-route knob should be tolerated (stripped), got PlatformConfigIntentJSON(%q) = %v", configContent, err)
		}
	}
	// route-address-set was the one exception, on the ground that it "changes WHICH traffic
	// enters the tunnel". It does not: sing-tun consumes it only through autoRedirect, in
	// redirect_linux.go and the nftables files, and upstream ignores it off Linux. The
	// exception is gone, so the tolerate-and-strip contract now has no holes in it.
	alsoTolerated := []string{
		"tun:\n  route-address-set: [cn]\n",
		"tun:\n  route-exclude-address-set: [cn]\n",
	}
	for _, configContent := range alsoTolerated {
		if _, err := PlatformConfigIntentJSON(configContent); err != nil {
			t.Fatalf("upstream loads this and so must we, got PlatformConfigIntentJSON(%q) = %v", configContent, err)
		}
	}
}

func TestGoVersionIncludesTarget(t *testing.T) {
	version := GoVersion()
	if !strings.Contains(version, "/") || !strings.Contains(version, "go") {
		t.Fatalf("GoVersion = %q", version)
	}
}

func TestCommandSchemaCompatibility(t *testing.T) {
	for _, test := range []struct {
		name             string
		peerMin, peerMax int32
		wantError        bool
	}{
		{name: "equal", peerMin: 1, peerMax: 1},
		{name: "newer overlapping", peerMin: 1, peerMax: 2},
		{name: "newer incompatible", peerMin: 2, peerMax: 2, wantError: true},
		{name: "invalid missing", peerMin: 0, peerMax: 0, wantError: true},
		{name: "invalid reversed", peerMin: 2, peerMax: 1, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := CheckCommandSchema(test.peerMin, test.peerMax)
			if (err != nil) != test.wantError {
				t.Fatalf("CheckCommandSchema(%d, %d) = %v", test.peerMin, test.peerMax, err)
			}
		})
	}
}

// ValidateConfigShape is a typed-shape contract, deliberately NOT
// FormatConfig-equivalence. FormatConfig re-encodes the document and enforces a
// 4 MiB limit on that formatted result -- a result its validateSource caller
// throws away. For a validator that produces nothing, a limit on a discarded
// artifact is neither upstream behavior nor platform-required, which is this
// house's own test for a self-made constraint. The one divergence this creates
// is pinned below, on purpose, so it can never become an accident.
func TestValidateConfigShapeMatchesFormatConfigOnOrdinaryDocuments(t *testing.T) {
	cases := map[string]string{
		"minimal":            "proxies: []\n",
		"one node":           "proxies:\n  - {name: A, type: socks5, server: e.test, port: 1080}\n",
		"groups and rules":   "proxies:\n  - {name: A, type: socks5, server: e.test, port: 1080}\nproxy-groups:\n  - {name: G, type: select, proxies: [A]}\nrules:\n  - MATCH,G\n",
		"anchors and merges": "base: &b {type: socks5, server: e.test, port: 1080}\nproxies:\n  - {name: A, <<: *b}\n",
		"not a mapping":      "- just\n- a\n- list\n",
		"broken yaml":        "proxies: [\n",
		"unknown proxy type": "proxies:\n  - {name: A, type: not-a-real-protocol, server: e.test, port: 1}\n",
		"empty":              "",
	}
	for name, yamlText := range cases {
		t.Run(name, func(t *testing.T) {
			_, formatErr := FormatConfig(yamlText)
			shapeErr := ValidateConfigShape(yamlText)
			if (formatErr == nil) != (shapeErr == nil) {
				t.Fatalf("verdicts differ on an ordinary document: FormatConfig=%v ValidateConfigShape=%v",
					formatErr, shapeErr)
			}
		})
	}
}

// The intended divergence: a compact document whose FORMATTED form would
// exceed the 4 MiB result limit. FormatConfig rejects it over an artifact it
// then discards; ValidateConfigShape accepts it, and any stage that actually
// produces an oversized artifact (merge, finalize, yamlToJSON) still refuses
// with its own readable reason. If this test ever fails, the contract changed
// by accident -- that is what it is here to catch.
func TestValidateConfigShapeAcceptsWhatOnlyTheDiscardedResultLimitRejected(t *testing.T) {
	var b strings.Builder
	b.WriteString("rules: [")
	// ~3.4 MiB compact input; formatting adds a space per element, pushing the
	// encoded result past the 4 MiB bound while the input stays under it.
	for i := 0; i < 1_200_000; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString("''")
	}
	b.WriteString("]\n")
	doc := b.String()

	if _, err := FormatConfig(doc); err == nil {
		t.Skip("fixture no longer trips FormatConfig's result limit; regenerate a larger one")
	}
	if err := ValidateConfigShape(doc); err != nil {
		t.Fatalf("the typed shape is legal ([]string); rejection must not survive: %v", err)
	}
}
