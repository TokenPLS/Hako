package hako

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/TokenPLS/Hako/component/process"
	"github.com/TokenPLS/Hako/config"
)

// The TestParseConfigForIOSRejectsUnsafe* family that stood here is gone
// . Seventeen tests, each pinning a refusal of a transport-option value
// upstream reads as given: QUIC flow-control windows, hysteria rates and hop
// intervals, hysteria2's udp-mtu, mekya and kcptun timings, TUIC datagram
// sizes and stream counts, BBR windows, xhttp ranges, and the global,
// per-group and per-provider durations. They were faithful tests of the wrong
// contract.
//
// What replaces them is not nothing: outbound_runtime_alignment_test.go pins
// the opposite property from the same inputs (these configurations start), and
// upstream_doc_conformance_test.go asks the wider question -- that nothing
// upstream publishes as an example is refused here.

func TestNormalizeRawConfigForIOS(t *testing.T) {
	raw := config.DefaultRawConfig()
	raw.GeodataLoader = "standard"
	raw.GeoAutoUpdate = true

	normalizeRawConfigForIOS(raw, false)

	if raw.GeodataLoader != "memconservative" || raw.GeoAutoUpdate {
		t.Fatalf("unsafe geodata settings survived: loader=%q update=%v", raw.GeodataLoader, raw.GeoAutoUpdate)
	}
	if raw.GeoXUrl.GeoIp != disabledGeoURL || raw.GeoXUrl.GeoSite != disabledGeoURL {
		t.Fatal("geodata network URLs must be fail-closed")
	}
}

func TestNormalizeRawNetworkExtensionSurfacesBeforeParse(t *testing.T) {
	raw := config.DefaultRawConfig()
	raw.MixedPort = 10801
	raw.AllowLan = true
	raw.InboundTfo = true
	raw.InboundMPTCP = true
	raw.Interface = "en0"
	raw.RoutingMark = 666
	raw.FindProcessMode = process.FindProcessStrict
	raw.Tun.AutoRedirect = true
	raw.Tun.IPRoute2TableIndex = 100
	raw.Tun.AutoRedirectInputMark = 42
	raw.Tun.IncludeInterface = []string{"en0"}
	raw.Tun.ExcludeInterface = []string{"en1"}
	raw.Tun.IncludeUID = []uint32{501}
	raw.Tun.ExcludeUID = []uint32{0}
	raw.Tun.IncludeUIDRange = []string{"1000:2000"}
	raw.Tun.ExcludeSrcPort = []uint16{53}
	raw.Tun.ExcludeDstPort = []uint16{443}
	raw.Tun.ExcludeDstPortRange = []string{"3000:4000"}
	raw.Tun.IncludeAndroidUser = []int{0}
	raw.Tun.IncludePackage = []string{"com.example.app"}
	raw.Tun.ExcludePackage = []string{"com.example.other"}
	raw.Tun.IncludeMACAddress = []string{"00:11:22:33:44:55"}
	raw.Tun.ExcludeMACAddress = []string{"66:77:88:99:aa:bb"}
	raw.ExternalUI = "ui"
	raw.ExternalController = "0.0.0.0:9090"
	raw.ExternalControllerUnix = "user.sock"
	raw.Secret = "must-not-survive"
	raw.Listeners = []map[string]any{{"name": "server", "type": "unsupported-test-listener"}}
	raw.DNS.Listen = "0.0.0.0:53"
	raw.DNS.ListenRoutingMark = 666
	raw.NTP.WriteToSystem = true
	raw.Proxy = []map[string]any{{"name": "probe", "type": "socks5", "server": "127.0.0.1", "port": 1080}}
	raw.Rule = []string{"MATCH,probe"}

	normalizeRawConfigForIOS(raw, true)

	// The local proxy surface is honoured now: mixed-port, allow-lan and the inbound socket
	// options belong to the user, and hub/executor opens them. What still goes is the
	// controller surface and the protocol servers -- different decisions, different reasons.
	if raw.MixedPort != 10801 || !raw.InboundTfo || !raw.InboundMPTCP {
		t.Fatalf("the local proxy surface was stripped: mixed-port=%d tfo=%v mptcp=%v",
			raw.MixedPort, raw.InboundTfo, raw.InboundMPTCP)
	}
	// allow-lan alone is gated: the app has not permitted local-network exposure here, and the
	// zero value of that permission is the safe one on purpose.
	if raw.AllowLan {
		t.Fatal("allow-lan survived without the app permitting local-network exposure")
	}
	// The API itself is the user's to ask for now; the dashboard is not, because it would
	// start a download inside the extension (executor.go:457 -> AutoDownloadUI).
	if raw.ExternalController == "" || raw.Secret == "" {
		t.Fatalf("the RESTful API surface was stripped: controller=%q secret set=%v",
			raw.ExternalController, raw.Secret != "")
	}
	// external-ui is honoured: the hold was, not a platform fact.
	if raw.ExternalUI == "" {
		t.Fatal("external-ui was stripped; upstream keeps it and the platform permits it")
	}
	if raw.Interface != "" || raw.RoutingMark != 0 {
		t.Fatalf("Apple-owned egress surface survived: interface=%q mark=%d", raw.Interface, raw.RoutingMark)
	}
	if raw.FindProcessMode != process.FindProcessOff {
		t.Fatalf("find-process-mode not neutralized to Off: %v", raw.FindProcessMode)
	}
	if raw.Tun.AutoRedirect || raw.Tun.IPRoute2TableIndex != 0 || raw.Tun.AutoRedirectInputMark != 0 ||
		len(raw.Tun.IncludeInterface) != 0 || len(raw.Tun.ExcludeInterface) != 0 ||
		len(raw.Tun.IncludeUID) != 0 || len(raw.Tun.ExcludeUID) != 0 || len(raw.Tun.IncludeUIDRange) != 0 ||
		len(raw.Tun.ExcludeSrcPort) != 0 || len(raw.Tun.ExcludeDstPort) != 0 || len(raw.Tun.ExcludeDstPortRange) != 0 ||
		len(raw.Tun.IncludeAndroidUser) != 0 || len(raw.Tun.IncludePackage) != 0 || len(raw.Tun.ExcludePackage) != 0 ||
		len(raw.Tun.IncludeMACAddress) != 0 || len(raw.Tun.ExcludeMACAddress) != 0 {
		t.Fatalf("host-route filter survived NE normalization: %#v", raw.Tun)
	}
	// The listener catalogue is honoured now: upstream allows it, the platform allows it.
	if len(raw.Listeners) == 0 {
		t.Fatal("the listener catalogue was stripped; upstream allows it and so do we")
	}
	if len(raw.Proxy) != 1 || len(raw.Rule) != 1 {
		t.Fatal("data-plane proxy/rule configuration must survive NE normalization")
	}
	if raw.NTP.WriteToSystem {
		t.Fatal("Network Extension must not write the device clock")
	}
}

func TestNormalizeRawConfigForIOSKeepsMetadataRulesInPlace(t *testing.T) {
	raw, err := config.UnmarshalRawConfig([]byte(`
rules:
  - DOMAIN,first.example,DIRECT
  - PROCESS-NAME,curl,REJECT
  - DOMAIN,second.example,REJECT
  - UID,501,REJECT
  - IN-USER,alice,REJECT
  - SOURCE-APP-SIGNING-ID,com.example.cli,REJECT
  - MATCH,DIRECT
sub-rules:
  child:
    - DOMAIN,child-first.example,DIRECT
    - UID,501,REJECT
    - SOURCE-APP-TEAM-ID,ABCDE12345,REJECT
    - DOMAIN,child-second.example,REJECT
rule-providers:
  inline:
    type: inline
    behavior: classical
    payload:
      - PROCESS-NAME,curl
      - DOMAIN,provider.example
      - IN-USER,alice
      - SOURCE-APP-SIGNING-ID,com.example.cli
      - SOURCE-APP-TEAM-ID,ABCDE12345
`))
	if err != nil {
		t.Fatal(err)
	}
	normalizeRawConfigForIOS(raw, true)
	wantRules := []string{
		"DOMAIN,first.example,DIRECT",
		"PROCESS-NAME,curl,REJECT",
		"DOMAIN,second.example,REJECT",
		// UID is gone on purpose -- see uid_construction_gate.go. Everything else stays.
		"IN-USER,alice,REJECT",
		"SOURCE-APP-SIGNING-ID,com.example.cli,REJECT",
		"MATCH,DIRECT",
	}
	if !reflect.DeepEqual(raw.Rule, wantRules) {
		t.Fatalf("rules after normalize = %v, want every rule kept in order %v", raw.Rule, wantRules)
	}
	wantSubRules := []string{
		"DOMAIN,child-first.example,DIRECT",
		"SOURCE-APP-TEAM-ID,ABCDE12345,REJECT",
		"DOMAIN,child-second.example,REJECT",
	}
	if !reflect.DeepEqual(raw.SubRules["child"], wantSubRules) {
		t.Fatalf("sub-rules after normalize = %v, want every rule kept in order %v", raw.SubRules["child"], wantSubRules)
	}
	payload, ok := raw.RuleProvider["inline"]["payload"].([]any)
	wantPayload := []any{
		"PROCESS-NAME,curl", "DOMAIN,provider.example", "IN-USER,alice",
		"SOURCE-APP-SIGNING-ID,com.example.cli", "SOURCE-APP-TEAM-ID,ABCDE12345",
	}
	if !ok || !reflect.DeepEqual(payload, wantPayload) {
		t.Fatalf("inline provider after normalize = %#v, want every entry kept", raw.RuleProvider["inline"]["payload"])
	}
	// Nothing was removed, so every affected rule still has to be findable.
	if summaries := summarizeMetadataRuleOccurrences(raw, nePolicy().processMetadata()); len(summaries) == 0 {
		t.Fatal("the kept metadata rules must still be reported to the reader")
	}
}

func TestNormalizeStripsNEIncompatibleNameservers(t *testing.T) {
	raw := config.DefaultRawConfig()
	raw.DNS.Enable = true
	raw.DNS.NameServer = []string{"223.5.5.5", "system", "dhcp://en0"}
	raw.DNS.Fallback = []string{"system://", "8.8.8.8"}
	raw.DNS.ProxyServerNameserver = []string{"system"}
	raw.DNS.DirectNameServer = []string{"114.114.114.114", "dhcp://system"}
	// default-nameserver is the bootstrap resolver: system/dhcp is stripped like
	// the query slots WHILE a usable pure-IP resolver remains. An all-system/dhcp
	// bootstrap (no usable IP left) is kept verbatim with a kept-warning; what
	// happens then is mihomo's call (system loads, dhcp fails its pure-IP check).
	raw.DNS.DefaultNameserver = []string{"223.5.5.5", "system"}

	normalizeRawConfigForIOS(raw, true)

	if got := raw.DNS.NameServer; len(got) != 1 || got[0] != "223.5.5.5" {
		t.Fatalf("nameserver system/dhcp not stripped: %v", got)
	}
	if got := raw.DNS.Fallback; len(got) != 1 || got[0] != "8.8.8.8" {
		t.Fatalf("fallback system not stripped: %v", got)
	}
	if len(raw.DNS.ProxyServerNameserver) != 0 {
		t.Fatalf("proxy-server-nameserver system not stripped: %v", raw.DNS.ProxyServerNameserver)
	}
	if got := raw.DNS.DirectNameServer; len(got) != 1 || got[0] != "114.114.114.114" {
		t.Fatalf("direct-nameserver dhcp not stripped: %v", got)
	}
	if got := raw.DNS.DefaultNameserver; len(got) != 1 || got[0] != "223.5.5.5" {
		t.Fatalf("default-nameserver system not stripped while a usable IP remains: %v", got)
	}
}

func TestNormalizeRealBootstrapStripsSystemKeepsIPs(t *testing.T) {
	// A widespread real shape: system leads a list of usable bootstrap IPs.
	// Strip the system entry, keep every IP including IPv6.
	raw := &config.RawConfig{}
	raw.DNS.Enable = true
	raw.DNS.NameServer = []string{"223.5.5.5"}
	raw.DNS.DefaultNameserver = []string{"system", "180.76.76.76", "182.254.118.118", "8.8.8.8", "180.184.2.2", "2400:3200::1"}

	normalizeRawConfigForIOS(raw, true)

	want := []string{"180.76.76.76", "182.254.118.118", "8.8.8.8", "180.184.2.2", "2400:3200::1"}
	got := raw.DNS.DefaultNameserver
	if len(got) != len(want) {
		t.Fatalf("bootstrap not stripped to the 5 IPs: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("bootstrap entry %d = %q, want %q (full: %v)", i, got[i], want[i], got)
		}
	}
}

func TestAllSystemBootstrapPassesStripSilentlyThenRepairReports(t *testing.T) {
	// Two stages, one story. The strip declines to touch an all-system
	// bootstrap (stripping to [] would trip mihomo's "at least one nameserver"
	// rule, config/config.go:1453-1454) and says NOTHING about it -- the "kept
	// as written, your nameservers may fail" warning that used to fire here was
	// falsified one line later by the repair, every time, because the repair
	// runs for every Apple packet tunnel and removes exactly those entries.
	// The repair's own description is the user-facing report,'s
	// no-silent-no-op requirement is satisfied by it.
	raw := &config.RawConfig{}
	raw.DNS.Enable = true
	raw.DNS.NameServer = []string{"223.5.5.5"}
	raw.DNS.DefaultNameserver = []string{"system"}

	stripped := stripNEIncompatibleNameservers(raw)
	for _, entry := range stripped {
		if strings.Contains(entry, "default-nameserver") {
			t.Fatalf("the strip must not claim the bootstrap entry: %v", stripped)
		}
	}
	if got := raw.DNS.DefaultNameserver; len(got) != 1 || got[0] != "system" {
		t.Fatalf("strip stage must hand the bootstrap through verbatim, got: %v", got)
	}

	repairs := repairApplePacketTunnelDNS(raw)
	reported := false
	for _, repair := range repairs {
		if strings.Contains(repair, "default-nameserver") && strings.Contains(repair, "replaced") {
			reported = true
		}
	}
	if !reported {
		t.Fatalf("the repair must report the substitution: %v", repairs)
	}
	want := config.DefaultRawConfig().DNS.DefaultNameserver
	if strings.Join(raw.DNS.DefaultNameserver, ",") != strings.Join(want, ",") {
		t.Fatalf("bootstrap after repair = %v, want mihomo defaults %v", raw.DNS.DefaultNameserver, want)
	}
}

func TestNormalizeKeepsNECompatibleDNSTypes(t *testing.T) {
	// mihomo has 10 DNS server types (config.go parseNameServer): udp, tcp, tls,
	// http/https, quic, system, ts/tailscale, dhcp, rcode, and bare. Only system
	// and dhcp are NE-incompatible; every other type resolves through the core
	// and must survive the tolerate+strip pass unchanged. This locks that the
	// scheme strip never over-reaches.
	raw := &config.RawConfig{}
	raw.DNS.Enable = true
	compatible := []string{
		"1.1.1.1", "udp://8.8.8.8", "tcp://9.9.9.9", "tls://223.5.5.5",
		"https://1.1.1.1/dns-query", "quic://8.8.4.4", "tailscale://ts-node",
		"rcode://success", "https://dns.google/dns-query",
		"https://1.1.1.1/dns-query#system", // fragment contains "system", NOT the scheme
	}
	raw.DNS.NameServer = append([]string(nil), compatible...)
	// Only system + dhcp are stripped; the tls entry between them survives.
	raw.DNS.Fallback = []string{"system", "tls://1.1.1.1", "dhcp://en0"}
	normalizeRawConfigForIOS(raw, true)
	if strings.Join(raw.DNS.NameServer, ",") != strings.Join(compatible, ",") {
		t.Errorf("NE-compatible DNS types must survive unchanged, got: %v", raw.DNS.NameServer)
	}
	if got := raw.DNS.Fallback; len(got) != 1 || got[0] != "tls://1.1.1.1" {
		t.Errorf("only system/dhcp must be stripped from fallback (tls kept), got: %v", got)
	}
}

func TestIsUsableBootstrapNameserver(t *testing.T) {
	cases := map[string]bool{
		"223.5.5.5": true, "223.5.5.5:53": true, "8.8.8.8": true,
		"2400:3200::1": true, "[2400:3200::1]:53": true,
		"tls://223.5.5.5": true, "udp://8.8.8.8:53": true,
		// scheme forms whose host is an IP — mihomo accepts these (a path or
		// port must not defeat the check):
		"https://1.1.1.1/dns-query": true, "tls://1.1.1.1:853": true,
		"quic://[2400:3200::1]:853": true, "https://[2606:4700:4700::1111]/dns-query": true,
		// not a usable pure-IP bootstrap:
		"system": false, "system://": false, "dhcp://en0": false,
		"": false, "   ": false, ":53": false, "udp://:53": false,
		"dns.google": false, "https://dns.google/dns-query": false,
	}
	for in, want := range cases {
		if got := isUsableBootstrapNameserver(in); got != want {
			t.Errorf("isUsableBootstrapNameserver(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestNormalizeBootstrapRequiresUsableIP(t *testing.T) {
	// A bootstrap of system + only junk has nothing a packet tunnel can
	// bootstrap from. filterBootstrap still keeps it verbatim rather than
	// stripping to [] — that would trip mihomo's "at least one nameserver"
	// rule (config/config.go:1453-1454) — but the repair then removes the
	// system/dhcp entries and, if nothing is left, substitutes mihomo's own
	// explicit defaults. Junk that is not system/dhcp survives both stages and
	// mihomo passes its own verdict on it, which is the point: we predict
	// upstream's answer, we do not invent one.
	defaults := config.DefaultRawConfig().DNS.DefaultNameserver
	for _, tc := range []struct {
		in   []string
		want []string
	}{
		{[]string{"system", ""}, []string{""}},
		{[]string{"system", "udp://:53"}, []string{"udp://:53"}},
		{[]string{"system", "dhcp://en0"}, defaults},
		{[]string{"system"}, defaults},
	} {
		raw := &config.RawConfig{}
		raw.DNS.Enable = true
		raw.DNS.NameServer = []string{"223.5.5.5"}
		raw.DNS.DefaultNameserver = append([]string(nil), tc.in...)
		normalizeRawConfigForIOS(raw, true)
		if strings.Join(raw.DNS.DefaultNameserver, ",") != strings.Join(tc.want, ",") {
			t.Errorf("bootstrap %v became %v, want %v", tc.in, raw.DNS.DefaultNameserver, tc.want)
		}
	}
	// system + junk + a usable IP: strip the incompatible entry, keep the IP.
	raw := &config.RawConfig{}
	raw.DNS.Enable = true
	raw.DNS.NameServer = []string{"223.5.5.5"}
	raw.DNS.DefaultNameserver = []string{"system", "8.8.8.8"}
	normalizeRawConfigForIOS(raw, true)
	got := raw.DNS.DefaultNameserver
	if len(got) != 1 || got[0] != "8.8.8.8" {
		t.Fatalf("bootstrap with a usable IP must strip system and keep the IP, got %v", got)
	}
}

func TestNormalizeStripsOutboundEgressOverrides(t *testing.T) {
	content := `
proxies:
  - {name: node, type: socks5, server: 127.0.0.1, port: 1080, interface-name: en0, routing-mark: 233}
proxy-groups:
  - {name: group, type: select, proxies: [node], interface-name: en1}
proxy-providers:
  inline:
    type: inline
    payload:
      - {name: pnode, type: socks5, server: 127.0.0.1, port: 1081, routing-mark: 7}
`
	raw, err := config.UnmarshalRawConfig([]byte(content))
	if err != nil {
		t.Fatal(err)
	}
	normalizeRawConfigForIOS(raw, true)

	if _, ok := raw.Proxy[0]["interface-name"]; ok {
		t.Fatalf("proxy interface-name not stripped: %v", raw.Proxy[0])
	}
	if _, ok := raw.Proxy[0]["routing-mark"]; ok {
		t.Fatalf("proxy routing-mark not stripped: %v", raw.Proxy[0])
	}
	if _, ok := raw.ProxyGroup[0]["interface-name"]; ok {
		t.Fatalf("group interface-name not stripped: %v", raw.ProxyGroup[0])
	}
	payload := providerPayloadMappings(raw.ProxyProvider["inline"]["payload"])
	if len(payload) != 1 {
		t.Fatalf("provider payload missing after normalize: %v", raw.ProxyProvider["inline"])
	}
	if _, ok := payload[0]["routing-mark"]; ok {
		t.Fatalf("provider payload routing-mark not stripped: %v", payload[0])
	}
	// The proxy itself must survive — only the egress override is stripped.
	if len(raw.Proxy) != 1 || raw.Proxy[0]["name"] != "node" {
		t.Fatalf("proxy must survive egress-override strip: %v", raw.Proxy)
	}
}

func TestParseConfigForNetworkExtensionIgnoresNonRoutingServerCatalog(t *testing.T) {
	setupConfigPipelineTest(t)
	cfg, err := parseConfigForIOS(`
mixed-port: 10801
allow-lan: true
external-controller: 0.0.0.0:9090
external-controller-unix: user.sock
external-ui: ui
secret: do-not-expose
listeners:
  - name: invalid-server
    type: mixed
    port: 7899
tunnels:
  - tcp,127.0.0.1:6553,example.com:53,probe
dns:
  enable: true
  listen: 0.0.0.0:53
  listen-routing-mark: 666
  nameserver: [1.1.1.1]
ntp:
  enable: true
  server: time.apple.com
  port: 123
  interval: 30
  write-to-system: true
proxies:
  - name: probe
    type: socks5
    server: 127.0.0.1
    port: 1080
rules:
  - MATCH,probe
`, true)
	if err != nil {
		t.Fatalf("a valid listener catalogue must parse: %v", err)
	}
	// mixed-port and allow-lan reach the parsed config now: the local proxy is the user's to
	// ask for. The DNS server surface and the Apple-owned egress fields still close.
	if cfg.General.MixedPort == 0 {
		t.Fatalf("the local proxy surface did not reach the parsed config: general=%+v", cfg.General)
	}
	if cfg.General.AllowLan {
		t.Fatal("allow-lan reached the parsed config without the app permitting exposure")
	}
	if cfg.General.Interface != "" || cfg.General.RoutingMark != 0 || cfg.DNS.ListenRoutingMark != 0 {
		t.Fatalf("parsed NE surface not closed: general=%+v dns=%+v", cfg.General, cfg.DNS)
	}
	// dns.listen is honoured now. What closes here is only what has nowhere to land on Darwin.
	if cfg.DNS.Listen != "0.0.0.0:53" {
		t.Fatalf("dns.listen did not reach the parsed config: %q", cfg.DNS.Listen)
	}
	if cfg.NTP == nil || !cfg.NTP.Enable || cfg.NTP.WriteToSystem {
		t.Fatalf("NTP offset service must survive without system-clock writes: %+v", cfg.NTP)
	}
	// Listeners and tunnels reach the parsed config now: upstream allows them and the platform
	// allows them, so this core does too. What the parser still refuses is what upstream
	// refuses -- an unknown listener type, a tunnel naming a proxy that does not exist -- and
	// that is parity, not a rule of ours.
	if len(cfg.Listeners) == 0 || len(cfg.Tunnels) == 0 {
		t.Fatalf("the listener/tunnel catalogue was stripped: %v / %v", cfg.Listeners, cfg.Tunnels)
	}
	if _, ok := cfg.Proxies["probe"]; !ok {
		t.Fatal("outbound proxy was removed with server surfaces")
	}
}

func TestParseConfigForNetworkExtensionPreservesCoreCatalog(t *testing.T) {
	setupConfigPipelineTest(t)
	cfg, err := parseConfigForIOS(`
mode: rule
ipv6: true
unified-delay: true
tcp-concurrent: true
profile:
  store-selected: true
  store-fake-ip: true
hosts:
  example.internal: 192.0.2.1
dns:
  enable: true
  enhanced-mode: fake-ip
  nameserver: [1.1.1.1]
  nameserver-policy:
    "domain:example.com": [tls://1.1.1.1:853]
sniffer:
  enable: true
  sniff:
    HTTP:
      ports: [80, 8080-8880]
      override-destination: true
proxy-providers:
  local-proxies:
    type: inline
    payload:
      - {name: provider-probe, type: socks5, server: 127.0.0.1, port: 1080}
proxy-groups:
  - name: SELECT
    type: select
    use: [local-proxies]
  - name: URL-TEST
    type: url-test
    proxies: [DIRECT]
    url: http://127.0.0.1/generate_204
  - name: FALLBACK
    type: fallback
    proxies: [DIRECT]
    url: http://127.0.0.1/generate_204
  - name: LOAD-BALANCE
    type: load-balance
    proxies: [DIRECT]
    url: http://127.0.0.1/generate_204
    strategy: round-robin
rule-providers:
  local-rules:
    type: inline
    behavior: domain
    payload: [+.example.com]
sub-rules:
  private:
    - DOMAIN-SUFFIX,internal,DIRECT
    - MATCH,SELECT
ntp:
  enable: true
  server: time.apple.com
  port: 123
  interval: 30
  dialer-proxy: SELECT
  write-to-system: true
experimental:
  quic-go-disable-gso: true
  quic-go-disable-ecn: true
rules:
  - SUB-RULE,(OR,((NETWORK,TCP),(NETWORK,UDP))),private
  - RULE-SET,local-rules,SELECT
  - MATCH,DIRECT
`, true)
	if err != nil {
		t.Fatalf("core catalog parse failed: %v", err)
	}
	for _, name := range []string{"SELECT", "URL-TEST", "FALLBACK", "LOAD-BALANCE"} {
		if _, ok := cfg.Proxies[name]; !ok {
			t.Errorf("proxy group %q was removed", name)
		}
	}
	if _, ok := cfg.Providers["local-proxies"]; !ok {
		t.Fatal("inline proxy provider was removed")
	}
	if _, ok := cfg.RuleProviders["local-rules"]; !ok {
		t.Fatal("inline rule provider was removed")
	}
	if len(cfg.SubRules["private"]) != 2 || len(cfg.Rules) != 3 {
		t.Fatalf("rules/sub-rules were not preserved: rules=%d sub=%d", len(cfg.Rules), len(cfg.SubRules["private"]))
	}
	if cfg.DNS == nil || cfg.DNS.FakeIPPool == nil || len(cfg.DNS.NameServerPolicy) != 1 {
		t.Fatalf("DNS policy/fake-IP was not preserved: %+v", cfg.DNS)
	}
	if cfg.Sniffer == nil || !cfg.Sniffer.Enable {
		t.Fatalf("sniffer was not preserved: %+v", cfg.Sniffer)
	}
	if cfg.Profile == nil || !cfg.Profile.StoreSelected || !cfg.Profile.StoreFakeIP {
		t.Fatalf("profile settings were not preserved/normalized: %+v", cfg.Profile)
	}
	if cfg.NTP == nil || !cfg.NTP.Enable || cfg.NTP.DialerProxy != "SELECT" || cfg.NTP.WriteToSystem {
		t.Fatalf("NTP data plane was not preserved safely: %+v", cfg.NTP)
	}
	if cfg.Experimental == nil || !cfg.Experimental.QUICGoDisableGSO || !cfg.Experimental.QUICGoDisableECN {
		t.Fatalf("experimental transport settings were not preserved: %+v", cfg.Experimental)
	}
}

func TestParseConfigForIOSLoadsClientStagedFileProviders(t *testing.T) {
	working := setupConfigPipelineTest(t)
	providers := filepath.Join(working, "providers")
	if err := os.MkdirAll(providers, 0o700); err != nil {
		t.Fatalf("mkdir providers: %v", err)
	}
	if err := os.WriteFile(filepath.Join(providers, "proxies.yaml"), []byte(`
proxies:
  - {name: file-probe, type: socks5, server: 127.0.0.1, port: 1080}
`), 0o600); err != nil {
		t.Fatalf("write proxy provider: %v", err)
	}
	if err := os.WriteFile(filepath.Join(providers, "rules.yaml"), []byte(`
payload:
  - +.example.org
`), 0o600); err != nil {
		t.Fatalf("write rule provider: %v", err)
	}

	cfg, err := parseConfigForIOS(`
dns:
  enable: true
  nameserver: [1.1.1.1]
proxy-providers:
  staged-proxies:
    type: file
    path: ./providers/proxies.yaml
proxy-groups:
  - name: SELECT
    type: select
    use: [staged-proxies]
rule-providers:
  staged-rules:
    type: file
    behavior: domain
    path: ./providers/rules.yaml
rules:
  - RULE-SET,staged-rules,SELECT
  - MATCH,DIRECT
`, true)
	if err != nil {
		t.Fatalf("parse staged providers: %v", err)
	}
	proxyProvider := cfg.Providers["staged-proxies"]
	if proxyProvider == nil {
		t.Fatal("staged proxy provider missing")
	}
	if err := proxyProvider.Initial(); err != nil {
		t.Fatalf("load staged proxy provider: %v", err)
	}
	if proxyProvider.Count() != 1 {
		t.Fatalf("staged proxy count = %d, want 1", proxyProvider.Count())
	}
	ruleProvider := cfg.RuleProviders["staged-rules"]
	if ruleProvider == nil {
		t.Fatal("staged rule provider missing")
	}
	if err := ruleProvider.Initial(); err != nil {
		t.Fatalf("load staged rule provider: %v", err)
	}
	if ruleProvider.Count() != 1 {
		t.Fatalf("staged rule count = %d, want 1", ruleProvider.Count())
	}
}

func TestParseConfigForIOSHonorsExplicitStoreFakeIPFalse(t *testing.T) {
	setupConfigPipelineTest(t)
	// A user who sets store-fake-ip:false wants a bounded in-memory fake-ip pool,
	// not an unbounded on-disk record of every resolved domain. Upstream defaults
	// it false and honors an explicit value; forcing it true would silently
	// override a deliberate privacy choice. Restart-consistency is a soft UX
	// preference, not a platform requirement, so an explicit value wins.
	cfg, err := parseConfigForIOS(`
mode: rule
profile:
  store-fake-ip: false
dns:
  enable: true
  enhanced-mode: fake-ip
  nameserver: [1.1.1.1]
rules:
  - MATCH,DIRECT
`, false)
	if err != nil {
		t.Fatalf("parseConfigForIOS: %v", err)
	}
	if cfg.Profile == nil || cfg.Profile.StoreFakeIP {
		t.Fatal("explicit store-fake-ip:false must be honored, not forced to true")
	}
}

func TestParseConfigForIOSForcesFakeIPPersistence(t *testing.T) {
	setupConfigPipelineTest(t)
	cfg, err := parseConfigForIOS(`
mode: rule
dns:
  enable: true
  enhanced-mode: fake-ip
  nameserver: [1.1.1.1]
rules:
  - MATCH,DIRECT
`, false)
	if err != nil {
		t.Fatalf("parseConfigForIOS: %v", err)
	}
	if cfg.Profile == nil || !cfg.Profile.StoreFakeIP {
		t.Fatal("parsed profile must record forced fake-IP persistence")
	}
	if cfg.DNS == nil || cfg.DNS.FakeIPPool == nil {
		t.Fatal("expected a fake-IP pool")
	}
}

func TestParseConfigForIOSRejectsRemoteProviderBeforeParse(t *testing.T) {
	setupConfigPipelineTest(t)
	_, err := parseConfigForIOS(`
proxy-providers:
  remote:
    type: http
    url: https://example.invalid/provider.yaml
    path: ./providers/remote.yaml
rules:
  - MATCH,DIRECT
`, false)
	if err == nil || !strings.Contains(err.Error(), "pre-download") {
		t.Fatalf("remote provider error = %v", err)
	}
}

func TestParseConfigForIOSUsesStableRemoteProviderPriority(t *testing.T) {
	setupConfigPipelineTest(t)
	_, err := parseConfigForIOS(`
proxy-providers:
  zebra: {type: http, url: https://example.com/zebra.yaml}
  alpha: {type: http, url: https://example.com/alpha.yaml}
rule-providers:
  aardvark: {type: http, behavior: domain, url: https://example.com/rules.yaml}
rules:
  - MATCH,DIRECT
`, false)
	if err == nil || !strings.Contains(err.Error(), `proxy-provider "alpha"`) {
		t.Fatalf("first remote provider error = %v, want proxy-provider alpha", err)
	}
}

func TestParseConfigForIOSRejectsUnsafeProviderHealthCheckDurations(t *testing.T) {
	// timeout came off this list on 2026-08-27. Upstream accepts a negative or
	// overflowing one (measured against config.ParseRawConfig) and
	// adapter/provider/parser.go:71 converts it to uint before NewHealthCheck,
	// so it becomes a very long timeout rather than a failure -- it costs that
	// provider's health results, not the configuration.
	//
	// interval stays for a reason that is NOT "upstream refuses it": upstream
	// accepts it too. It reaches time.NewTicker (healthcheck.go:47) through the
	// same conversion, and what a huge duration does there is unmeasured. This
	// list is what the tree currently refuses, not what it has proven it must.
	tests := map[string]string{
		"negative interval":    "interval: -1",
		"overflowing interval": "interval: 9223372037",
	}
	for name, timing := range tests {
		t.Run(name, func(t *testing.T) {
			setupConfigPipelineTest(t)
			_, err := parseConfigForIOS(`
proxy-providers:
  local:
    type: inline
    health-check:
      enable: true
      url: https://example.com/generate_204
      `+timing+`
    payload:
      - {name: probe, type: socks5, server: 127.0.0.1, port: 1080}
proxy-groups:
  - {name: SELECT, type: select, use: [local]}
dns:
  enable: true
  nameserver: [1.1.1.1]
rules:
  - MATCH,SELECT
`, true)
			if err == nil || !strings.Contains(err.Error(), "proxy-provider \"local\" health-check") {
				t.Fatalf("unsafe health-check duration error = %v", err)
			}
		})
	}
}

func TestParseConfigForIOSRejectsInvalidProxyGroupRegexWithoutPanicking(t *testing.T) {
	tests := map[string]string{
		"filter":         "filter: '('",
		"exclude-filter": "exclude-filter: '['",
	}
	for field, expression := range tests {
		t.Run(field, func(t *testing.T) {
			setupConfigPipelineTest(t)
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("iOS preflight panicked for invalid %s: %v", field, recovered)
				}
			}()
			_, err := parseConfigForIOS(`
proxy-groups:
  - name: TEST
    type: url-test
    proxies: [DIRECT]
    url: https://example.com/generate_204
    `+expression+`
dns:
  enable: true
  nameserver: [1.1.1.1]
rules:
  - MATCH,TEST
`, true)
			if err == nil || !strings.Contains(err.Error(), "proxy-groups[0]."+field) {
				t.Fatalf("invalid proxy-group %s error = %v", field, err)
			}
		})
	}
}

func TestParseConfigForIOSAllowsUnusedHysteriaHopIntervalWithoutPorts(t *testing.T) {
	setupConfigPipelineTest(t)
	_, err := parseConfigForIOS(`
proxies:
  - name: HY
    type: hysteria
    server: 127.0.0.1
    port: 443
    auth-str: fixture
    up: 10 Mbps
    down: 10 Mbps
    hop-interval: -1
dns:
  enable: true
  nameserver: [1.1.1.1]
rules:
  - MATCH,HY
`, true)
	if err != nil {
		t.Fatalf("unused Hysteria hop interval was rejected: %v", err)
	}
}

func TestParseConfigForIOSAllowsUnusedHysteriaHopIntervalForNonUDPProtocol(t *testing.T) {
	setupConfigPipelineTest(t)
	_, err := parseConfigForIOS(`
proxies:
  - name: HY
    type: hysteria
    server: 127.0.0.1
    port: 443
    ports: 443-444
    protocol: wechat-video
    auth-str: fixture
    up: 10 Mbps
    down: 10 Mbps
    hop-interval: -1
dns:
  enable: true
  nameserver: [1.1.1.1]
rules:
  - MATCH,HY
`, true)
	if err != nil {
		t.Fatalf("unused non-UDP Hysteria hop interval was rejected: %v", err)
	}
}

func TestParseConfigForIOSAllowsTUICV5UnusedRequestTimeout(t *testing.T) {
	setupConfigPipelineTest(t)
	_, err := parseConfigForIOS(`
proxies:
  - name: TUIC
    type: tuic
    server: 127.0.0.1
    port: 443
    uuid: 00000000-0000-0000-0000-000000000001
    password: fixture
    request-timeout: -1
    skip-cert-verify: true
dns:
  enable: true
  nameserver: [1.1.1.1]
rules:
  - MATCH,TUIC
`, true)
	if err != nil {
		t.Fatalf("TUIC v5 unused request-timeout was rejected: %v", err)
	}
}

func TestParseConfigForIOSPreservesDisabledGlobalDurationSemantics(t *testing.T) {
	setupConfigPipelineTest(t)
	_, err := parseConfigForIOS(`
keep-alive-idle: -1
keep-alive-interval: -1
ntp:
  enable: false
  interval: 9223372036854775807
tun:
  udp-timeout: -1
  icmp-timeout: -1
dns:
  enable: true
  nameserver: [1.1.1.1]
rules:
  - MATCH,DIRECT
`, true)
	if err != nil {
		t.Fatalf("disabled/non-positive global duration semantics rejected: %v", err)
	}
}

func TestParseConfigForIOSIgnoresFakeIPTTLInNormalMode(t *testing.T) {
	setupConfigPipelineTest(t)
	_, err := parseConfigForIOS(`
dns:
  enable: true
  enhanced-mode: normal
  fake-ip-ttl: 9223372036854775807
  nameserver: [1.1.1.1]
rules:
  - MATCH,DIRECT
`, true)
	if err != nil {
		t.Fatalf("unconsumed normal-mode fake-IP TTL rejected: %v", err)
	}
}

func TestParseConfigForIOSRejectsMissingGeodataBeforeCoreParse(t *testing.T) {
	working := setupConfigPipelineTest(t)
	_, err := parseConfigForIOS(`
mode: rule
rules:
  - GEOIP,CN,DIRECT
  - MATCH,DIRECT
`, false)
	if err == nil || !strings.Contains(err.Error(), "not pre-staged") {
		t.Fatalf("missing geodata error = %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(working, "geoip.metadb")); !os.IsNotExist(statErr) {
		t.Fatalf("parse attempted to create/download geodata: %v", statErr)
	}
}

func setupConfigPipelineTest(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	working := filepath.Join(base, "working")
	if err := Setup(&SetupOptions{
		BasePath:    base,
		WorkingPath: working,
		TempPath:    filepath.Join(base, "temp"),
	}); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	return working
}

// A dhcp:// or system:// nameserver must not refuse the configuration. Upstream
// carries both as ordinary transports and reports their failure per query, never
// at load: a DHCP probe that gets no answer returns ErrNotResponding
// (component/dhcp/dhcp.go:15) from the resolver, and dns.ParseNameServer accepts
// both schemes without consulting the platform. sing-box, which does compile its
// DHCP transport into the Apple build (cmd/internal/build_libbox/main.go:67 adds
// with_dhcp to darwinTags), takes the same line the other way round: its Start()
// logs a failed interface fetch from a goroutine and returns nil regardless
// (dns/transport/dhcp/dhcp.go:95-113), and the build without the tag errors at
// transport CONSTRUCTION with "rebuild with -tags with_dhcp"
// (include/dhcp_stub.go) -- an actionable message at the point of use, not a
// refusal to load the profile.
//
// Neither scheme is a platform prohibition, which is what our message claimed.
// What is true is narrower and belongs to the transport, not the sandbox:
// mihomo's DHCP client binds 0.0.0.0:68 (component/dhcp/conn.go:13), a
// privileged port that no unprivileged Apple process can bind -- the containing
// App as much as the extension. That is a reason to strip and warn, which the
// packet-tunnel path already does; it was never a reason to refuse to start.
func TestDHCPAndSystemNameserversDoNotRefuseTheConfig(t *testing.T) {
	const content = `
dns:
  enable: true
  nameserver: [223.5.5.5, "dhcp://en0", "system://"]
rules:
  - MATCH,DIRECT
`
	// Outside the extension nothing is stripped, so validation sees both schemes
	// verbatim. This is the seam that used to refuse: service.go:174 passes
	// platform.UnderNetworkExtension(), and a packet-tunnel profile evaluated
	// from the App process has networkExtension false and so never strips.
	outside, err := parseConfigForIOS(content, false)
	if err != nil {
		t.Fatalf("dhcp://+system:// refused the config outside the extension: %v", err)
	}
	if got := len(outside.DNS.NameServer); got != 3 {
		t.Errorf("outside the extension the resolvers should be kept verbatim, got %d of 3", got)
	}

	// Inside the extension they are stripped with a warning and the config still
	// starts -- tolerate + strip, unchanged.
	inside, err := parseConfigForIOS(content, true)
	if err != nil {
		t.Fatalf("dhcp://+system:// refused the config inside the extension: %v", err)
	}
	if got := len(inside.DNS.NameServer); got != 1 {
		t.Fatalf("inside the extension only the explicit resolver should survive, got %d of 1", got)
	}
	if addr := inside.DNS.NameServer[0].Addr; addr != "223.5.5.5:53" {
		t.Errorf("the surviving resolver is not the explicit one: %q", addr)
	}
}

// The privacy ruling that store-fake-ip's explicit value wins used to cost a
// second full YAML parse of the whole configuration -- 18ms of a 529ms
// startup on a 578KB profile -- because RawProfile.StoreFakeIP is a bool and
// an absent key is indistinguishable from an explicit false once decoded.
// RawProfile now records presence during the one parse that already happens.
func TestRawProfileRecordsWhetherStoreFakeIPWasWritten(t *testing.T) {
	for _, item := range []struct {
		name  string
		yaml  string
		set   bool
		value bool
	}{
		{"absent entirely", "mode: rule\n", false, false},
		{"profile without the key", "profile:\n  store-selected: true\n", false, false},
		{"explicit false", "profile:\n  store-fake-ip: false\n", true, false},
		{"explicit true", "profile:\n  store-fake-ip: true\n", true, true},
		// A merge key can carry the field in from an anchor, and resolving
		// that here would mean walking the document again. Presence is
		// assumed instead: the cost of guessing wrong is forcing persistence
		// over a deliberate privacy choice, and the cost of assuming is one
		// profile that keeps mihomo's own default.
		{"merge key", "defaults: &d\n  store-fake-ip: false\nprofile:\n  <<: *d\n", true, false},
	} {
		t.Run(item.name, func(t *testing.T) {
			raw, err := config.UnmarshalRawConfig([]byte(item.yaml))
			if err != nil {
				t.Fatalf("UnmarshalRawConfig: %v", err)
			}
			if raw.Profile.StoreFakeIPSet != item.set {
				t.Fatalf("StoreFakeIPSet = %v, want %v", raw.Profile.StoreFakeIPSet, item.set)
			}
			if raw.Profile.StoreFakeIP != item.value {
				t.Fatalf("StoreFakeIP = %v, want %v", raw.Profile.StoreFakeIP, item.value)
			}
		})
	}
}

// The defaults DefaultRawConfig installs must survive a profile block that
// names only its sibling.
func TestRawProfileKeepsDefaultsForKeysTheDocumentOmits(t *testing.T) {
	base, err := config.UnmarshalRawConfig([]byte("mode: rule\n"))
	if err != nil {
		t.Fatal(err)
	}
	withProfile, err := config.UnmarshalRawConfig([]byte("profile:\n  store-fake-ip: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if withProfile.Profile.StoreSelected != base.Profile.StoreSelected {
		t.Fatalf("store-selected default lost: %v != %v",
			withProfile.Profile.StoreSelected, base.Profile.StoreSelected)
	}
}
