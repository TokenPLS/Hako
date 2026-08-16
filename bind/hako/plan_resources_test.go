package hako

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
)

type planResult struct {
	SchemaVersion int `json:"schemaVersion"`
	Providers     []struct {
		Name, Kind, ResourceKey, Behavior, Type, URL, Path, Format, Proxy string
		Headers                                                           map[string][]string
		MaximumBytes                                                      int64
		UpdateIntervalSeconds                                             int64
	} `json:"providers"`
	Geodata []struct {
		Kind, URL, Format, Path string
		MaximumBytes            int64
	} `json:"geodata"`
	Notices []string                         `json:"notices"`
	Errors  []struct{ Field, Reason string } `json:"errors"`
}

func TestPlanNamespacesSameNamedProxyAndRuleProviders(t *testing.T) {
	r := planOf(t, `
proxy-providers:
  shared: {type: http, url: https://example.com/proxies.yaml}
rule-providers:
  shared: {type: http, behavior: domain, url: https://example.com/rules.yaml}
`)
	if r.SchemaVersion != resourcePlanSchemaVersion || len(r.Providers) != 2 {
		t.Fatalf("plan = %+v", r)
	}
	if r.Providers[0].ResourceKey != "proxy:shared" || r.Providers[1].ResourceKey != "rule:shared" {
		t.Fatalf("resource keys = %q / %q", r.Providers[0].ResourceKey, r.Providers[1].ResourceKey)
	}
	if r.Providers[0].Path == r.Providers[1].Path {
		t.Fatalf("same-named provider paths collided: %q", r.Providers[0].Path)
	}
}

func TestPlanSortsProvidersByNamespaceAndName(t *testing.T) {
	r := planOf(t, `
proxy-providers:
  zebra: {type: http, url: https://example.com/zebra.yaml}
  alpha: {type: http, url: https://example.com/alpha.yaml}
rule-providers:
  zebra: {type: http, behavior: domain, url: https://example.com/zebra-rules.yaml}
  alpha: {type: http, behavior: domain, url: https://example.com/alpha-rules.yaml}
`)
	keys := make([]string, 0, len(r.Providers))
	for _, provider := range r.Providers {
		keys = append(keys, provider.ResourceKey)
	}
	want := []string{"proxy:alpha", "proxy:zebra", "rule:alpha", "rule:zebra"}
	if !slices.Equal(keys, want) {
		t.Fatalf("provider order = %v, want %v", keys, want)
	}
}

func TestPlanCarriesEffectiveProviderSizeLimit(t *testing.T) {
	r := planOf(t, `
rule-providers:
  small:
    type: http
    behavior: domain
    url: https://example.com/small.yaml
    size-limit: 10240
  bounded:
    type: http
    behavior: domain
    url: https://example.com/bounded.yaml
    size-limit: 33554432
  default:
    type: http
    behavior: domain
    url: https://example.com/default.yaml
`)
	if len(r.Providers) != 3 {
		t.Fatalf("providers = %+v; errors = %+v", r.Providers, r.Errors)
	}
	limits := map[string]int64{}
	for _, provider := range r.Providers {
		limits[provider.Name] = provider.MaximumBytes
	}
	if limits["small"] != 10_240 ||
		limits["bounded"] != maximumProviderResourceBytes ||
		limits["default"] != maximumProviderResourceBytes {
		t.Fatalf("effective provider limits = %+v", limits)
	}
}

func TestPlanRejectsNegativeProviderSizeLimit(t *testing.T) {
	r := planOf(t, `
proxy-providers:
  invalid:
    type: http
    url: https://example.com/proxies.yaml
    size-limit: -1
`)
	if len(r.Errors) != 1 || r.Errors[0].Field != "proxy-providers.invalid.size-limit" {
		t.Fatalf("negative size-limit errors = %+v", r.Errors)
	}
}

func TestPlanCarriesProviderUpdateInterval(t *testing.T) {
	r := planOf(t, `
proxy-providers:
  scheduled:
    type: http
    url: https://example.com/proxies.yaml
    interval: 3600
rule-providers:
  manual:
    type: http
    behavior: domain
    url: https://example.com/rules.yaml
`)
	if len(r.Providers) != 2 {
		t.Fatalf("providers = %+v; errors = %+v", r.Providers, r.Errors)
	}
	if r.Providers[0].UpdateIntervalSeconds != 3600 || r.Providers[1].UpdateIntervalSeconds != 0 {
		t.Fatalf("provider intervals = %d / %d", r.Providers[0].UpdateIntervalSeconds, r.Providers[1].UpdateIntervalSeconds)
	}
}

func TestPlanRejectsNegativeProviderUpdateInterval(t *testing.T) {
	r := planOf(t, `
rule-providers:
  invalid:
    type: http
    behavior: domain
    url: https://example.com/rules.yaml
    interval: -1
`)
	if len(r.Errors) != 1 || r.Errors[0].Field != "rule-providers.invalid.interval" {
		t.Fatalf("negative interval errors = %+v", r.Errors)
	}
}

func TestPlanRejectsProviderUpdateIntervalThatOverflowsTimeDuration(t *testing.T) {
	r := planOf(t, `
proxy-providers:
  invalid:
    type: http
    url: https://example.com/proxies.yaml
    interval: 9223372037
`)
	if len(r.Errors) != 1 || r.Errors[0].Field != "proxy-providers.invalid.interval" ||
		!strings.Contains(r.Errors[0].Reason, "out of range") {
		t.Fatalf("overflowing interval errors = %+v", r.Errors)
	}
}

// What a provider URL may be is what the core will fetch, and the core refuses
// almost nothing: it parses the URL, hands it to net/http, and turns userinfo
// into Basic auth (component/http/http.go:32-61). Three refusals that used to
// live here were stricter than that and none was required by the platform —
// admits a rejection only when it is both.
//
// http:// blocked every reader running a Sub-Store or rule mirror on their own
// network. Userinfo is how a private rule server is authenticated, and the
// refusal pointed at Keychain-backed headers, which abolished. A fragment
// never reaches the wire at all.
func TestPlanAcceptsEveryProviderURLTheCoreWouldFetch(t *testing.T) {
	r := planOf(t, `
proxy-providers:
  plaintext: {type: http, url: http://192.168.1.4:3000/download/hako}
  credentials: {type: http, url: https://user:password@example.com/proxies.yaml}
rule-providers:
  fragment: {type: http, behavior: domain, url: "https://example.com/rules.yaml#ignored"}
  valid-query: {type: http, behavior: domain, url: "  https://example.com/rules.yaml?token=opaque  "}
`)
	if len(r.Errors) != 0 {
		t.Fatalf("a URL the core would have fetched was refused: %+v", r.Errors)
	}
	got := make(map[string]string, len(r.Providers))
	for _, provider := range r.Providers {
		got[provider.Name] = provider.URL
	}
	want := map[string]string{
		"plaintext":   "http://192.168.1.4:3000/download/hako",
		"credentials": "https://user:password@example.com/proxies.yaml",
		"fragment":    "https://example.com/rules.yaml#ignored",
		// Surrounding whitespace is still trimmed: it is a typo, not an intent.
		"valid-query": "https://example.com/rules.yaml?token=opaque",
	}
	for name, expected := range want {
		if got[name] != expected {
			t.Fatalf("provider %s planned as %q, want %q", name, got[name], expected)
		}
	}
}

// What stays refused: a URL the core could not fetch either.
func TestPlanRejectsProviderURLsTheCoreCouldNotFetch(t *testing.T) {
	r := planOf(t, `
rule-providers:
  missing-host: {type: http, behavior: domain, url: "https:///rules.yaml"}
  not-a-transport: {type: http, behavior: domain, url: "file:///etc/passwd"}
  relative: {type: http, behavior: domain, url: "rules.yaml"}
`)
	fields := make([]string, 0, len(r.Errors))
	for _, failure := range r.Errors {
		fields = append(fields, failure.Field)
	}
	want := []string{
		"rule-providers.missing-host.url",
		"rule-providers.not-a-transport.url",
		"rule-providers.relative.url",
	}
	if !slices.Equal(fields, want) {
		t.Fatalf("URL errors = %+v, want fields %v", r.Errors, want)
	}
	if len(r.Providers) != 0 {
		t.Fatalf("an unfetchable provider stayed executable: %+v", r.Providers)
	}
}

func TestPlanRejectsUnsafeHysteriaHopInterval(t *testing.T) {
	r := planOf(t, `
proxies:
  - name: HY
    type: hysteria
    server: 127.0.0.1
    port: 443
    ports: 443-444
    auth-str: fixture
    up: 10 Mbps
    down: 10 Mbps
    hop-interval: -1
rules: [MATCH,HY]
`)
	if len(r.Errors) != 1 || r.Errors[0].Field != "proxies[0].hop-interval" {
		t.Fatalf("unsafe Hysteria plan errors = %+v", r.Errors)
	}
}

func TestPlanRejectsUnsafeHysteria2HopInterval(t *testing.T) {
	r := planOf(t, `
proxies:
  - name: HY2
    type: hysteria2
    server: 127.0.0.1
    port: 443
    ports: 443-444
    password: fixture
    hop-interval: 5-9223372037
rules: [MATCH,HY2]
`)
	if len(r.Errors) != 1 || r.Errors[0].Field != "proxies[0].hop-interval" {
		t.Fatalf("unsafe Hysteria2 plan errors = %+v", r.Errors)
	}
}

func TestWalkStringsSortsMappingKeys(t *testing.T) {
	var values []string
	walkStrings(map[string]any{
		"zebra": "last",
		"alpha": "first",
	}, func(value string) {
		values = append(values, value)
	})
	if want := []string{"first", "last"}; !slices.Equal(values, want) {
		t.Fatalf("walk order = %v, want %v", values, want)
	}
}

func TestPlanResourceSchemaVersion(t *testing.T) {
	r := planOf(t, "mode: rule\n")
	if r.SchemaVersion != resourcePlanSchemaVersion {
		t.Fatalf("schema version = %d", r.SchemaVersion)
	}
}

func TestPlanGeoIPUsesMMDBWhenGeodataModeIsDisabled(t *testing.T) {
	r := planOf(t, `
geodata-mode: false
geox-url:
  geoip: https://example.com/wrong-for-this-mode.dat
  mmdb: https://example.com/country.metadb
rules:
  - GEOIP,CN,DIRECT
`)
	if len(r.Geodata) != 1 {
		t.Fatalf("geodata plan = %+v; errors = %+v", r.Geodata, r.Errors)
	}
	geo := r.Geodata[0]
	if geo.Kind != "geoip" || geo.URL != "https://example.com/country.metadb" ||
		geo.Format != "mmdb" || geo.Path != "geoip.metadb" ||
		geo.MaximumBytes != maximumGeodataResourceBytes {
		t.Fatalf("wrong MMDB plan: %+v", geo)
	}
}

func TestPlanGeoIPUsesDatWhenGeodataModeIsEnabled(t *testing.T) {
	r := planOf(t, `
geodata-mode: true
geox-url:
  geoip: https://example.com/geoip.dat
  mmdb: https://example.com/wrong-for-this-mode.metadb
rules:
  - GEOIP,CN,DIRECT
`)
	if len(r.Geodata) != 1 {
		t.Fatalf("geodata plan = %+v; errors = %+v", r.Geodata, r.Errors)
	}
	geo := r.Geodata[0]
	if geo.URL != "https://example.com/geoip.dat" || geo.Format != "dat" || geo.Path != "GeoIP.dat" {
		t.Fatalf("wrong dat plan: %+v", geo)
	}
}

func TestPlanGeositeAndASNHaveDeterministicCorePaths(t *testing.T) {
	r := planOf(t, `
geox-url:
  geosite: https://example.com/sites.bin
  asn: https://example.com/asn.bin
rules:
  - GEOSITE,private,DIRECT
  - IP-ASN,13335,DIRECT
`)
	if len(r.Geodata) != 2 {
		t.Fatalf("geodata plan = %+v; errors = %+v", r.Geodata, r.Errors)
	}
	if r.Geodata[0].Kind != "geosite" || r.Geodata[0].Format != "dat" || r.Geodata[0].Path != "GeoSite.dat" {
		t.Fatalf("wrong geosite plan: %+v", r.Geodata[0])
	}
	if r.Geodata[1].Kind != "asn" || r.Geodata[1].Format != "mmdb" || r.Geodata[1].Path != "ASN.mmdb" {
		t.Fatalf("wrong ASN plan: %+v", r.Geodata[1])
	}
}

func TestPlanRejectsEmptyRequiredGeodataURL(t *testing.T) {
	r := planOf(t, `
geodata-mode: false
geox-url:
  mmdb: ""
rules:
  - GEOIP,CN,DIRECT
`)
	if len(r.Geodata) != 0 || len(r.Errors) != 1 || r.Errors[0].Field != "geox-url.mmdb" {
		t.Fatalf("expected missing MMDB URL error, plan=%+v errors=%+v", r.Geodata, r.Errors)
	}
}

// Geodata URLs answer to the same rule as provider URLs, because the core
// fetches them through the same helper: no scheme restriction, userinfo turned
// into Basic auth, fragment never sent. An internal mirror on http and a
// geosite behind Basic auth are ordinary, and refusing them was stricter than
// upstream without being required by the platform.
func TestPlanAcceptsEveryGeodataURLTheCoreWouldFetch(t *testing.T) {
	r := planOf(t, `
geodata-mode: false
geox-url:
  mmdb: http://mirror.internal/country.metadb
  geosite: https://user:password@example.com/geosite.dat
  asn: https://example.com/asn.mmdb#ignored
rules:
  - GEOIP,CN,DIRECT
  - GEOSITE,private,DIRECT
  - IP-ASN,13335,DIRECT
`)
	if len(r.Errors) != 0 {
		t.Fatalf("a geodata URL the core would have fetched was refused: %+v", r.Errors)
	}
	if len(r.Geodata) != 3 {
		t.Fatalf("geodata plans = %+v, want all three executable", r.Geodata)
	}
}

func TestPlanRejectsGeodataURLsTheCoreCouldNotFetch(t *testing.T) {
	r := planOf(t, `
geodata-mode: false
geox-url:
  mmdb: "https:///country.metadb"
  geosite: "file:///etc/geosite.dat"
rules:
  - GEOIP,CN,DIRECT
  - GEOSITE,private,DIRECT
`)
	fields := make([]string, 0, len(r.Errors))
	for _, failure := range r.Errors {
		fields = append(fields, failure.Field)
	}
	want := []string{"geox-url.mmdb", "geox-url.geosite"}
	if !slices.Equal(fields, want) {
		t.Fatalf("geodata URL errors = %+v, want %v", r.Errors, want)
	}
	if len(r.Geodata) != 0 {
		t.Fatalf("an unfetchable geodata plan stayed executable: %+v", r.Geodata)
	}
}

func TestPlanNormalizesSafeGeodataURL(t *testing.T) {
	r := planOf(t, `
geodata-mode: false
geox-url:
  mmdb: "  https://example.com/country.metadb?version=1  "
rules:
  - GEOIP,CN,DIRECT
`)
	if len(r.Errors) != 0 || len(r.Geodata) != 1 ||
		r.Geodata[0].URL != "https://example.com/country.metadb?version=1" {
		t.Fatalf("safe geodata URL was not normalized: plan=%+v errors=%+v", r.Geodata, r.Errors)
	}
}

func TestPlanDoesNotTreatDomainPayloadAsGeodataRule(t *testing.T) {
	r := planOf(t, `
rules:
  - DOMAIN-SUFFIX,geoip.example,DIRECT
  - DOMAIN,geosite,DIRECT
`)
	if len(r.Geodata) != 0 {
		t.Fatalf("ordinary domain payload produced geodata requirements: %+v", r.Geodata)
	}
}

func TestPlanFindsGeodataInsideLogicRuleAndDNSFilter(t *testing.T) {
	r := planOf(t, `
rules:
  - AND,((GEOIP,CN),(NETWORK,TCP)),DIRECT
dns:
  fake-ip-filter:
    - geosite:private
`)
	if len(r.Geodata) != 2 || r.Geodata[0].Kind != "geoip" || r.Geodata[1].Kind != "geosite" {
		t.Fatalf("nested rule or DNS geosite was missed: %+v", r.Geodata)
	}
}

func TestPlanGeoIPRequirementMirrorsUpstreamFileDependency(t *testing.T) {
	// requiredGeodata must match what upstream NewGEOIP actually reads: a non-lan
	// country needs the GeoIP database, but country "lan" (case-insensitive,
	// evaluated by a pure netip predicate before any file access) needs no file.
	// SRC-GEOIP shares GEOIP's dependency and was previously omitted from the scan.
	for name, tc := range map[string]struct {
		rule    string
		wantGeo bool
	}{
		"geoip lan needs no db":         {"GEOIP,lan,DIRECT", false},
		"geoip LAN is case-insensitive": {"GEOIP,LAN,DIRECT", false},
		"geoip country needs db":        {"GEOIP,CN,DIRECT", true},
		"src-geoip lan needs no db":     {"SRC-GEOIP,lan,DIRECT", false},
		"src-geoip country needs db":    {"SRC-GEOIP,CN,DIRECT", true},
		"nested geoip lan needs no db":  {"AND,((GEOIP,lan),(NETWORK,UDP)),DIRECT", false},
		"nested geoip country needs db": {"AND,((GEOIP,CN),(NETWORK,TCP)),DIRECT", true},
	} {
		t.Run(name, func(t *testing.T) {
			r := planOf(t, "rules:\n  - "+tc.rule+"\n")
			hasGeoIP := false
			for _, g := range r.Geodata {
				if g.Kind == "geoip" {
					hasGeoIP = true
				}
			}
			if hasGeoIP != tc.wantGeo {
				t.Fatalf("rule %q: geoip required = %v, want %v (geodata=%+v)", tc.rule, hasGeoIP, tc.wantGeo, r.Geodata)
			}
		})
	}
}

func planOf(t *testing.T, yaml string) planResult {
	t.Helper()
	box, err := PlanResourcesForIOS(yaml)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var r planResult
	if err := json.Unmarshal([]byte(box.Value), &r); err != nil {
		t.Fatalf("bad json: %v\n%s", err, box.Value)
	}
	return r
}

func TestPlanListsHTTPProviders(t *testing.T) {
	y := "rule-providers:\n  rule1:\n    type: http\n    url: https://example.com/r.yaml\n    behavior: classical\n"
	r := planOf(t, y)
	if len(r.Providers) != 1 || r.Providers[0].Name != "rule1" || r.Providers[0].Type != "http" {
		t.Fatalf("provider not planned: %+v", r.Providers)
	}
	if r.Providers[0].URL != "https://example.com/r.yaml" {
		t.Fatalf("url missing: %+v", r.Providers[0])
	}
	if !strings.HasPrefix(r.Providers[0].Path, "provider-") ||
		strings.Contains(r.Providers[0].Path, "rule1") ||
		strings.ContainsAny(r.Providers[0].Path, `/\\`) {
		t.Fatalf("provider path is not anonymous/safe: %q", r.Providers[0].Path)
	}
}

func TestPlanProviderNameCannotEscapeCandidateDirectory(t *testing.T) {
	y := "rule-providers:\n  '../private/token':\n    type: http\n    url: https://example.com/r.yaml\n    behavior: classical\n"
	r := planOf(t, y)
	if len(r.Providers) != 1 {
		t.Fatalf("provider not planned: %+v", r.Providers)
	}
	if strings.Contains(r.Providers[0].Path, "..") ||
		strings.ContainsAny(r.Providers[0].Path, `/\\`) {
		t.Fatalf("provider escaped candidate directory: %q", r.Providers[0].Path)
	}
}

func TestPlanCarriesHeadersAndStripsProviderProxy(t *testing.T) {
	// A provider's fetch proxy only selects HOW the payload downloads, never
	// which proxy serves user traffic — the App downloader fetches directly, so
	// the field is stripped + noticed and the config still starts.
	y := "rule-providers:\n  rules:\n    type: http\n    behavior: classical\n    url: https://example.com/r.yaml\n    proxy: Selected\n    header:\n      X-Token: secret\n      Accept:\n        - application/yaml\n"
	r := planOf(t, y)
	if len(r.Providers) != 1 {
		t.Fatalf("provider not planned: %+v", r.Providers)
	}
	if got := r.Providers[0].Headers["X-Token"]; len(got) != 1 || got[0] != "secret" {
		t.Fatalf("headers missing: %+v", r.Providers[0].Headers)
	}
	if len(r.Errors) != 0 {
		t.Fatalf("provider fetch proxy must not be a plan error: %+v", r.Errors)
	}
	if r.Providers[0].Proxy != "" {
		t.Fatalf("provider fetch proxy must be stripped from the download plan: %+v", r.Providers[0])
	}
	noted := false
	for _, n := range r.Notices {
		if strings.Contains(n, ".proxy") && strings.Contains(n, "stripped") {
			noted = true
		}
	}
	if !noted {
		t.Fatalf("expected a stripped fetch-proxy notice, got: %v", r.Notices)
	}
}

func TestPlanRejectsProviderHeadersThatCannotBeReproducedSafely(t *testing.T) {
	for name, headerYAML := range map[string]string{
		"not a mapping":        "header: invalid",
		"mixed value list":     "header: {Accept: [application/yaml, 7]}",
		"invalid field name":   "header: {'Bad Name': [value]}",
		"hop by hop":           "header: {Connection: [keep-alive]}",
		"line break injection": `header: {X-Test: ["safe\r\nInjected: yes"]}`,
		"duplicate field name": "header: {X-Token: [one], x-token: [two]}",
	} {
		t.Run(name, func(t *testing.T) {
			r := planOf(t, `
proxy-providers:
  remote:
    type: http
    url: https://example.com/proxies.yaml
    `+headerYAML+`
`)
			if len(r.Errors) != 1 || r.Errors[0].Field != "proxy-providers.remote.header" {
				t.Fatalf("unsafe header errors = %+v", r.Errors)
			}
			if strings.Contains(r.Errors[0].Reason, "Injected") || strings.Contains(r.Errors[0].Reason, "keep-alive") {
				t.Fatalf("header value leaked in error: %+v", r.Errors[0])
			}
		})
	}
}

func TestPlanRejectsProviderHeadersOverAggregateByteLimit(t *testing.T) {
	// Each value is individually below the historical 8 KiB check, while the
	// combined request headers exceed the intended bounded request envelope.
	value := strings.Repeat("a", maximumProviderHeaderBytes/2+1)
	r := planOf(t, `
proxy-providers:
  remote:
    type: http
    url: https://example.com/proxies.yaml
    header:
      X-First: "`+value+`"
      X-Second: "`+value+`"
`)
	if len(r.Errors) != 1 || r.Errors[0].Field != "proxy-providers.remote.header" ||
		!strings.Contains(r.Errors[0].Reason, "total byte limit") {
		t.Fatalf("oversized aggregate header errors = %+v", r.Errors)
	}
	if strings.Contains(r.Errors[0].Reason, value[:32]) {
		t.Fatalf("oversized header content leaked in error: %+v", r.Errors[0])
	}
}

func TestProviderHeadersAcceptEveryHTTPTokenCharacter(t *testing.T) {
	name := "X!#$%&'*+-.^_`|~09azAZ"
	headers, err := providerHeaders(map[string]any{name: "value"})
	if err != nil {
		t.Fatalf("valid HTTP field name rejected: %v", err)
	}
	if got := headers[name]; len(got) != 1 || got[0] != "value" {
		t.Fatalf("valid HTTP field was not preserved: %+v", headers)
	}
}

func TestPlanRejectsUnmaterializedFileProvider(t *testing.T) {
	y := "rule-providers:\n  local:\n    type: file\n    behavior: classical\n    path: ../private/rules.yaml\n"
	r := planOf(t, y)
	if len(r.Errors) != 1 || !strings.Contains(r.Errors[0].Field, ".path") {
		t.Fatalf("file provider was not rejected: %+v", r.Errors)
	}
}

func TestPlanTreatsUnexecutableTunIntentAsStrippedNotice(t *testing.T) {
	r := planOf(t, `
tun:
  auto-redirect: true
  auto-redirect-input-mark: 101
  include-package: [com.example.app]
  exclude-dst-port: [53]
`)
	// These host-route filters are stripped on iOS (tolerate + strip), so the
	// plan reports them as notices and the config still starts — never as errors.
	if len(r.Errors) != 0 {
		t.Fatalf("stripped tun intent must not be a plan error: %+v", r.Errors)
	}
	for _, field := range []string{
		"tun.auto-redirect",
		"tun.auto-redirect-input-mark",
		"tun.include-package",
		"tun.exclude-dst-port",
	} {
		found := false
		for _, notice := range r.Notices {
			if strings.Contains(notice, field) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected a stripped-knob notice for %s, notices=%v", field, r.Notices)
		}
	}
}

func TestPlanNotesEveryOutboundEgressOverride(t *testing.T) {
	// Global AND per-proxy interface-name/routing-mark egress overrides are all
	// stripped on iOS (tolerate + strip), so the plan reports them as notices,
	// never errors — a config carrying one still starts.
	for name, yaml := range map[string]string{
		"global": "routing-mark: 233\n",
		"direct proxy": `
proxies:
  - {name: node, type: socks5, server: 127.0.0.1, port: 1080, interface-name: en0}
`,
		"group": `
proxy-groups:
  - {name: group, type: select, proxies: [DIRECT], routing-mark: 233}
`,
		"provider override": `
proxy-providers:
  remote:
    type: http
    url: https://example.com/proxies.yaml
    override: {interface-name: en0}
`,
		"inline provider payload": `
proxy-providers:
  inline:
    type: inline
    payload:
      - {name: node, type: socks5, server: 127.0.0.1, port: 1080, routing-mark: 233}
`,
	} {
		t.Run(name, func(t *testing.T) {
			r := planOf(t, yaml)
			if len(r.Errors) != 0 {
				t.Fatalf("egress override must not be a plan error: %+v", r.Errors)
			}
			noted := false
			for _, notice := range r.Notices {
				if strings.Contains(notice, "interface-name") || strings.Contains(notice, "routing-mark") {
					noted = true
					break
				}
			}
			if !noted {
				t.Fatalf("egress override should be a stripped-knob notice, notices=%v", r.Notices)
			}
		})
	}
}

func TestPlanNotesEachPairedOutboundEgressOverrideField(t *testing.T) {
	r := planOf(t, `
interface-name: en0
routing-mark: 233
proxies:
  - {name: node, type: socks5, server: 127.0.0.1, port: 1080, interface-name: en0, routing-mark: 1}
proxy-groups:
  - {name: group, type: select, proxies: [node], interface-name: en1, routing-mark: 2}
proxy-providers:
  remote:
    type: http
    url: https://example.com/proxies.yaml
    override: {interface-name: en2, routing-mark: 3}
  inline:
    type: inline
    payload:
      - {name: inline-node, type: socks5, server: 127.0.0.1, port: 1081, interface-name: en3, routing-mark: 4}
`)
	if len(r.Errors) != 0 {
		t.Fatalf("paired egress overrides must not be plan errors: %+v", r.Errors)
	}
	for _, marker := range []string{
		"interface-name: global",
		"routing-mark: global",
		"proxies[0].interface-name",
		"proxies[0].routing-mark",
		"proxy-groups[0].interface-name",
		"proxy-groups[0].routing-mark",
		"proxy-providers.remote.override.interface-name",
		"proxy-providers.remote.override.routing-mark",
		"proxy-providers.inline.payload[0].interface-name",
		"proxy-providers.inline.payload[0].routing-mark",
	} {
		found := false
		for _, notice := range r.Notices {
			if strings.Contains(notice, marker) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing paired egress notice %q; notices=%+v", marker, r.Notices)
		}
	}
}

func TestPlanErrorsOnDanglingRouteAddressSet(t *testing.T) {
	y := "tun:\n  route-address-set:\n    - ruleset-1\n"
	r := planOf(t, y)
	found := false
	for _, e := range r.Errors {
		if strings.Contains(e.Field, "route-address-set") && strings.Contains(e.Reason, "ruleset-1") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected dangling-ruleset error, got: %+v", r.Errors)
	}
}

func TestPlanNotesProcessRuleAsStripped(t *testing.T) {
	y := "rules:\n  - PROCESS-NAME,curl,DIRECT\n"
	r := planOf(t, y)
	// A PROCESS rule no-ops on iOS (FindProcessOff); the plan notes it rather
	// than failing, so a subscription carrying one still starts.
	if len(r.Errors) != 0 {
		t.Fatalf("a PROCESS rule must not be a plan error: %+v", r.Errors)
	}
	found := false
	for _, notice := range r.Notices {
		if strings.Contains(strings.ToLower(notice), "process") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a process-rule notice, got: %+v", r.Notices)
	}
}

func TestPlanNotesStrippedDNSSchemeButErrorsOnBootstrap(t *testing.T) {
	// system/dhcp in a query-resolver list is stripped on iOS → notice, no error.
	r := planOf(t, "dns:\n  nameserver: [223.5.5.5, system]\n  fallback: [dhcp://en0]\n")
	if len(r.Errors) != 0 {
		t.Fatalf("stripped DNS scheme must not be a plan error: %+v", r.Errors)
	}
	noticed := 0
	for _, n := range r.Notices {
		if strings.Contains(n, "system/dhcp") {
			noticed++
		}
	}
	if noticed < 2 {
		t.Fatalf("expected notices for stripped nameserver+fallback schemes, got: %v", r.Notices)
	}
	// An all-system bootstrap is NOT an error, because mihomo loads it: the
	// pure-IP check `continue`s past ns.Net == "system" (config/config.go:1461-1463).
	// The plan has to agree with the runtime about which configs start, and the
	// runtime now starts this one -- CheckConfig proves it in
	// TestCheckConfigStripsSystemNameserverButRejectsSystemBootstrap.
	rb := planOf(t, "dns:\n  default-nameserver: [system]\n")
	for _, e := range rb.Errors {
		if e.Field == "dns.default-nameserver" {
			t.Fatalf("all-system bootstrap must not be a plan error: %+v", rb.Errors)
		}
	}
	// It is not reported as STRIPPED, because it is not stripped -- but it is
	// not silent either. The old rejection was at least loud about the hazard;
	// its replacement is a kept-notice: the entry stays as written, and inside a
	// packet tunnel the system resolver is the tunnel itself, so a nameserver
	// that needs bootstrapping may fail. Total silence here was reviewed as the
	// worst of both worlds.
	keptNoticed := false
	for _, n := range rb.Notices {
		if strings.Contains(n, "default-nameserver") {
			if strings.Contains(n, "stripped") {
				t.Fatalf("an unstripped bootstrap must not be reported as stripped: %v", rb.Notices)
			}
			if strings.Contains(n, "explicit defaults") {
				keptNoticed = true
			}
		}
	}
	if !keptNoticed {
		t.Fatalf("an all-system bootstrap must carry a repair notice, got: %v", rb.Notices)
	}
	// dhcp:// in the same slot is stripped and repaired like system, so it is a
	// notice too. What stays a plan error is a survivor mihomo itself refuses:
	// a hostname where the pure-IP check wants an address.
	rbd := planOf(t, "dns:\n  default-nameserver: [dhcp://en0]\n")
	for _, e := range rbd.Errors {
		if e.Field == "dns.default-nameserver" {
			t.Fatalf("an all-dhcp bootstrap is repaired, not an error: %+v", rbd.Errors)
		}
	}
	rbh := planOf(t, "dns:\n  default-nameserver: [\"https://dns.google/dns-query\"]\n")
	found := false
	for _, e := range rbh.Errors {
		if e.Field == "dns.default-nameserver" {
			found = true
		}
	}
	if !found {
		t.Fatalf("a bootstrap mihomo rejects must stay a plan error: %+v", rbh.Errors)
	}
	// A bootstrap with system + usable IPs strips system, keeps the IPs: not an
	// error (the common real shape, e.g. [system, 180.76.76.76, 8.8.8.8, ...]).
	rb2 := planOf(t, "dns:\n  default-nameserver: [system, 180.76.76.76, 8.8.8.8]\n")
	for _, e := range rb2.Errors {
		if e.Field == "dns.default-nameserver" {
			t.Fatalf("bootstrap with usable IPs must not be a plan error: %+v", rb2.Errors)
		}
	}
}

func TestPlanNotesDNSPhysicalInterfaceFragmentAsStripped(t *testing.T) {
	// The fragment is stripped on iOS (the resolver survives through normal
	// core routing), so the plan notes it rather than failing the config.
	r := planOf(t, `
dns:
  enable: true
  nameserver:
    - https://dns.example/dns-query#en0
`)
	if len(r.Errors) != 0 {
		t.Fatalf("stripped DNS fragment must not be a plan error: %+v", r.Errors)
	}
	noted := false
	for _, n := range r.Notices {
		if strings.Contains(n, "nameserver") && strings.Contains(n, "fragment") {
			noted = true
		}
	}
	if !noted {
		t.Fatalf("expected a stripped-fragment notice, got: %v", r.Notices)
	}
}

func TestPlanAcceptsDNSFragmentNamingConfiguredProxy(t *testing.T) {
	r := planOf(t, `
proxies:
  - {name: DNS PROXY, type: direct}
dns:
  enable: true
  nameserver:
    - https://dns.example/dns-query#DNS%20PROXY
`)
	if len(r.Errors) != 0 {
		t.Fatalf("configured DNS proxy fragment rejected: %+v", r.Errors)
	}
}

func TestPlanRejectsOutboundEmbeddedDNSBareFragment(t *testing.T) {
	for name, yaml := range map[string]string{
		"top-level": `
proxies:
  - name: tunnel
    type: openvpn
    remote-dns-resolve: true
    dns: ["https://dns.example/dns-query#en0"]
`,
		"inline provider": `
proxy-providers:
  nodes:
    type: inline
    payload:
      - name: tunnel
        type: wireguard
        remote-dns-resolve: true
        dns: ["quic://dns.example#pdp_ip0"]
`,
	} {
		t.Run(name, func(t *testing.T) {
			r := planOf(t, yaml)
			if len(r.Errors) != 1 || !strings.HasSuffix(r.Errors[0].Field, ".dns") {
				t.Fatalf("outbound embedded DNS errors = %+v", r.Errors)
			}
		})
	}
}

func TestPlanNotesEveryUnavailableMetadataRuleShapeAsStripped(t *testing.T) {
	for name, yaml := range map[string]string{
		"uid":          "rules:\n  - UID,501,DIRECT\n",
		"in-user":      "rules:\n  - IN-USER,alice,DIRECT\n",
		"wildcard":     "rules:\n  - PROCESS-NAME-WILDCARD,curl*,DIRECT\n",
		"nested logic": "rules:\n  - NOT,(PROCESS-PATH-WILDCARD,/private/*),DIRECT\n",
		"sub-rule":     "sub-rules:\n  child:\n    - PROCESS-PATH-REGEX,^/bin/.*,DIRECT\n",
	} {
		t.Run(name, func(t *testing.T) {
			r := planOf(t, yaml)
			// Every process/uid/in-user rule shape no-ops on iOS; the plan notes
			// it (matches nothing, falls through) rather than failing the config.
			if len(r.Errors) != 0 {
				t.Fatalf("metadata rule must not be a plan error: %+v", r.Errors)
			}
			if len(r.Notices) == 0 {
				t.Fatalf("metadata rule should be a stripped-knob notice: %+v", r.Notices)
			}
		})
	}
}

func TestPlanNotesEachMetadataRuleWithoutOneMaskingAnother(t *testing.T) {
	r := planOf(t, `
rules:
  - PROCESS-NAME,curl,DIRECT
  - UID,501,DIRECT
  - IN-USER,alice,DIRECT
  - MATCH,DIRECT
`)
	if len(r.Errors) != 0 {
		t.Fatalf("metadata no-op rules must not be plan errors: %+v", r.Errors)
	}
	for _, kind := range []string{"PROCESS-NAME", "UID", "IN-USER"} {
		found := false
		for _, notice := range r.Notices {
			if strings.Contains(notice, kind) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing %s notice; notices=%+v", kind, r.Notices)
		}
	}
}

func TestPlanNotesInlineProviderMetadataNoops(t *testing.T) {
	r := planOf(t, `
rule-providers:
  inline:
    type: inline
    behavior: classical
    payload:
      - UID,501
      - DOMAIN,example.com
      - IN-USER,alice
`)
	if len(r.Errors) != 0 {
		t.Fatalf("inline provider metadata no-ops must not be plan errors: %+v", r.Errors)
	}
	for _, kind := range []string{"UID", "IN-USER"} {
		found := false
		for _, notice := range r.Notices {
			if strings.Contains(notice, kind) && strings.Contains(notice, "rule-providers[") {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing inline provider %s notice: %+v", kind, r.Notices)
		}
	}
}

// The plan and the runtime must agree about which bootstraps start, because
// defaultNameserverStrip exists for exactly that promise and the App shows the
// plan's verdict before the core ever runs. Rather than assert a hand-derived
// table, this drives both sides over the same inputs and compares them -- so a
// future change to either one cannot drift without a red test, and the kernel
// stays the authority on the answer.
func TestPlanAndRuntimeAgreeOnBootstrapShapes(t *testing.T) {
	options := testOptions(t)
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	// The first review of this test carried nine shapes and missed three
	// disagreements; the matrix below is fat on purpose. Notable rows, as
	// decided AFTER the Apple packet-tunnel DNS repair joined the pipeline:
	// every system/dhcp-schemed entry is removed by strip or repair before
	// mihomo looks (so "SyStEm" -- NE-incompatible by our case-insensitive
	// predicate -- never reaches parsePureDNSServer's exact comparison at
	// config/config.go:1308, and an all-system or explicit-empty list is
	// refilled with mihomo's defaults rather than tripping "should have at
	// least one nameserver", config.go:1453); what still refuses is mihomo's
	// own verdict on a SURVIVOR -- a hostname where the pure-IP check wants an
	// address (bare "dhcp", "tls://dns.google") or an unknown scheme failing
	// parseNameServer outright (config.go:1269-1270).
	for _, list := range []string{
		`[system]`,
		`[system, ""]`,
		`[system, "udp://:53"]`,
		`[system, "dhcp://x"]`,
		`["dhcp://en0"]`,
		`[dhcp]`,
		`["https://dns.google/dns-query"]`,
		`[system, 180.76.76.76]`,
		`[223.5.5.5]`,
		`["dhcp://en0", 8.8.8.8]`,
		`[SyStEm]`,
		`[System]`,
		`["dhcp://system"]`,
		`["system://"]`,
		`["SYSTEM://"]`,
		`["tls://dns.google"]`,
		`["tls://1.1.1.1"]`,
		`["https://1.1.1.1/dns-query"]`,
		`["rcode://success"]`,
		`["udp://:53"]`,
		`["abc://1.1.1.1"]`,
		`[]`,
		`["dhcp://system", "dhcp://en0"]`,
		`[SyStEm, 8.8.8.8]`,
	} {
		content := fmt.Sprintf(
			"mode: rule\ndns:\n  enable: true\n  nameserver: [223.5.5.5]\n  default-nameserver: %s\nrules:\n  - MATCH,DIRECT\n",
			list,
		)
		runtimeStarts := CheckConfig(content) == nil

		planned := planOf(t, content)
		plannedError := false
		for _, e := range planned.Errors {
			if e.Field == "dns.default-nameserver" {
				plannedError = true
			}
		}
		if runtimeStarts == plannedError {
			verdict := "starts"
			if !runtimeStarts {
				verdict = "is refused"
			}
			t.Errorf("default-nameserver %s: the core %s but the plan says error=%v", list, verdict, plannedError)
		}
		t.Logf("default-nameserver %-30s core-starts=%-5v plan-error=%v", list, runtimeStarts, plannedError)
	}
}

// The projection must NEVER ride in the plan result. Two reasons, both hard:
// the plan result has a 16 MiB ceiling (config_limits.go:32) and a projection
// pushing a legal plan past it turns "slower" into "activation fails at
// coordinator :858"; and three notice-only UI callers (two on the main thread)
// would pay for bytes they never read.
func TestPlanResultCarriesNoProjection(t *testing.T) {
	box, err := PlanResourcesForIOS("proxies:\n  - {name: A, type: socks5, server: e.test, port: 1080}\n")
	if err != nil {
		t.Fatalf("plan failed: %v", err)
	}
	var root map[string]any
	if err := json.Unmarshal([]byte(box.Value), &root); err != nil {
		t.Fatalf("plan result does not decode: %v", err)
	}
	if _, present := root["projection"]; present {
		t.Fatal("the plan result must not carry a projection")
	}
	// Exact key set, not just presence: ANY new top-level key grows every
	// notice-only caller's payload, projection or otherwise.
	expected := map[string]bool{
		"schemaVersion": true, "providers": true, "geodata": true,
		"notices": true, "errors": true,
	}
	for key := range root {
		if !expected[key] {
			t.Fatalf("plan schema grew an unexpected top-level key %q", key)
		}
	}
	for key := range expected {
		if _, present := root[key]; !present {
			t.Fatalf("plan schema changed: key %q missing", key)
		}
	}
}

// One flow, one parse: the handle serves the plan and a projection from the
// same open, and both agree with the standalone route.
func TestHandleServesPlanAndProjectionFromOneOpen(t *testing.T) {
	yamlText := "proxies:\n  - {name: A, type: socks5, server: e.test, port: 1080}\nproxy-groups:\n  - {name: G, type: select, proxies: [A]}\n"
	doc, err := NewConfigDocument(yamlText)
	if err != nil {
		t.Fatalf("open failed: %v", err)
	}
	defer doc.Close()
	planBox, err := doc.PlanResourcesJSON()
	if err != nil {
		t.Fatalf("plan via handle failed: %v", err)
	}
	legacyBox, err := PlanResourcesForIOS(yamlText)
	if err != nil {
		t.Fatalf("legacy plan failed: %v", err)
	}
	if planBox.Value != legacyBox.Value {
		t.Fatalf("handle plan and wrapper plan disagree:\n handle = %s\n legacy = %s",
			planBox.Value, legacyBox.Value)
	}
	mergedBox, err := doc.ProjectionJSON(projectionKindMerged, `["catalog"]`)
	if err != nil {
		t.Fatalf("projection from the same open failed: %v", err)
	}
	var merged struct {
		DocumentKind string `json:"documentKind"`
	}
	if err := json.Unmarshal([]byte(mergedBox.Value), &merged); err != nil {
		t.Fatalf("merged projection does not decode: %v", err)
	}
	if merged.DocumentKind != "merged" {
		t.Fatalf("the merged label must survive into the artifact, got %q", merged.DocumentKind)
	}
}
