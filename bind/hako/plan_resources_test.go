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
	Notices           []string                         `json:"notices"`
	StructuredNotices []planNotice                     `json:"structuredNotices"`
	Errors            []struct{ Field, Reason string } `json:"errors"`
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

func TestPlanDefaultsNegativeProviderSizeLimit(t *testing.T) {
	r := planOf(t, `
proxy-providers:
  invalid:
    type: http
    url: https://example.com/proxies.yaml
    size-limit: -1
`)
	// vehicle.go:157 reads `if h.sizeLimit > 0`, so a negative limit means "no
	// limit" upstream. The plan needs a number for the app's downloader and
	// takes the default; it does not cost the configuration.
	if len(r.Errors) != 0 {
		t.Fatalf("negative size-limit refused the configuration: %+v", r.Errors)
	}
	if len(r.Providers) != 1 || r.Providers[0].MaximumBytes != int64(maximumProviderResourceBytes) {
		t.Fatalf("size-limit did not fall back: %+v", r.Providers)
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

func TestPlanDefaultsNegativeProviderUpdateInterval(t *testing.T) {
	r := planOf(t, `
rule-providers:
  invalid:
    type: http
    behavior: domain
    url: https://example.com/rules.yaml
    interval: -1
`)
	// Upstream's schema is a plain `Interval int` and never checks the sign.
	if len(r.Errors) != 0 {
		t.Fatalf("negative interval refused the configuration: %+v", r.Errors)
	}
	if len(r.Providers) != 1 || r.Providers[0].UpdateIntervalSeconds != 0 {
		t.Fatalf("interval did not fall back to zero: %+v", r.Providers)
	}
}

func TestPlanDefaultsProviderUpdateIntervalThatOverflowsTimeDuration(t *testing.T) {
	r := planOf(t, `
proxy-providers:
  invalid:
    type: http
    url: https://example.com/proxies.yaml
    interval: 9223372037
`)
	// A value that would wrap upstream's time.Duration is not representable
	// here either, but zero -- upstream's own "no timer" -- is, and the
	// provider still loads.
	if len(r.Errors) != 0 {
		t.Fatalf("overflowing interval refused the configuration: %+v", r.Errors)
	}
	if len(r.Providers) != 1 || r.Providers[0].UpdateIntervalSeconds != 0 {
		t.Fatalf("overflowing interval did not fall back to zero: %+v", r.Providers)
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
func TestPlanReportsProviderURLsTheCoreCouldNotFetch(t *testing.T) {
	r := planOf(t, `
rule-providers:
  missing-host: {type: http, behavior: domain, url: "https:///rules.yaml"}
  not-a-transport: {type: http, behavior: domain, url: "file:///etc/passwd"}
  relative: {type: http, behavior: domain, url: "rules.yaml"}
`)
	// None of the three costs the configuration: rewriteProviders applies this
	// same predicate before demanding materialization, so each definition
	// survives finalize and the kernel fails its own download the way upstream
	// does (executor.go:400).
	if len(r.Errors) != 0 {
		t.Fatalf("an unfetchable provider url refused the configuration: %+v", r.Errors)
	}
	if len(r.Providers) != 0 {
		t.Fatalf("an unfetchable provider entered the download plan: %+v", r.Providers)
	}
	for _, name := range []string{"missing-host", "not-a-transport", "relative"} {
		named := false
		for _, notice := range r.Notices {
			if strings.Contains(notice, "rule-providers."+name) {
				named = true
			}
		}
		if !named {
			t.Fatalf("no notice named %q: %+v", name, r.Notices)
		}
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

// TestPlanCarriesHeadersAndHonoursProviderProxy: a fetch proxy is no longer stripped (
// already lets the core fetch a provider the app has no local copy of; a named proxy is routed
// onto that same path instead of being blanked). The app-side decision not to pre-download a
// proxy-bound provider is not this function's to make or verify -- only that the field survives
// into the plan unaltered, so the app HAS the value to act on.
func TestPlanCarriesHeadersAndHonoursProviderProxy(t *testing.T) {
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
	if r.Providers[0].Proxy != "Selected" {
		t.Fatalf("provider fetch proxy must reach the plan unaltered so the core can dial through it, got: %+v", r.Providers[0])
	}
	noted := false
	for _, n := range r.Notices {
		if strings.Contains(n, ".proxy") && strings.Contains(n, "honoured") {
			noted = true
		}
	}
	if !noted {
		t.Fatalf("expected an honoured fetch-proxy notice, got: %v", r.Notices)
	}
	for _, n := range r.Notices {
		if strings.Contains(n, "not itself a proxy") {
			t.Fatalf("Selected does not name this provider -- the self-referential notice must not fire: %v", r.Notices)
		}
	}
}

// TestPlanNotesAProviderNamingItselfAsItsOwnFetchProxy: checkable from the document alone, at
// plan time, with no knowledge of what has loaded -- a provider's own key in proxy-providers is
// never itself an entry in the outbound table the core resolves a fetch proxy against
// (tunnel.go resolveMetadata: proxies[metadata.SpecialProxy]), whether or not this provider has
// fetched. Purely informational: this changes nothing the core does, upstream fails the same
// dial the same way.
func TestPlanNotesAProviderNamingItselfAsItsOwnFetchProxy(t *testing.T) {
	y := "proxy-providers:\n  HK:\n    type: http\n    url: https://example.com/hk.yaml\n    proxy: HK\n"
	r := planOf(t, y)
	if len(r.Providers) != 1 || r.Providers[0].Proxy != "HK" {
		t.Fatalf("provider fetch proxy must still reach the plan unaltered: %+v", r.Providers)
	}
	found := ""
	for _, n := range r.Notices {
		if strings.Contains(n, "not itself a proxy") {
			found = n
		}
	}
	if found == "" {
		t.Fatalf("expected a self-referential fetch-proxy notice, got: %v", r.Notices)
	}
	// The consequence sentence is the core's own -- quoted, not paraphrased
	// (tunnel/tunnel.go resolveMetadata: fmt.Errorf("proxy %s not found", ...)).
	if !strings.Contains(found, `"proxy HK not found"`) {
		t.Fatalf("notice must quote the core's own error text verbatim, got: %q", found)
	}
}

// TestPlanDoesNotFlagASiblingProviderAsSelfReferential: the self-referential check is scoped to
// a provider naming ITSELF, not to any name shared with a sibling provider -- a sibling's own
// nodes may well have loaded by the time this one fetches, which is a real, working
// configuration this notice must not discourage.
func TestPlanDoesNotFlagASiblingProviderAsSelfReferential(t *testing.T) {
	y := "proxy-providers:\n  HK:\n    type: http\n    url: https://example.com/hk.yaml\n  JP:\n    type: http\n    url: https://example.com/jp.yaml\n    proxy: HK\n"
	r := planOf(t, y)
	for _, n := range r.Notices {
		if strings.Contains(n, "not itself a proxy") {
			t.Fatalf("JP naming sibling provider HK as its fetch proxy is not self-reference: %v", r.Notices)
		}
	}
}

func TestPlanDropsProviderHeadersThatCannotBeReproducedSafely(t *testing.T) {
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
			// vehicle.go:125-139 caps nothing and forbids nothing, so a field
			// this layer cannot reproduce is dropped on its own and the
			// provider still loads.
			if len(r.Errors) != 0 {
				t.Fatalf("an unusable header refused the configuration: %+v", r.Errors)
			}
			if len(r.Providers) != 1 {
				t.Fatalf("provider dropped with its header: %+v", r.Providers)
			}
			dropped := false
			for _, notice := range r.Notices {
				if strings.Contains(notice, "header field") {
					dropped = true
				}
				// The value may carry an Authorization token; only the field
				// name is ever named.
				if strings.Contains(notice, "Injected") || strings.Contains(notice, "keep-alive") {
					t.Fatalf("header value leaked in a notice: %q", notice)
				}
			}
			if !dropped {
				t.Fatalf("no notice reported the dropped header: %+v", r.Notices)
			}
		})
	}
}

// Renamed and inverted on 2026-08-27 from
// TestPlanDropsProviderHeadersOverAggregateByteLimit. The aggregate byte
// envelope it pinned -- along with the per-field 8 KiB and 64-field caps -- was
// this tree's invention: upstream has no header limits of any kind
// (component/resource/vehicle.go:125-139 passes the map straight through), and
// no Apple API imposes one. A subscription needing a long token used to lose it
// without being refused, which is worse than a refusal because nothing said so
// loudly enough to act on.
//
// The test stays, pointed the other way: large headers must SURVIVE.
func TestPlanKeepsProviderHeadersThatUsedToExceedTheByteEnvelope(t *testing.T) {
	value := strings.Repeat("a", 8*1024)
	r := planOf(t, `
proxy-providers:
  remote:
    type: http
    url: https://example.com/proxies.yaml
    header:
      X-First: "`+value+`"
      X-Second: "`+value+`"
`)
	if len(r.Errors) != 0 {
		t.Fatalf("a large header refused the configuration: %+v", r.Errors)
	}
	if len(r.Providers) != 1 {
		t.Fatalf("provider dropped with its header: %+v", r.Providers)
	}
	for _, field := range []string{"X-First", "X-Second"} {
		if _, kept := r.Providers[0].Headers[field]; !kept {
			t.Errorf("%s was dropped for its size, and upstream imposes no size: %+v", field, r.Providers[0].Headers)
		}
	}
	for _, notice := range r.Notices {
		if strings.Contains(notice, value[:32]) {
			t.Fatalf("header content leaked in a notice: %q", notice)
		}
	}
}

func TestProviderHeadersAcceptEveryHTTPTokenCharacter(t *testing.T) {
	name := "X!#$%&'*+-.^_`|~09azAZ"
	headers, drops := providerHeaders(map[string]any{name: "value"})
	if len(drops) != 0 {
		t.Fatalf("valid HTTP field name dropped: %+v", drops)
	}
	if got := headers[name]; len(got) != 1 || got[0] != "value" {
		t.Fatalf("valid HTTP field was not preserved: %+v", headers)
	}
}

func TestPlanReportsFileProviderWithoutRefusingTheConfiguration(t *testing.T) {
	y := "rule-providers:\n  local:\n    type: file\n    behavior: classical\n    path: ../private/rules.yaml\n"
	r := planOf(t, y)
	// executor.go:400 logs a provider whose Initial() fails and keeps going, so
	// the kernel starts on this and the provider rides empty.
	if len(r.Errors) != 0 {
		t.Fatalf("a file provider refused the configuration: %+v", r.Errors)
	}
	if len(r.Providers) != 0 {
		t.Fatalf("a file provider must not enter the download plan: %+v", r.Providers)
	}
	named := false
	for _, notice := range r.Notices {
		if strings.Contains(notice, "rule-providers.local") {
			named = true
		}
	}
	if !named {
		t.Fatalf("no notice named the file provider: %+v", r.Notices)
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

// Renamed from TestPlanErrorsOnDanglingRouteAddressSet on 2026-08-27. A set
// naming a provider that does not exist contributes no routes, which is what
// upstream does with it too (listener/sing_tun/server.go:565-593, and mihomo
// accepts the document when driven). It is worth saying and not worth refusing
// the rest of the configuration over.
func TestPlanNotesADanglingRouteAddressSet(t *testing.T) {
	y := "tun:\n  route-address-set:\n    - ruleset-1\n"
	r := planOf(t, y)
	mustNotRefuse(t, r, "a dangling route-address-set")
	if noticeContaining(t, r, "ruleset-1") == "" {
		t.Fatalf("the set goes inert and nothing said so: %+v", r.Notices)
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

func TestPlanReportsOutboundEmbeddedDNSBareFragment(t *testing.T) {
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
			// wireguard.go:496-503 parses the servers and then overwrites
			// ProxyAdapter unconditionally: the fragment selects nothing, but
			// the outbound is built and the configuration starts.
			if len(r.Errors) != 0 {
				t.Fatalf("a nested dns fragment refused the configuration: %+v", r.Errors)
			}
			reported := false
			for _, notice := range r.Notices {
				if strings.Contains(notice, ".dns") {
					reported = true
				}
			}
			if !reported {
				t.Fatalf("no notice reported the inert fragment: %+v", r.Notices)
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
		"notices": true, "structuredNotices": true, "errors": true,
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

// The kernel half of "large headers reach the server as written", which is the
// half that can be measured without a packet capture.
//
// The feature has two halves and only one needs a capture: whether this tree
// DROPS an oversized header (kernel, measurable here) and whether the App's
// downloader actually sends it (client, needs a server or a capture). On
// 2026-08-28 the whole thing was reported to the device lanes as "unverified",
// which reads as "no evidence for any of it" -- and there is evidence for the
// half that this session changed. The caps removed were 64 fields, 16 values
// per field and 8 KiB; a header past them used to vanish silently, which is
// worse than a refusal because nothing said so.
//
// So the boundary is written as a test rather than as a sentence in a message:
// what survives into the plan is measured, and what the downloader does with it
// is named as out of scope right here.
func TestLargeProviderHeadersSurviveIntoThePlan(t *testing.T) {
	big := strings.Repeat("a", 9*1024) // past the old 8 KiB per-value cap
	r := planOf(t, `
proxy-providers:
  p:
    type: http
    url: https://example.com/p.yaml
    header:
      X-Big: "`+big+`"
      X-Second: "`+big+`"
`)
	mustNotRefuse(t, r, "a provider with two 9 KiB headers")
	if len(r.Providers) != 1 {
		t.Fatalf("the provider was dropped with its headers: %+v", r.Providers)
	}
	headers := r.Providers[0].Headers
	if len(headers) != 2 {
		t.Fatalf("a header field was dropped for its size, and upstream imposes no size: %v", headers)
	}
	for _, field := range []string{"X-Big", "X-Second"} {
		if got := len(strings.Join(headers[field], "")); got != len(big) {
			t.Errorf("%s reached the plan truncated: %d bytes of %d", field, got, len(big))
		}
	}
	// Out of scope, stated where someone reading this test will see it: whether
	// the App's downloader puts these on the wire is a client-side question and
	// needs a capture. This test says only that the kernel no longer removes
	// them, which is exactly what changed.
}
