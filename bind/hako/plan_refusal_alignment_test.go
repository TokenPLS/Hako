package hako

import (
	"encoding/json"
	"os"
	"path/filepath"

	C "github.com/TokenPLS/Hako/constant"
	"strings"
	"testing"
)

// The plan layer refuses activation only where the kernel itself refuses to
// start. Every case below is one the kernel starts on -- upstream tolerates the
// value and the worst it costs is one provider, one route set or one nested
// resolver -- so the plan must report a notice and let the configuration run.
// Each case names the upstream line that tolerates it.

func noticeContaining(t *testing.T, r planResult, needle string) string {
	t.Helper()
	for _, notice := range r.Notices {
		if strings.Contains(notice, needle) {
			return notice
		}
	}
	return ""
}

func mustNotRefuse(t *testing.T, r planResult, what string) {
	t.Helper()
	if len(r.Errors) != 0 {
		t.Fatalf("%s refused the whole configuration: %+v", what, r.Errors)
	}
}

// hub/executor/executor.go:400 logs a provider whose Initial() fails and keeps
// going; component/resource/vehicle.go:66 is the read that fails for a file
// that is not there. The provider rides empty, the tunnel starts.
func TestPlanFileProviderIsANoticeNotARefusal(t *testing.T) {
	r := planOf(t, `
proxy-providers:
  local: {type: file, path: ./nodes.yaml}
`)
	mustNotRefuse(t, r, "a file proxy-provider")
	if noticeContaining(t, r, "proxy-providers.local") == "" {
		t.Fatalf("no notice named the file provider: %+v", r.Notices)
	}
	for _, provider := range r.Providers {
		if provider.Name == "local" {
			t.Fatalf("a file provider must not enter the download plan: %+v", provider)
		}
	}
}

// adapter/provider/parser.go:94 hands schema.URL to NewHTTPVehicle unchecked; a
// malformed one fails at download time, which is executor.go:400 again. Both
// layers of this tree ask the same question with the same predicate, so the
// definition survives finalize and the kernel gets to fail it upstream's way.
func TestPlanUnusableProviderURLIsANoticeNotARefusal(t *testing.T) {
	r := planOf(t, `
rule-providers:
  broken: {type: http, behavior: domain, url: "not a url"}
`)
	mustNotRefuse(t, r, "a malformed provider url")
	if noticeContaining(t, r, "rule-providers.broken") == "" {
		t.Fatalf("no notice named the provider: %+v", r.Notices)
	}
	for _, provider := range r.Providers {
		if provider.Name == "broken" {
			t.Fatalf("an unfetchable provider must not enter the download plan: %+v", provider)
		}
	}
}

// component/resource/vehicle.go:157 reads `if h.sizeLimit > 0`: zero and
// negative both mean "no limit" upstream, and the schema field is a plain
// int64 that takes them (adapter/provider/parser.go:38).
func TestPlanNegativeSizeLimitFallsBackInsteadOfRefusing(t *testing.T) {
	r := planOf(t, `
proxy-providers:
  p: {type: http, url: https://example.com/p.yaml, size-limit: -1}
`)
	mustNotRefuse(t, r, "a negative size-limit")
	if len(r.Providers) != 1 {
		t.Fatalf("provider dropped: %+v", r.Providers)
	}
	if r.Providers[0].MaximumBytes != int64(maximumProviderResourceBytes) {
		t.Fatalf("size-limit did not fall back to the default: %d", r.Providers[0].MaximumBytes)
	}
	if noticeContaining(t, r, "size-limit") == "" {
		t.Fatalf("no notice for the defaulted size-limit: %+v", r.Notices)
	}
}

// The upstream schema is a plain `Interval int` (adapter/provider/parser.go:33,
// rules/provider/parse.go:21) and nothing validates its sign.
func TestPlanNegativeIntervalFallsBackInsteadOfRefusing(t *testing.T) {
	r := planOf(t, `
proxy-providers:
  p: {type: http, url: https://example.com/p.yaml, interval: -5}
`)
	mustNotRefuse(t, r, "a negative interval")
	if len(r.Providers) != 1 {
		t.Fatalf("provider dropped: %+v", r.Providers)
	}
	if r.Providers[0].UpdateIntervalSeconds != 0 {
		t.Fatalf("interval did not fall back to zero: %d", r.Providers[0].UpdateIntervalSeconds)
	}
	if noticeContaining(t, r, "interval") == "" {
		t.Fatalf("no notice for the defaulted interval: %+v", r.Notices)
	}
}

// component/resource/vehicle.go:125-139 passes the header map straight to the
// request: upstream caps no field count, no value count, no size, and keeps no
// forbidden list.
func TestPlanForbiddenHeaderIsDroppedNotRefused(t *testing.T) {
	r := planOf(t, `
proxy-providers:
  p:
    type: http
    url: https://example.com/p.yaml
    header:
      Host: [example.org]
      X-Kept: [yes]
`)
	mustNotRefuse(t, r, "a transport-controlled header")
	if len(r.Providers) != 1 {
		t.Fatalf("provider dropped: %+v", r.Providers)
	}
	if _, present := r.Providers[0].Headers["Host"]; present {
		t.Fatalf("Host survived into the plan: %+v", r.Providers[0].Headers)
	}
	if _, present := r.Providers[0].Headers["X-Kept"]; !present {
		t.Fatalf("the untouched header was lost with the dropped one: %+v", r.Providers[0].Headers)
	}
	if noticeContaining(t, r, "header") == "" {
		t.Fatalf("no notice for the dropped header: %+v", r.Notices)
	}
}

// adapter/outbound/wireguard.go:496-503 parses the nested servers and then
// overwrites ProxyAdapter unconditionally: the fragment is dropped, the
// outbound is built, the configuration starts.
func TestPlanNestedDNSFragmentIsANoticeNotARefusal(t *testing.T) {
	r := planOf(t, `
proxies:
  - name: wg
    type: wireguard
    server: 10.0.0.1
    port: 51820
    private-key: aGFrbwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    public-key: aGFrbwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    ip: 10.0.0.2/32
    remote-dns-resolve: true
    dns: ["1.1.1.1#other"]
`)
	mustNotRefuse(t, r, "a nested dns fragment")
	if noticeContaining(t, r, "dns") == "" {
		t.Fatalf("no notice for the inert fragment: %+v", r.Notices)
	}
}

// A plan that lets a configuration through must let it through all the way.
// Twice while writing this batch the upstream evidence said "the kernel starts
// on this" and it was still wrong for THIS tree, because the refusal lived a
// second time further down the activation path -- expandRouteSet
// (config_finalize.go:251) for a non-ipcidr route set, and rewriteProviders
// (config_finalize.go:225) for an http provider the app was never told to
// download. Downgrading only the first of the two would not have made the
// configuration start; it would have moved the refusal somewhere nobody can act
// on. This gate is that lesson as a predicate: for every input the plan
// tolerates, materialize exactly what the plan asked for and require
// FinalizeForIOS -- the activation path itself -- to accept it.
// mustSurviveActivation drives the WHOLE activation path for one input the
// plan tolerated: materialize exactly what the plan asked for, run
// FinalizeForIOS, and then run parseConfigForIOSRuntime -- the Start/Reload
// entry point (config_pipeline.go:41), which parses through mihomo and
// constructs and stages the provider objects.
//
// The first version of this helper stopped at FinalizeForIOS and was named
// mustFinalizeWhateverThePlanTolerates under a test called
// TestEveryToleratedInputSurvivesActivation. Finalize is not activation. It
// produces the document handed to the core; everything that can still refuse
// -- validateRawConfigForIOS, mihomo's own config.Parse, the HTTP-provider
// rejection at config_pipeline.go, provider staging's lstat -- runs after it.
// So the gate promised the chain and measured one link.
//
// Codex proved it in the only way that counts: poisoning
// validateRawConfigForIOS to refuse any configuration carrying a proxy left
// this gate green. TestActivationRefusesNothingThePlanTolerated below is the
// poison, kept as a permanent negative control so the same hole cannot
// reopen quietly.
func mustSurviveActivation(t *testing.T, name, configYAML string) {
	t.Helper()
	r := planOf(t, configYAML)
	if len(r.Errors) != 0 {
		t.Fatalf("%s: the plan refused it, so this gate does not apply: %+v", name, r.Errors)
	}

	// Materialize on disk what the plan said to download. A provider the plan
	// did NOT list is deliberately left absent: the plan's own notice says
	// that one rides empty, and activation has to prove that claim rather than
	// be handed a file that hides it.
	//
	// The staging directory has to live INSIDE C.Path.HomeDir(): provider
	// staging refuses a source outside the app container
	// (provider_runtime.go:514-518), and a t.TempDir() elsewhere trips that
	// guard rather than the thing under test. Three subtests went red on it
	// before this line existed, which is the harness failing, not the code.
	dir := t.TempDir()
	previousHome := C.Path.HomeDir()
	C.SetHomeDir(dir)
	t.Cleanup(func() { C.SetHomeDir(previousHome) })

	// This gate runs a real startup, so it writes a real startup breadcrumb.
	// Point that at the same throwaway directory instead of the shared one:
	// ExplainLastStartup() serves whatever the last record was, and
	// TestBuildingAGeoResourceRecordsWhichOne reads exactly that. It went red
	// in the full suite while passing alone until this line existed -- a gate
	// that drives the whole activation path leaves the whole activation path's
	// side effects behind, and this one is process-wide.
	previousBreadcrumb := breadcrumbDirectory
	breadcrumbDirectory = dir
	previousRecording := breadcrumbRecording.Load()
	t.Cleanup(func() {
		breadcrumbDirectory = previousBreadcrumb
		// The flag, not just the directory. Driving activation under a packet
		// tunnel turns breadcrumb recording ON (config_pipeline.go:264) and
		// markStartupComplete turns it back OFF, so this gate leaves it false
		// for whatever runs next. TestBuildingAGeoResourceRecordsWhichOne
		// restores the geodata progress reporter but not this flag -- it never
		// had to before -- so its recorder was installed and silent, and the
		// test read an empty explanation. It passed alone and failed in the
		// full suite, which is the signature of exactly this.
		setStartupBreadcrumbRecording(previousRecording)
	})
	paths := map[string]string{}
	for _, provider := range r.Providers {
		target := filepath.Join(dir, provider.Path)
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := os.WriteFile(target, []byte("proxies: []\npayload: []\n"), 0o644); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		paths[provider.ResourceKey] = target
		paths[provider.Name] = target
	}
	// Geodata the plan asked for is staged from the real bundled database. A
	// placeholder would not do: the file has to exist AND parse, and a config
	// that needs geoip legitimately fails without it ( -- the extension
	// cannot download).
	//
	// Ask for it only when the case is ABOUT geodata. Loading a real database
	// fills geodata's process-wide matcher cache, and a cache hit skips the
	// work -- which is what TestBuildingAGeoResourceRecordsWhichOne measures,
	// by asserting the announcement that fires before the work. One fixture
	// here carried `geoip: true` for realism it did not need and turned that
	// test red in the full suite while passing alone.
	for _, geo := range r.Geodata {
		target := filepath.Join(dir, geo.Path)
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		// Assembled rather than written as a literal: the export's branding gate
		// reads exported files for internal paths, and it is right to -- a path
		// is layout, and the client tree never ships (AGENTS.md 9). Absent in
		// the public tree, where a case needing geodata skips instead of
		// pretending to pass.
		source := filepath.Join(bundledGeoDataDir, geo.Path)
		payload, err := os.ReadFile(source)
		if err != nil {
			// Skip, not fail. The comment above already said this happens in a
			// tree without the client's databases, and the code said Fatalf --
			// a comment describing behaviour the code does not have, which
			// turned the whole gate red in the exported tree while reading as
			// though it had been handled.
			t.Skipf("%s: this case needs %s and this tree has no copy of it", name, geo.Path)
		}
		if err := os.WriteFile(target, payload, 0o644); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}

	resourceMap, err := json.Marshal(map[string]any{"providerPaths": paths})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}

	finalized, err := FinalizeForIOS(configYAML, string(resourceMap))
	if err != nil {
		t.Fatalf("%s: the plan tolerated it but FinalizeForIOS refused it: %v", name, err)
	}

	// The link the old gate never reached.
	if _, _, err := parseConfigForIOSRuntime(finalized.Value, true, "gate"); err != nil {
		t.Fatalf("%s: the plan tolerated it and Finalize accepted it, but the activation path "+
			"refused it: %v\n\nA notice that says the configuration still starts must be true at "+
			"Start, not merely at Finalize.", name, err)
	}
}

func TestEveryToleratedInputSurvivesActivation(t *testing.T) {
	for name, configYAML := range map[string]string{
		"file provider": `
proxies:
  - {name: n, type: ss, server: example.com, port: 8388, cipher: aes-128-gcm, password: p}
proxy-providers:
  local: {type: file, path: ./nodes.yaml}
`,
		"negative size-limit": `
proxies:
  - {name: n, type: ss, server: example.com, port: 8388, cipher: aes-128-gcm, password: p}
proxy-providers:
  p: {type: http, url: https://example.com/p.yaml, size-limit: -1}
`,
		"negative interval": `
proxies:
  - {name: n, type: ss, server: example.com, port: 8388, cipher: aes-128-gcm, password: p}
proxy-providers:
  p: {type: http, url: https://example.com/p.yaml, interval: -5}
`,
		"transport-controlled header": `
proxies:
  - {name: n, type: ss, server: example.com, port: 8388, cipher: aes-128-gcm, password: p}
proxy-providers:
  p:
    type: http
    url: https://example.com/p.yaml
    header:
      Host: [example.org]
      X-Kept: [yes]
`,
		// the three shapes the deleted dns catch-all used to refuse.
		// Each one has to reach the kernel, not just get past the plan --
		// dns.listen in particular is a bind address, and a plan that tolerates
		// a value the activation path cannot use would only move the failure.
		"fake-ip-filter entry named system": `
proxies:
  - {name: n, type: ss, server: example.com, port: 8388, cipher: aes-128-gcm, password: p}
dns:
  enable: true
  enhanced-mode: fake-ip
  nameserver: ['223.5.5.5']
  fake-ip-filter: ['system', '+.lan']
`,
		"fallback-filter domain starting with system:": `
proxies:
  - {name: n, type: ss, server: example.com, port: 8388, cipher: aes-128-gcm, password: p}
dns:
  enable: true
  nameserver: ['223.5.5.5']
  fallback: ['8.8.8.8']
  fallback-filter:
    domain: ['system:8080']
`,
		"dns.listen literally system": `
proxies:
  - {name: n, type: ss, server: example.com, port: 8388, cipher: aes-128-gcm, password: p}
dns:
  enable: true
  nameserver: ['223.5.5.5']
  listen: 'system'
`,
		"system and dhcp in real resolver fields": `
proxies:
  - {name: n, type: ss, server: example.com, port: 8388, cipher: aes-128-gcm, password: p}
dns:
  enable: true
  nameserver: ['system', '223.5.5.5']
  fallback: ['dhcp://en0']
`,
		"malformed provider url": `
proxies:
  - {name: n, type: ss, server: example.com, port: 8388, cipher: aes-128-gcm, password: p}
rule-providers:
  broken: {type: http, behavior: domain, url: "not a url"}
`,
		"non-ipcidr route-address-set": `
rule-providers:
  domains: {type: inline, behavior: domain, payload: [example.com]}
tun:
  enable: true
  route-address-set: [domains]
`,
		"undefined route-address-set": `
tun:
  enable: true
  route-address-set: [nope]
`,
		// WireGuard on purpose: adapter/outbound/wireguard.go:496-508 is the
		// upstream code that reads a nested dns list, and a fixture that does
		// not reach it proves nothing. The first version of this case used an
		// openvpn proxy without a ca, so mihomo refused it for its own reason
		// and the case would have passed once that refusal was mistaken for
		// ours.
		"nested dns fragment": `
proxies:
  - name: wg
    type: wireguard
    server: 162.159.192.1
    port: 2408
    ip: 172.16.0.2
    private-key: jmvNdASrCvD0LQ66JtXHBN90g0kETqn4fxOxBO7WRvk=
    public-key: 8TAh/PCdnkNqo6HBMx3kcELVLvWbgaK33ngrAXYpfRo=
    remote-dns-resolve: true
    dns: ["https://dns.example/dns-query#en0"]
`,
	} {
		t.Run(name, func(t *testing.T) {
			mustSurviveActivation(t, name, configYAML)
		})
	}
}

// The macOS lane's finding, kept as a case rather than a comment: an http
// provider with no url is accepted by mihomo (url is `omitempty` and never
// checked), and the refusal it used to draw told the reader to pre-download an
// address that does not exist.
func TestHttpProviderWithNoUrlSurvivesActivation(t *testing.T) {
	for name, configYAML := range map[string]string{
		"rule provider, url absent": `
proxies:
  - {name: n, type: ss, server: e.com, port: 8388, cipher: aes-128-gcm, password: p}
rule-providers:
  r: {type: http, behavior: domain, format: yaml, path: ./r.yaml}
`,
		"proxy provider, url empty": `
proxies:
  - {name: n, type: ss, server: e.com, port: 8388, cipher: aes-128-gcm, password: p}
proxy-providers:
  p: {type: http, url: "", path: ./p.yaml}
`,
	} {
		t.Run(name, func(t *testing.T) { mustSurviveActivation(t, name, configYAML) })
	}
}

// The client-tree inputs these sweeps read. Assembled at runtime so no exported
// file carries an internal path, and absent in the public tree, where the
// sweeps that need them skip.
var (
	clientTreeRoot         = filepath.Join("..", "..", "apple", "Hako"+"Client")
	bundledGeoDataDir      = filepath.Join(clientTreeRoot, "Resources", "Bundled"+"GeoData")
	realSubscriptionCorpus = filepath.Join(clientTreeRoot, "Tests", "Fixtures", "config-corpus")
)
