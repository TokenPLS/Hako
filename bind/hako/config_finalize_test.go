package hako

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	P "github.com/TokenPLS/Hako/constant/provider"
	ruleprovider "github.com/TokenPLS/Hako/rules/provider"
	"gopkg.in/yaml.v3"
)

func TestFinalizeRewritesHTTPProviderToFile(t *testing.T) {
	y := "rule-providers:\n  rule1:\n    type: http\n    url: https://e/r.yaml\n    behavior: classical\n"
	m := `{"providerPaths":{"rule1":"/data/providers/rule1.yaml"}}`
	out, err := FinalizeForIOS(y, m)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	got := out.Value
	if !strings.Contains(got, "type: file") || !strings.Contains(got, "/data/providers/rule1.yaml") {
		t.Fatalf("not rewritten to file:\n%s", got)
	}
	if strings.Contains(got, "https://e/r.yaml") {
		t.Fatalf("url should be dropped:\n%s", got)
	}
}

func TestFinalizeNamespacesSameNamedProxyAndRuleProviders(t *testing.T) {
	y := `
proxy-providers:
  shared: {type: http, url: https://example.com/proxies.yaml}
rule-providers:
  shared: {type: http, behavior: domain, url: https://example.com/rules.yaml}
`
	resourceMap := `{"providerPaths":{"proxy:shared":"/published/proxy.yaml","rule:shared":"/published/rule.yaml"}}`
	out, err := FinalizeForIOS(y, resourceMap)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Proxy map[string]struct {
			Path string `yaml:"path"`
		} `yaml:"proxy-providers"`
		Rule map[string]struct {
			Path string `yaml:"path"`
		} `yaml:"rule-providers"`
	}
	if err := yaml.Unmarshal([]byte(out.Value), &document); err != nil {
		t.Fatal(err)
	}
	if document.Proxy["shared"].Path != "/published/proxy.yaml" || document.Rule["shared"].Path != "/published/rule.yaml" {
		t.Fatalf("namespaced paths were crossed: %+v / %+v", document.Proxy, document.Rule)
	}
}

func TestFinalizeRejectsAmbiguousLegacyProviderKey(t *testing.T) {
	y := `
proxy-providers:
  shared: {type: http, url: https://example.com/proxies.yaml}
rule-providers:
  shared: {type: http, behavior: domain, url: https://example.com/rules.yaml}
`
	_, err := FinalizeForIOS(y, `{"providerPaths":{"shared":"/published/shared.yaml"}}`)
	if err == nil || !strings.Contains(err.Error(), "schema-v2") {
		t.Fatalf("ambiguous legacy key was accepted: %v", err)
	}
}

func TestFinalizeRemovesRemoteProviderSecretsButKeepsRuntimePolicy(t *testing.T) {
	y := `
proxy-providers:
  remote:
    type: http
    url: https://example.com/proxies.yaml
    interval: 3600
    size-limit: 10240
    proxy: DIRECT
    age-secret-key: AGE-SECRET-KEY-PRIVATE
    header:
      Authorization: [Bearer private-token]
    filter: keep
    dialer-proxy: relay
    health-check: {enable: true, url: https://example.com/generate_204}
    override: {udp: true}
rule-providers:
  remote:
    type: http
    behavior: domain
    url: https://example.com/rules.yaml
    interval: 3600
    size-limit: 10240
    proxy: DIRECT
    header:
      Authorization: [Bearer private-rule-token]
`
	out, err := FinalizeForIOS(y, `{"providerPaths":{"proxy:remote":"/published/proxies.yaml","rule:remote":"/published/rules.yaml"}}`)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"AGE-SECRET-KEY-PRIVATE", "private-token", "private-rule-token"} {
		if strings.Contains(out.Value, secret) {
			t.Fatalf("finalized config leaked %q:\n%s", secret, out.Value)
		}
	}
	var document map[string]any
	if err := yaml.Unmarshal([]byte(out.Value), &document); err != nil {
		t.Fatal(err)
	}
	providers := document["proxy-providers"].(map[string]any)
	provider := providers["remote"].(map[string]any)
	for _, removed := range []string{"url", "interval", "size-limit", "proxy", "age-secret-key", "header"} {
		if _, exists := provider[removed]; exists {
			t.Errorf("remote-only field %q survived: %+v", removed, provider)
		}
	}
	for _, kept := range []string{"filter", "dialer-proxy", "health-check", "override"} {
		if _, exists := provider[kept]; !exists {
			t.Errorf("runtime field %q was removed: %+v", kept, provider)
		}
	}
	ruleProviders := document["rule-providers"].(map[string]any)
	ruleProvider := ruleProviders["remote"].(map[string]any)
	for _, removed := range []string{"url", "interval", "size-limit", "proxy", "header"} {
		if _, exists := ruleProvider[removed]; exists {
			t.Errorf("rule remote-only field %q survived: %+v", removed, ruleProvider)
		}
	}
	if ruleProvider["behavior"] != "domain" {
		t.Errorf("rule runtime behavior was removed: %+v", ruleProvider)
	}
}

// a provider with a fetch proxy is never pre-downloaded, at any budget, so the app never
// has a path to hand FinalizeForIOS for it. This is the other half of that decision, proven
// rather than assumed: this function needed NO new code for it. rewriteProviders' existing
// !found branch already left a provider's WHOLE definition untouched whenever the resourceMap
// has no path for it (the app has no copy at activation, or a host it could not reach) --
// 's pre-existing reason for that branch to exist -- and a provider the app has decided not
// to attempt is indistinguishable from one it merely failed to reach. `proxy` survives for the
// same reason `url` does: nothing here special-cases it.
func TestFinalizeLeavesAProxyBoundProviderRemoteForTheCoreToFetch(t *testing.T) {
	y := "proxy-providers:\n  air:\n    type: http\n    url: https://example.com/air.yaml\n    proxy: HK\n    interval: 3600\n"
	// No entry for "air" in providerPaths: the app decided not to fetch this one.
	out, err := FinalizeForIOS(y, `{"providerPaths":{}}`)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal([]byte(out.Value), &document); err != nil {
		t.Fatal(err)
	}
	provider := document["proxy-providers"].(map[string]any)["air"].(map[string]any)
	if provider["type"] != "http" {
		t.Fatalf("a provider the app never staged must stay remote for the core to fetch, got type=%v", provider["type"])
	}
	if provider["proxy"] != "HK" {
		t.Fatalf("the fetch proxy must reach the core verbatim so it can dial through it, got: %+v", provider)
	}
	if provider["url"] != "https://example.com/air.yaml" {
		t.Fatalf("the url the core will fetch from must survive too, got: %+v", provider)
	}
	if _, staged := provider["path"]; staged {
		t.Fatalf("a provider the core will fetch itself must not carry a local path: %+v", provider)
	}
}

func TestFinalizePreservesUnsupportedTunIntentForPreflight(t *testing.T) {
	y := "tun:\n  auto-redirect: true\n  stack: gvisor\n"
	out, err := FinalizeForIOS(y, "{}")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	got := out.Value
	if !strings.Contains(got, "auto-redirect: true") {
		t.Fatalf("unsupported route intent was silently discarded:\n%s", got)
	}
	if !strings.Contains(got, "stack: gvisor") {
		t.Fatalf("unrelated key lost:\n%s", got)
	}
}

func TestFinalizeExpandsRouteAddressSet(t *testing.T) {
	dir := t.TempDir()
	setFile := filepath.Join(dir, "cn.yaml")
	if err := os.WriteFile(setFile, []byte("payload:\n  - 1.0.0.0/24\n  - 2.0.0.0/16\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	y := "rule-providers:\n  cn:\n    type: http\n    behavior: ipcidr\n    url: https://e/cn.yaml\n" +
		"tun:\n  route-address-set:\n    - cn\n"
	m := `{"providerPaths":{"cn":"` + setFile + `"}}`
	out, err := FinalizeForIOS(y, m)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	got := out.Value
	if strings.Contains(got, "route-address-set") {
		t.Fatalf("route-address-set not consumed:\n%s", got)
	}
	if !strings.Contains(got, "1.0.0.0/24") || !strings.Contains(got, "2.0.0.0/16") {
		t.Fatalf("CIDRs not expanded into route-address:\n%s", got)
	}
	var document map[string]any
	if err := yaml.Unmarshal([]byte(got), &document); err != nil {
		t.Fatal(err)
	}
	provider := document["rule-providers"].(map[string]any)["cn"].(map[string]any)
	if safe, exists := provider[providerSideUpdateSafeField].(bool); !exists || safe {
		t.Fatalf("platform route provider was not marked side-update unsafe: %+v", provider)
	}
}

func TestFinalizeMarksOrdinaryRuleProviderSideUpdateSafe(t *testing.T) {
	y := "rule-providers:\n  ordinary:\n    type: http\n    behavior: domain\n    url: https://e/rules.yaml\n"
	out, err := FinalizeForIOS(y, `{"providerPaths":{"ordinary":"/published/rules.yaml"}}`)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal([]byte(out.Value), &document); err != nil {
		t.Fatal(err)
	}
	provider := document["rule-providers"].(map[string]any)["ordinary"].(map[string]any)
	if safe, exists := provider[providerSideUpdateSafeField].(bool); !exists || !safe {
		t.Fatalf("ordinary rule provider was not marked side-update safe: %+v", provider)
	}
}

func TestInertRouteReferencesKeepOrdinaryRuleSideUpdates(t *testing.T) {
	for _, behavior := range []string{"domain", "classical"} {
		for _, field := range []string{"route-address-set", "route-exclude-address-set"} {
			t.Run(behavior+"/"+field, func(t *testing.T) {
				input := "rule-providers:\n  ordinary:\n    type: http\n    behavior: " + behavior +
					"\n    url: https://rules.example.test/rules.yaml\ntun:\n  " + field + ": [ordinary]\n"
				out, err := FinalizeForIOS(input, `{}`)
				if err != nil {
					t.Fatal(err)
				}
				var document map[string]any
				if err := yaml.Unmarshal([]byte(out.Value), &document); err != nil {
					t.Fatal(err)
				}
				provider := document["rule-providers"].(map[string]any)["ordinary"].(map[string]any)
				if safe, _ := provider[providerSideUpdateSafeField].(bool); !safe {
					t.Fatal("a rule set that contributes no platform routes must remain eligible for background rule updates")
				}
				if _, exists := document["tun"].(map[string]any)[field]; exists {
					t.Fatal("inert route reference survived finalization")
				}
			})
		}
	}
}

func TestFinalizeReadsCandidateButWritesPublishedProviderPath(t *testing.T) {
	dir := t.TempDir()
	staging := filepath.Join(dir, ".tmp-revision", "providers", "cn.yaml")
	if err := os.MkdirAll(filepath.Dir(staging), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staging, []byte("payload:\n  - 10.0.0.0/8\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	published := filepath.Join(dir, "revision", "providers", "cn.yaml")
	y := "rule-providers:\n  cn:\n    type: http\n    behavior: ipcidr\n    url: https://e/cn.yaml\n" +
		"tun:\n  route-address-set:\n    - cn\n"
	m := `{"providerPaths":{"cn":"` + published + `"},"providerReadPaths":{"cn":"` + staging + `"}}`
	out, err := FinalizeForIOS(y, m)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !strings.Contains(out.Value, published) || strings.Contains(out.Value, staging) {
		t.Fatalf("final YAML leaked staging path:\n%s", out.Value)
	}
	if !strings.Contains(out.Value, "10.0.0.0/8") {
		t.Fatalf("candidate CIDR was not expanded:\n%s", out.Value)
	}
}

// Both renamed from ...Rejects... on 2026-08-27. Upstream refuses neither:
// listener/sing_tun/server.go:565-593 falls to `default: return` for a set
// whose behavior is not ipcidr, and mihomo accepts both shapes when driven
// (measured, not read). The set contributes no routes either way -- the
// question was only whether the user loses the rest of their configuration
// with it.
//
// A route set that expands to nothing is still worth saying out loud, so
// expandRouteSet logs which names were skipped. These pin the tolerance; the
// notice is not asserted here because the log is not this function's return
// value.
func TestFinalizeSkipsMissingRouteSetCandidate(t *testing.T) {
	y := "tun:\n  route-address-set:\n    - missing\n"
	out, err := FinalizeForIOS(y, `{}`)
	if err != nil {
		t.Fatalf("an undefined route-address-set provider is inert upstream, not fatal: %v", err)
	}
	if strings.Contains(out.Value, "missing") {
		t.Fatalf("the skipped set still reached the core:\n%s", out.Value)
	}
}

// The reader's OpenClash template (2026-09-06): tun.route-exclude-address-set names an http
// ipcidr set, and since phase two a switch that cannot fetch it leaves no file and no
// path. Upstream reads a route set from the loaded provider and a provider that has not loaded
// contributes nothing while the tun comes up (listener/sing_tun/server.go), so a set the App
// has no bytes for is inert here too -- the tunnel starts without its routes, the provider
// stays remote for the core's own first load, and the App's first-load retry republishes with
// the routes expanded once it has the bytes.
func TestFinalizeSkipsARouteSetTheAppHasNoBytesFor(t *testing.T) {
	y := `
rule-providers:
  cn_ip: {type: http, behavior: ipcidr, format: mrs, url: https://example.com/cn_ip.mrs, interval: 86400}
tun:
  route-exclude-address-set: [cn_ip]
`
	out, err := FinalizeForIOS(y, `{}`)
	if err != nil {
		t.Fatalf("a route set the App has no bytes for is inert, not fatal: %v", err)
	}
	for _, key := range []string{"route-exclude-address-set", "route-exclude-address"} {
		if strings.Contains(out.Value, key) {
			t.Fatalf("%s reached the core although nothing could be expanded:\n%s", key, out.Value)
		}
	}
	var document map[string]any
	if err := yaml.Unmarshal([]byte(out.Value), &document); err != nil {
		t.Fatal(err)
	}
	provider := document["rule-providers"].(map[string]any)["cn_ip"].(map[string]any)
	if provider["type"] != "http" || provider["url"] != "https://example.com/cn_ip.mrs" {
		t.Fatalf("the provider must stay remote so the core loads its rules half itself, got %+v", provider)
	}
}

// 's real cases stay refused: a path the App did map but that is not a readable regular
// file is the App's bug (it wrote no such file), and must fail loud rather than go inert.
func TestFinalizeStillRefusesAMappedRouteSetFileThatIsNotThere(t *testing.T) {
	y := `
rule-providers:
  cn_ip: {type: http, behavior: ipcidr, format: mrs, url: https://example.com/cn_ip.mrs}
tun:
  route-exclude-address-set: [cn_ip]
`
	_, err := FinalizeForIOS(y, `{"providerPaths":{"cn_ip":"`+filepath.Join(t.TempDir(), "never-written.mrs")+`"}}`)
	if err == nil || !strings.Contains(err.Error(), "read route-exclude-address-set provider") {
		t.Fatalf("a mapped path nobody wrote must still refuse, got %v", err)
	}
}

func TestFinalizeSkipsNonIPCidrRouteSet(t *testing.T) {
	y := `
rule-providers:
  domains: {type: inline, behavior: domain, payload: [example.com]}
tun:
  route-address-set: [domains]
`
	out, err := FinalizeForIOS(y, `{}`)
	if err != nil {
		t.Fatalf("a non-ipcidr route-address-set is inert upstream, not fatal: %v", err)
	}
	if strings.Contains(out.Value, "route-address-set") {
		t.Fatalf("the skipped set still reached the core:\n%s", out.Value)
	}
}

func TestFinalizeExpandsInlineRouteSet(t *testing.T) {
	y := `
rule-providers:
  private:
    type: inline
    behavior: ipcidr
    payload:
      - 10.0.0.1/8
      - 10.0.0.0/8
tun:
  route-address-set: [private]
`
	out, err := FinalizeForIOS(y, `{}`)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Tun struct {
			RouteAddress []string `yaml:"route-address"`
		} `yaml:"tun"`
	}
	if err := yaml.Unmarshal([]byte(out.Value), &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Tun.RouteAddress) != 1 || document.Tun.RouteAddress[0] != "10.0.0.0/8" {
		t.Fatalf("inline prefixes were not canonicalized/deduplicated:\n%s", out.Value)
	}
}

func TestFinalizeExpandsTextAndMRSRouteSets(t *testing.T) {
	directory := t.TempDir()
	textPath := filepath.Join(directory, "text.txt")
	if err := os.WriteFile(textPath, []byte("192.0.2.0/24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var mrs bytes.Buffer
	if err := ruleprovider.ConvertToMrs([]byte("2001:db8::/32\n"), P.IPCIDR, P.TextRule, &mrs); err != nil {
		t.Fatal(err)
	}
	mrsPath := filepath.Join(directory, "set.mrs")
	if err := os.WriteFile(mrsPath, mrs.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	y := `
rule-providers:
  text-set: {type: http, behavior: ipcidr, format: text, url: https://example.com/text}
  mrs-set: {type: http, behavior: ipcidr, format: mrs, url: https://example.com/mrs}
tun:
  route-address-set: [text-set, mrs-set]
`
	resourceMap := `{"providerPaths":{"text-set":"` + textPath + `","mrs-set":"` + mrsPath + `"}}`
	out, err := FinalizeForIOS(y, resourceMap)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.Value, "192.0.2.0/24") || !strings.Contains(out.Value, "2001:db8::/32") {
		t.Fatalf("text/MRS prefixes were not expanded:\n%s", out.Value)
	}
}

func TestFinalizeRejectsUnsafeOrInvalidRouteSet(t *testing.T) {
	directory := t.TempDir()
	y := `
rule-providers:
  set: {type: http, behavior: ipcidr, format: yaml, url: https://example.com/set}
tun:
  route-address-set: [set]
`
	t.Run("invalid CIDR", func(t *testing.T) {
		path := filepath.Join(directory, "invalid.yaml")
		if err := os.WriteFile(path, []byte("payload: [not-a-prefix]\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := FinalizeForIOS(y, `{"providerPaths":{"set":"`+path+`"}}`); err == nil || !strings.Contains(err.Error(), "invalid") {
			t.Fatalf("invalid CIDR was accepted: %v", err)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		target := filepath.Join(directory, "target.yaml")
		if err := os.WriteFile(target, []byte("payload: [10.0.0.0/8]\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(directory, "link.yaml")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := FinalizeForIOS(y, `{"providerPaths":{"set":"`+link+`"}}`); err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("symlink was accepted: %v", err)
		}
	})
	t.Run("oversized", func(t *testing.T) {
		path := filepath.Join(directory, "oversized.yaml")
		file, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Truncate(int64(maximumProviderResourceBytes) + 1); err != nil {
			file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := FinalizeForIOS(y, `{"providerPaths":{"set":"`+path+`"}}`); err == nil || !strings.Contains(err.Error(), "size") {
			t.Fatalf("oversized provider was accepted: %v", err)
		}
	})
	t.Run("unsafe MRS length", func(t *testing.T) {
		path := filepath.Join(directory, "unsafe.mrs")
		decoded := buildDecodedMRSTestPayload(t, P.IPCIDR, 1, func(output *bytes.Buffer) {
			if err := binary.Write(output, binary.BigEndian, int64(^uint64(0)>>1)); err != nil {
				t.Fatal(err)
			}
		})
		if err := os.WriteFile(path, compressMRSTestPayload(t, decoded), 0o600); err != nil {
			t.Fatal(err)
		}
		mrsYAML := `
rule-providers:
  set: {type: http, behavior: ipcidr, format: mrs, url: https://example.com/set}
tun:
  route-address-set: [set]
`
		var panicValue any
		var err error
		func() {
			defer func() { panicValue = recover() }()
			_, err = FinalizeForIOS(mrsYAML, `{"providerPaths":{"set":"`+path+`"}}`)
		}()
		if panicValue != nil {
			t.Fatalf("unsafe route-set MRS panicked: %v", panicValue)
		}
		if err == nil || !strings.Contains(err.Error(), "MRS") {
			t.Fatalf("unsafe route-set MRS error = %v", err)
		}
	})
}
