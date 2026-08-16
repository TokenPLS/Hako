package hako

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	P "github.com/TokenPLS/Hako/constant/provider"
	ruleprovider "github.com/TokenPLS/Hako/rules/provider"
	"github.com/TokenPLS/Hako/tunnel"
)

func TestProxyProviderRuntimeStripsPairedEgressOverridesWithoutMutatingPublishedBytes(t *testing.T) {
	options := testOptions(t)
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	published := filepath.Join(options.WorkingPath, "published-proxies.yaml")
	original := []byte("proxies:\n  - {name: node, type: direct, interface-name: en0, routing-mark: 233}\n")
	if err := os.WriteFile(published, original, 0o600); err != nil {
		t.Fatal(err)
	}
	content := fmt.Sprintf(`
dns:
  enable: true
  nameserver: [8.8.8.8]
proxy-providers:
  controlled:
    type: file
    path: %q
proxy-groups:
  - name: Controlled
    type: select
    use: [controlled]
rules:
  - MATCH,Controlled
`, published)
	service, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Start(content); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	entry := service.providerRuntime.entries[providerRuntimeKey("proxy", "controlled")]
	runtimePayload, err := os.ReadFile(entry.runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(runtimePayload, []byte("interface-name")) || bytes.Contains(runtimePayload, []byte("routing-mark")) {
		t.Fatalf("paired egress override survived in private runtime provider: %q", runtimePayload)
	}
	if got := tunnel.Providers()["controlled"].Count(); got != 1 {
		t.Fatalf("runtime proxy provider count = %d, want 1", got)
	}
	publishedPayload, err := os.ReadFile(published)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(publishedPayload, original) {
		t.Fatal("private runtime sanitization mutated the published proxy provider")
	}
}

func TestRuleProviderRuntimeStripsMetadataNoopsWithoutMutatingPublishedBytes(t *testing.T) {
	options := testOptions(t)
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	published := filepath.Join(options.WorkingPath, "published-classical.yaml")
	original := []byte("payload:\n  - PROCESS-NAME,curl\n  - DOMAIN,example.com\n  - UID,501\n  - IN-USER,alice\n  - SOURCE-APP-SIGNING-ID,com.example.cli\n  - SOURCE-APP-TEAM-ID,ABCDE12345\n")
	if err := os.WriteFile(published, original, 0o600); err != nil {
		t.Fatal(err)
	}
	content := fmt.Sprintf(`
dns:
  enable: true
  nameserver: [8.8.8.8]
rule-providers:
  controlled:
    type: file
    behavior: classical
    format: yaml
    path: %q
rules:
  - RULE-SET,controlled,DIRECT
  - MATCH,DIRECT
`, published)
	service, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Start(content); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	entry := service.providerRuntime.entries[providerRuntimeKey("rule", "controlled")]
	runtimePayload, err := os.ReadFile(entry.runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(runtimePayload, []byte("PROCESS")) || bytes.Contains(runtimePayload, []byte("UID")) || bytes.Contains(runtimePayload, []byte("IN-USER")) || bytes.Contains(runtimePayload, []byte("SOURCE-APP")) {
		t.Fatalf("metadata no-op survived in private runtime provider: %q", runtimePayload)
	}
	if !bytes.Contains(runtimePayload, []byte("DOMAIN,example.com")) {
		t.Fatalf("executable provider rule was lost: %q", runtimePayload)
	}
	if got := tunnel.RuleProviders()["controlled"].Count(); got != 1 {
		t.Fatalf("runtime provider count = %d, want 1", got)
	}
	publishedPayload, err := os.ReadFile(published)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(publishedPayload, original) {
		t.Fatal("private runtime sanitization mutated the published provider")
	}
}

func TestProviderSideUpdateUsesCopyOnWriteRuntimeShadows(t *testing.T) {
	options := testOptions(t)
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	publishedDirectory := filepath.Join(options.WorkingPath, "store", "published", "providers")
	if err := os.MkdirAll(publishedDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	proxyPath := filepath.Join(publishedDirectory, "proxy.yaml")
	filteredProxyPath := filepath.Join(publishedDirectory, "proxy-filtered.yaml")
	rulePath := filepath.Join(publishedDirectory, "rule.yaml")
	originalProxy := []byte("proxies:\n  - {name: Original, type: direct}\n")
	originalFilteredProxy := []byte("proxies:\n  - {name: Allowed, type: direct}\n")
	originalRule := []byte("payload:\n  - DOMAIN,example.com\n")
	if err := os.WriteFile(proxyPath, originalProxy, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rulePath, originalRule, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filteredProxyPath, originalFilteredProxy, 0o600); err != nil {
		t.Fatal(err)
	}

	config := fmt.Sprintf(`
mode: rule
log-level: info
dns:
  enable: true
  nameserver: [8.8.8.8]
proxy-providers:
  controlled-proxy:
    type: file
    path: %q
  controlled-filtered:
    type: file
    path: %q
    filter: '^Allowed$'
rule-providers:
  controlled-rule:
    type: file
    behavior: classical
    format: yaml
    x-hako-side-update-safe: true
    path: %q
  controlled-route-rule:
    type: file
    behavior: classical
    format: yaml
    path: %q
proxy-groups:
  - name: Controlled
    type: select
    use: [controlled-proxy]
rules:
  - RULE-SET,controlled-rule,DIRECT
  - MATCH,DIRECT
`, proxyPath, filteredProxyPath, rulePath, rulePath)
	service, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Start(config); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })

	proxyEntry := service.providerRuntime.entries[providerRuntimeKey("proxy", "controlled-proxy")]
	filteredProxyEntry := service.providerRuntime.entries[providerRuntimeKey("proxy", "controlled-filtered")]
	ruleEntry := service.providerRuntime.entries[providerRuntimeKey("rule", "controlled-rule")]
	routeRuleEntry := service.providerRuntime.entries[providerRuntimeKey("rule", "controlled-route-rule")]
	for _, pair := range [][2]string{{proxyPath, proxyEntry.runtimePath}, {filteredProxyPath, filteredProxyEntry.runtimePath}, {rulePath, ruleEntry.runtimePath}} {
		published, err := os.Stat(pair[0])
		if err != nil {
			t.Fatal(err)
		}
		runtimeFile, err := os.Stat(pair[1])
		if err != nil {
			t.Fatal(err)
		}
		if !os.SameFile(published, runtimeFile) {
			t.Fatalf("runtime provider %s was copied instead of hard-linked", filepath.Base(pair[1]))
		}
	}

	path := shortClashSocketPath(t)
	if err := startControlPlane(nil, path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stopClashAPI(path) })
	client, err := NewClashAPIClientWithOptions(path, newRecordingClashAPIHandler(), &ClashAPIClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	proxyCatalog, err := client.GetProxyProviders()
	if err != nil || !strings.Contains(proxyCatalog, `"controlled-proxy"`) {
		t.Fatalf("GetProxyProviders = %q, %v", proxyCatalog, err)
	}
	proxyDetail, err := client.GetProxyProvider("controlled-proxy")
	if err != nil || !strings.Contains(proxyDetail, `"controlled-proxy"`) {
		t.Fatalf("GetProxyProvider = %q, %v", proxyDetail, err)
	}
	if err := client.HealthCheckProxyProvider("controlled-proxy"); err != nil {
		t.Fatalf("HealthCheckProxyProvider: %v", err)
	}
	ruleCatalog, err := client.GetRuleProviders()
	if err != nil || !strings.Contains(ruleCatalog, `"controlled-rule"`) {
		t.Fatalf("GetRuleProviders = %q, %v", ruleCatalog, err)
	}

	updatedProxy := []byte("proxies:\n  - {name: One, type: direct, interface-name: en0, routing-mark: 233}\n  - {name: Two, type: direct}\n")
	if err := client.SideUpdateProxyProvider("controlled-proxy", updatedProxy); err != nil {
		t.Fatalf("SideUpdateProxyProvider: %v", err)
	}
	if got := tunnel.Providers()["controlled-proxy"].Count(); got != 2 {
		t.Fatalf("proxy provider count = %d, want 2", got)
	}
	sanitizedProxy, err := os.ReadFile(proxyEntry.runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sanitizedProxy, []byte("interface-name")) || bytes.Contains(sanitizedProxy, []byte("routing-mark")) {
		t.Fatalf("paired egress override survived in runtime proxy provider: %q", sanitizedProxy)
	}
	updatedRule := []byte("payload:\n  - UID,501\n  - DOMAIN,example.net\n  - IN-USER,alice\n  - SOURCE-APP-SIGNING-ID,com.example.cli\n  - SOURCE-APP-TEAM-ID,ABCDE12345\n  - DOMAIN,example.org\n")
	if err := client.SideUpdateRuleProvider("controlled-rule", updatedRule); err != nil {
		t.Fatalf("SideUpdateRuleProvider: %v", err)
	}
	if got := tunnel.RuleProviders()["controlled-rule"].Count(); got != 2 {
		t.Fatalf("rule provider count = %d, want 2", got)
	}
	sanitizedRule, err := os.ReadFile(ruleEntry.runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sanitizedRule, []byte("UID")) || bytes.Contains(sanitizedRule, []byte("IN-USER")) || bytes.Contains(sanitizedRule, []byte("SOURCE-APP")) {
		t.Fatalf("metadata no-op survived in runtime provider: %q", sanitizedRule)
	}
	metadataOnlyRule := []byte("payload:\n  - PROCESS-NAME,curl\n  - UID,501\n  - IN-USER,alice\n  - SOURCE-APP-SIGNING-ID,com.example.cli\n  - SOURCE-APP-TEAM-ID,ABCDE12345\n")
	if err := client.SideUpdateRuleProvider("controlled-rule", metadataOnlyRule); err != nil {
		t.Fatalf("metadata-only SideUpdateRuleProvider: %v", err)
	}
	if got := tunnel.RuleProviders()["controlled-rule"].Count(); got != 0 {
		t.Fatalf("metadata-only runtime rule provider count = %d, want 0", got)
	}
	if err := client.SideUpdateRuleProvider("controlled-route-rule", updatedRule); err == nil {
		t.Fatal("Apple platform route provider side update unexpectedly succeeded")
	}
	routeRuntimePayload, err := os.ReadFile(routeRuleEntry.runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(routeRuntimePayload, originalRule) {
		t.Fatal("rejected Apple route provider update changed runtime bytes")
	}

	for path, want := range map[string][]byte{proxyPath: originalProxy, rulePath: originalRule} {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("published provider %s was mutated", filepath.Base(path))
		}
	}
	for _, pair := range [][2]string{{proxyPath, proxyEntry.runtimePath}, {rulePath, ruleEntry.runtimePath}} {
		published, _ := os.Stat(pair[0])
		runtimeFile, _ := os.Stat(pair[1])
		if os.SameFile(published, runtimeFile) {
			t.Fatalf("updated runtime provider %s still aliases the published inode", filepath.Base(pair[1]))
		}
	}

	if err := client.SideUpdateProxyProvider("controlled-proxy", []byte("proxies: []\n")); err == nil {
		t.Fatal("invalid proxy provider side update unexpectedly succeeded")
	}
	if got := tunnel.Providers()["controlled-proxy"].Count(); got != 2 {
		t.Fatalf("invalid update changed proxy provider count to %d", got)
	}
	runtimePayload, err := os.ReadFile(proxyEntry.runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(runtimePayload, sanitizedProxy) {
		t.Fatal("invalid update changed the last-known-good runtime payload")
	}
	if err := client.SideUpdateProxyProvider(
		"controlled-filtered", []byte("proxies:\n  - {name: Blocked, type: direct}\n"),
	); err == nil {
		t.Fatal("provider-specific filter rejection unexpectedly succeeded")
	}
	if got := tunnel.Providers()["controlled-filtered"].Count(); got != 1 {
		t.Fatalf("rejected filtered update changed provider count to %d", got)
	}
	filteredRuntimePayload, err := os.ReadFile(filteredProxyEntry.runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(filteredRuntimePayload, originalFilteredProxy) {
		t.Fatal("runtime parser rejection did not atomically restore the previous provider")
	}

	secretName := "private-provider-name"
	if err := client.SideUpdateProxyProvider(secretName, updatedProxy); err == nil || strings.Contains(err.Error(), secretName) {
		t.Fatalf("unknown provider error leaked its name: %v", err)
	}

	oldRuntimeDirectory := service.providerRuntime.directory
	nextProxyPath := filepath.Join(publishedDirectory, "proxy-next.yaml")
	nextRulePath := filepath.Join(publishedDirectory, "rule-next.yaml")
	nextProxy := []byte("proxies:\n  - {name: Three, type: direct}\n  - {name: Four, type: direct}\n  - {name: Five, type: direct}\n")
	nextRule := []byte("payload:\n  - DOMAIN,one.example\n  - DOMAIN,two.example\n  - DOMAIN,three.example\n")
	if err := os.WriteFile(nextProxyPath, nextProxy, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nextRulePath, nextRule, 0o600); err != nil {
		t.Fatal(err)
	}
	nextConfig := strings.ReplaceAll(strings.ReplaceAll(config, proxyPath, nextProxyPath), rulePath, nextRulePath)
	if err := service.Reload(nextConfig); err != nil {
		t.Fatalf("Reload with next published revision: %v", err)
	}
	if got := tunnel.Providers()["controlled-proxy"].Count(); got != 3 {
		t.Fatalf("reloaded proxy provider count = %d, want 3", got)
	}
	if got := tunnel.RuleProviders()["controlled-rule"].Count(); got != 3 {
		t.Fatalf("reloaded rule provider count = %d, want 3", got)
	}
	// The staged directory is persistent now: Reload reuses it instead of
	// building a sibling and deleting the old one. What must hold is that the
	// same directory serves both generations and the parent accumulates no
	// per-start litter.
	if service.providerRuntime.directory != oldRuntimeDirectory {
		t.Fatalf("Reload abandoned the staged directory: %q -> %q",
			oldRuntimeDirectory, service.providerRuntime.directory)
	}
	parentEntries, err := os.ReadDir(filepath.Dir(oldRuntimeDirectory))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range parentEntries {
		if entry.Name() != providerRuntimeStagedDirectoryName &&
			entry.Name() != providerRuntimeManifestName {
			t.Fatalf("Reload left litter beside the staged directory: %s", entry.Name())
		}
	}
	nextProxyEntry := service.providerRuntime.entries[providerRuntimeKey("proxy", "controlled-proxy")]
	publishedNext, _ := os.Stat(nextProxyPath)
	runtimeNext, _ := os.Stat(nextProxyEntry.runtimePath)
	if !os.SameFile(publishedNext, runtimeNext) {
		t.Fatal("Reload did not stage the next immutable revision as a runtime hard link")
	}
	var waitGroup sync.WaitGroup
	concurrentErrors := make(chan error, 16)
	for index := 0; index < 16; index++ {
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			payload := []byte(fmt.Sprintf("proxies:\n  - {name: Concurrent-%d, type: direct}\n", index))
			concurrentErrors <- client.SideUpdateProxyProvider("controlled-proxy", payload)
		}(index)
	}
	waitGroup.Wait()
	close(concurrentErrors)
	for err := range concurrentErrors {
		if err != nil {
			t.Fatalf("concurrent provider side update: %v", err)
		}
	}
	if got := tunnel.Providers()["controlled-proxy"].Count(); got != 1 {
		t.Fatalf("concurrent provider update final count = %d, want 1", got)
	}

	runtimeDirectory := service.providerRuntime.directory
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	// Close releases the service's reference and nothing else: the staged
	// directory surviving Close is the whole point of the persistent cache --
	// the next start reuses it instead of re-reading fifty-six files.
	if _, err := os.Stat(runtimeDirectory); err != nil {
		t.Fatalf("Close deleted the staged runtime cache: %v", err)
	}
}

func TestFailedStartRemovesProviderRuntimeStaging(t *testing.T) {
	options := testOptions(t)
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	published := filepath.Join(options.WorkingPath, "published-rule.yaml")
	if err := os.WriteFile(published, []byte("payload:\n  - example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf(`
rule-providers:
  invalid:
    type: file
    behavior: unsupported
    path: %q
rules:
  - MATCH,DIRECT
`, published)
	service, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	if err := service.Start(config); err == nil {
		t.Fatal("invalid provider Start unexpectedly succeeded")
	}
	if service.providerRuntime != nil {
		t.Fatal("failed Start published a provider runtime")
	}
	// The persistent staged directory may exist -- it is the cache root, not
	// litter -- but a start that failed must publish nothing reusable: no
	// staged files, no manifest recording products that were never blessed.
	parent := filepath.Join(options.WorkingPath, providerRuntimeDirectoryName)
	entries, err := os.ReadDir(parent)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() == providerRuntimeManifestName {
			t.Fatal("failed Start recorded a staging manifest")
		}
		if entry.Name() != providerRuntimeStagedDirectoryName {
			t.Fatalf("failed Start left litter: %s", entry.Name())
		}
	}
	staged, err := os.ReadDir(filepath.Join(parent, providerRuntimeStagedDirectoryName))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if len(staged) != 0 {
		t.Fatalf("failed Start left %d staged files behind", len(staged))
	}
}

func TestProviderSideUpdateRejectsInvalidClientInputs(t *testing.T) {
	client, err := NewClashAPIClient("/tmp/does-not-exist.sock", newRecordingClashAPIHandler())
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		payload []byte
	}{
		{name: "", payload: []byte("proxies: [{}]\n")},
		{name: "provider", payload: nil},
		{name: "provider", payload: make([]byte, maximumProviderResourceBytes+1)},
	} {
		if err := client.SideUpdateProxyProvider(test.name, test.payload); err == nil {
			t.Fatalf("SideUpdateProxyProvider(%q, %d bytes) unexpectedly succeeded", test.name, len(test.payload))
		}
	}
}

// One rule provider whose bytes this core cannot read must not refuse the whole
// configuration. Upstream loads providers with hub/executor/executor.go:318-338,
// which calls Initial() and on failure does nothing but
// `log.Errorln("initial rule provider %s error: %v")` before moving to the next
// one -- the config starts and that one rule set is empty. Nothing about the
// failure is platform-relevant either: an unreadable rule set costs no memory,
// spawns nothing, downloads nothing (it is already a pre-staged file provider)
// and leaves no sandbox. Both questions answer no.
//
// The real report this reproduces (TestFlight user feedback, 2026-08-01): an
// OpenClash export with 27 rule providers, of which exactly one pointed at a
// GitHub /blob/ HTML page while declaring format: mrs. The HTML is served 200
// with 384683 bytes of "<!DOCTYPE html>", so the MRS magic check fired and was
// RIGHT -- and then took the other 26 rule sets down with it. The same config
// runs in OpenClash.
//
// Note where the parse actually happens, because it is why this is safe:
// ParseRuleProvider only builds a FileVehicle (rules/provider/parse.go:50) and
// never reads the file, so staging bad bytes cannot fail ParseRawConfig. The
// read is Initial()'s, on upstream's non-fatal path.
func TestOneUnreadableRuleProviderDoesNotRefuseTheConfig(t *testing.T) {
	options := testOptions(t)
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}

	classical := filepath.Join(options.WorkingPath, "good-classical.yaml")
	if err := os.WriteFile(classical, []byte("payload:\n  - DOMAIN,example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// A real MRS, written by the kernel's own writer rather than a hand-rolled
	// byte string, so "good" means what the kernel means by it.
	var mrs bytes.Buffer
	if err := ruleprovider.ConvertToMrs([]byte("203.0.113.0/24\n"), P.IPCIDR, P.TextRule, &mrs); err != nil {
		t.Fatal(err)
	}
	goodMRS := filepath.Join(options.WorkingPath, "good.mrs")
	if err := os.WriteFile(goodMRS, mrs.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	// The offender, in the exact shape reported: an HTML page declared as MRS.
	broken := filepath.Join(options.WorkingPath, "broken.mrs")
	html := append([]byte("<!DOCTYPE html>\n<html><head><title>ios_rule_script</title></head>\n"),
		bytes.Repeat([]byte("<div>rule</div>\n"), 64)...)
	if err := os.WriteFile(broken, html, 0o600); err != nil {
		t.Fatal(err)
	}

	content := fmt.Sprintf(`
dns:
  enable: true
  nameserver: [8.8.8.8]
rule-providers:
  good-classical:
    type: file
    behavior: classical
    format: yaml
    path: %q
  good-mrs:
    type: file
    behavior: ipcidr
    format: mrs
    path: %q
  crypto-domain:
    type: file
    behavior: domain
    format: mrs
    path: %q
rules:
  - RULE-SET,good-classical,DIRECT
  - RULE-SET,good-mrs,DIRECT
  - RULE-SET,crypto-domain,DIRECT
  - MATCH,DIRECT
`, classical, goodMRS, broken)

	service, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Start(content); err != nil {
		t.Fatalf("one unreadable rule provider refused the whole configuration: %v", err)
	}
	t.Cleanup(func() { _ = service.Close() })

	// The intact rule sets are all the way up, not merely staged.
	providers := tunnel.RuleProviders()
	for name, want := range map[string]int{"good-classical": 1, "good-mrs": 1} {
		provider, ok := providers[name]
		if !ok {
			t.Errorf("rule provider %q is missing; a broken sibling took it down", name)
			continue
		}
		if got := provider.Count(); got != want {
			t.Errorf("rule provider %q has %d rules, want %d", name, got, want)
		}
	}

	// The offender is still declared -- it is the kernel's job to fail it at
	// Initial() and log, exactly as upstream does -- and its bytes were staged
	// verbatim rather than swallowed, so the log names a real cause.
	entry, staged := service.providerRuntime.entries[providerRuntimeKey("rule", "crypto-domain")]
	if !staged {
		t.Fatal("the unreadable provider was dropped from the runtime instead of staged")
	}
	stagedBytes, err := os.ReadFile(entry.runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stagedBytes, html) {
		t.Error("the unreadable provider's bytes were rewritten; the kernel should see what the user published")
	}
	if provider, ok := providers["crypto-domain"]; ok && provider.Count() != 0 {
		t.Errorf("the unreadable provider reported %d rules; it cannot have any", provider.Count())
	}
}

// A schema-level defect is not a content-level one, and upstream draws the same
// line: an unreadable FILE fails at Initial() and is warn-and-continue
// (hub/executor/executor.go:318-338), but an unparseable behavior/format STRING
// fails inside ParseRuleProvider (rules/provider/parse.go:34-41) during
// config.ParseRawConfig, where parseRuleProviders returns the error and the
// whole load stops (config/config.go:687-690, 1014-1027). Staging must keep
// that split: tolerating a schema typo here does not make the config start --
// it just replaces our contextual error with mihomo's bare one, after logging a
// false "the configuration still starts". The adversarial review reproduced
// exactly that with `behavior: clasical`.
func TestRuleProviderSchemaTypoStaysFatalWithContext(t *testing.T) {
	options := testOptions(t)
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	payload := filepath.Join(options.WorkingPath, "schema-typo.yaml")
	if err := os.WriteFile(payload, []byte("payload:\n  - DOMAIN,example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, defect := range []struct{ field, value, wantToken string }{
		{"behavior", "clasical", "provider behavior"},
		{"format", "not-a-real-format", "provider format"},
	} {
		behavior, format := "classical", "yaml"
		if defect.field == "behavior" {
			behavior = defect.value
		} else {
			format = defect.value
		}
		content := fmt.Sprintf(`
dns:
  enable: true
  nameserver: [8.8.8.8]
rule-providers:
  typo:
    type: file
    behavior: %s
    format: %s
    path: %q
rules:
  - RULE-SET,typo,DIRECT
  - MATCH,DIRECT
`, behavior, format, payload)
		service, err := NewService(newRecordingPlatform())
		if err != nil {
			t.Fatal(err)
		}
		startErr := service.Start(content)
		_ = service.Close()
		if startErr == nil {
			t.Fatalf("%s typo was accepted; upstream refuses it at ParseRawConfig", defect.field)
		}
		if !strings.Contains(startErr.Error(), defect.wantToken) ||
			!strings.Contains(startErr.Error(), "stage rule provider runtime") {
			t.Errorf("%s typo lost its staging context: %v", defect.field, startErr)
		}
	}
}
