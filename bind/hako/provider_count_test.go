package hako

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TokenPLS/Hako/config"
	C "github.com/TokenPLS/Hako/constant"
	P "github.com/TokenPLS/Hako/constant/provider"
	ruleprovider "github.com/TokenPLS/Hako/rules/provider"
)

// The rules page shows how many entries each rule set holds. With the tunnel up the
// figure comes from the running core; with the tunnel down the only thing on disk that
// knows is the staging manifest, because staging is the one pass that already reads
// every set. So each rule entry in the manifest carries the count of what was staged --
// the compiled MRS's header for a compiled set, the entries of a source MRS, the kept
// entries of a set that rides as text. Proxy entries carry nothing: a proxy provider's
// entries are nodes, and the proxies page already has them.

func stagedManifestForCountTest(t *testing.T, home string) (*stagedProviderManifest, map[string]any) {
	t.Helper()
	parent := stagedProviderParentDirectory()
	manifest := loadStagedProviderManifest(parent, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true))
	raw, err := os.ReadFile(filepath.Join(parent, providerRuntimeManifestName))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("manifest is not JSON: %v", err)
	}
	entries, _ := decoded["entries"].(map[string]any)
	return manifest, entries
}

func TestStagedManifestCarriesTheRuleSetCount(t *testing.T) {
	options := testOptions(t)
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	home := options.WorkingPath
	C.SetHomeDir(home)

	// Three shapes a rule set arrives in, plus a proxy provider that must stay silent.
	domainPath := filepath.Join(home, "domains.yaml")
	if err := os.WriteFile(domainPath, []byte("payload:\n  - example.com\n  - '+.example.org'\n  - example.net\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	classicalPath := filepath.Join(home, "classical.yaml")
	if err := os.WriteFile(classicalPath,
		[]byte("payload:\n  - DOMAIN-SUFFIX,example.com\n  - IP-CIDR,10.0.0.0/8,no-resolve\n  - DOMAIN-KEYWORD,ads\n  - PROCESS-NAME,Mail\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var compiled bytes.Buffer
	if err := ruleprovider.ConvertToMrs([]byte("203.0.113.0/24\n198.51.100.0/24\n"), P.IPCIDR, P.TextRule, &compiled); err != nil {
		t.Fatal(err)
	}
	mrsPath := filepath.Join(home, "cidrs.mrs")
	if err := os.WriteFile(mrsPath, compiled.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	proxyPath := filepath.Join(home, "air.yaml")
	if err := os.WriteFile(proxyPath, []byte(publishTestProxy), 0o600); err != nil {
		t.Fatal(err)
	}
	content := "" +
		"dns:\n  enable: true\n  nameserver: [8.8.8.8]\n" +
		"proxy-providers:\n  air:\n    type: file\n    path: " + proxyPath + "\n" +
		"rule-providers:\n" +
		"  domains:\n    type: file\n    behavior: domain\n    format: yaml\n    path: " + domainPath + "\n" +
		"  classical:\n    type: file\n    behavior: classical\n    format: yaml\n    path: " + classicalPath + "\n" +
		"  cidrs:\n    type: file\n    behavior: ipcidr\n    format: mrs\n    path: " + mrsPath + "\n" +
		"proxy-groups:\n  - name: G\n    type: select\n    use: [air]\n" +
		"rules:\n  - RULE-SET,domains,G\n  - RULE-SET,classical,G\n  - RULE-SET,cidrs,G\n  - MATCH,DIRECT\n"

	if err := StageProvidersForPublish(content, RuntimeProfileIOSPacketTunnel, true); err != nil {
		t.Fatalf("StageProvidersForPublish: %v", err)
	}
	manifest, entries := stagedManifestForCountTest(t, home)

	// PROCESS-NAME is stripped on iOS before the set is staged, so the count is what the
	// core will load, not what the file says.
	for name, want := range map[string]int{"domains": 3, "classical": 3, "cidrs": 2} {
		record, ok := manifest.Entries[providerRuntimeKey("rule", name)]
		if !ok {
			t.Fatalf("rule set %q has no manifest entry", name)
		}
		if record.Count != want {
			t.Errorf("rule set %q: count %d, want %d (verdict %q)", name, record.Count, want, record.CompileVerdict)
		}
		raw, _ := entries[providerRuntimeKey("rule", name)].(map[string]any)
		if got, ok := raw["count"].(float64); !ok || int(got) != want {
			t.Errorf("rule set %q: the JSON the app reads says count=%v, want %d", name, raw["count"], want)
		}
	}
	if record, ok := manifest.Entries[providerRuntimeKey("proxy", "air")]; !ok {
		t.Fatalf("proxy provider has no manifest entry")
	} else if record.Count != 0 {
		t.Errorf("proxy provider carries a count (%d); nodes are not rule entries", record.Count)
	}
	if raw, _ := entries[providerRuntimeKey("proxy", "air")].(map[string]any); raw != nil {
		if _, present := raw["count"]; present {
			t.Errorf("proxy provider's JSON carries a count key; it must be omitted")
		}
	}
}

// The extension's own staging (no compile) counts the same way, so a manifest it
// rewrites after a source change says the same thing the app's publish would.
func TestExtensionStagingCountsTheSameRuleSet(t *testing.T) {
	options := testOptions(t)
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	home := options.WorkingPath
	C.SetHomeDir(home)
	rulePath := filepath.Join(home, "domains.txt")
	if err := os.WriteFile(rulePath, []byte("# comment\nexample.com\n\n+.example.org\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	content := "" +
		"dns:\n  enable: true\n  nameserver: [8.8.8.8]\n" +
		"rule-providers:\n  domains:\n    type: file\n    behavior: domain\n    format: text\n    path: " + rulePath + "\n" +
		"rules:\n  - RULE-SET,domains,DIRECT\n  - MATCH,DIRECT\n"
	raw, err := config.UnmarshalRawConfig([]byte(content))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stageProviderRuntime(raw, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true), false); err != nil {
		t.Fatalf("stageProviderRuntime: %v", err)
	}
	manifest, _ := stagedManifestForCountTest(t, home)
	record := manifest.Entries[providerRuntimeKey("rule", "domains")]
	if record.Count != 2 {
		t.Fatalf("text rule set staged uncompiled: count %d, want 2 (comments and blank lines are not entries)", record.Count)
	}
}

// A manifest written before counts existed must not be served as one that has them:
// the hit path carries records verbatim, so the only way every served entry carries a
// count is for the staging logic version to have moved.
func TestManifestsFromBeforeCountsAreRestaged(t *testing.T) {
	if providerStagingLogicVersion < 6 {
		t.Fatalf("providerStagingLogicVersion is %d; counts joined the record at 6, and a manifest from 5 has none", providerStagingLogicVersion)
	}
	options := testOptions(t)
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	home := options.WorkingPath
	C.SetHomeDir(home)
	policy := runtimePolicyFor(runtimeProfileIOSPacketTunnel, true)
	parent := stagedProviderParentDirectory()
	if err := os.MkdirAll(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	old := newStagedProviderManifest(policy)
	old.Logic = 5
	old.Entries[providerRuntimeKey("rule", "x")] = stagedProviderRecord{File: "x", StagedSize: 1}
	saveStagedProviderManifest(parent, old)
	if got := loadStagedProviderManifest(parent, policy); len(got.Entries) != 0 {
		t.Fatalf("a logic-5 manifest was served with %d entries; it carries no counts and must be restaged", len(got.Entries))
	}
	if !strings.Contains(string(mustReadFile(t, filepath.Join(parent, providerRuntimeManifestName))), `"logic":5`) {
		t.Fatalf("fixture did not write the old logic version")
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}
