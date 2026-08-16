package hako

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TokenPLS/Hako/config"
	C "github.com/TokenPLS/Hako/constant"
)

// A provider definition's keys reach this fork as the reader's literal YAML
// (RawConfig.ProxyProvider is map[string]map[string]any, config/config.go:475),
// while upstream's decoder matches field names case-INSENSITIVELY
// (common/structure/structure.go:522, strings.EqualFold). Every guard in this
// fork that reads definition["type"] or definition["path"] by literal lowercase
// therefore has a bypass spelled `Type:` — and upstream still builds the
// provider from it. That splits the config this fork inspects from the config
// the core runs, which is the shape every provider guard here depends on.
//
// Threat model: the subscription author. They write the YAML; the reader only
// presses import.

func canonicalizedRawConfig(t *testing.T, content string) *config.RawConfig {
	t.Helper()
	raw, err := config.UnmarshalRawConfig([]byte(content))
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	canonicalizeProviderDefinitionKeys(raw)
	return raw
}

func TestProviderDefinitionKeysAreCanonicalizedBeforeEveryGuard(t *testing.T) {
	raw := canonicalizedRawConfig(t, `
proxy-providers:
  air:
    Type: file
    Path: ./nodes.yaml
rule-providers:
  ads:
    TYPE: file
    PATH: ./ads.yaml
    Behavior: classical
    Format: yaml
`)
	for _, subject := range []struct {
		kind       string
		definition map[string]any
	}{
		{"proxy-provider", raw.ProxyProvider["air"]},
		{"rule-provider", raw.RuleProvider["ads"]},
	} {
		if _, ok := subject.definition["type"]; !ok {
			t.Fatalf("%s: type key not canonicalized; every literal-lowercase guard in this fork misses it: %v",
				subject.kind, subject.definition)
		}
		if _, ok := subject.definition["path"]; !ok {
			t.Fatalf("%s: path key not canonicalized: %v", subject.kind, subject.definition)
		}
		for key := range subject.definition {
			if key != strings.ToLower(key) {
				t.Fatalf("%s: mixed-case key %q survived canonicalization: %v", subject.kind, key, subject.definition)
			}
		}
	}
	if behavior := raw.RuleProvider["ads"]["behavior"]; behavior != "classical" {
		t.Fatalf("canonicalization lost a value: behavior=%v", behavior)
	}
}

// keeps downloads on the App side: a remote provider inside the Network
// Extension fetches during ApplyConfig, which blocks Start and spikes memory in
// a 50 MiB process. The refusal reads definition["type"], so `Type: http` used
// to walk straight past it — and past the http→file materialization — leaving
// upstream to build a live HTTPVehicle in the extension.
func TestRemoteProviderIsRefusedWhateverTheKeyCase(t *testing.T) {
	for _, spelling := range []string{"type", "Type", "TYPE", "tYpE"} {
		content := "proxy-providers:\n  air:\n    " + spelling + ": http\n    url: http://example.com/n.yaml\n    path: ./n.yaml\n"
		raw, err := config.UnmarshalRawConfig([]byte(content))
		if err != nil {
			t.Fatalf("%s: unmarshal: %v", spelling, err)
		}
		canonicalizeProviderDefinitionKeys(raw)
		err = validateRawProvidersForIOS("proxy-provider", raw.ProxyProvider)
		if err == nil {
			t.Fatalf("%s: a remote provider was accepted; downloading inside the extension is forbidden", spelling)
		}
		// Assert on what the refusal TELLS the reader, not on the task id: the
		// OSS export scrubs bracketed ids out of string literals by design
		// (that is why they are written in that shape), so an id-keyed
		// assertion passes privately and fails in the exported tree -- which
		// is exactly what it did here.
		if !strings.Contains(err.Error(), "remote") || !strings.Contains(err.Error(), "file provider") {
			t.Fatalf("%s: refusal does not say what is wrong or what to do: %v", spelling, err)
		}
	}
}

// Staging is where a file-backed provider's payload is sanitized: egress
// overrides stripped from proxy providers, unexecutable owner-metadata rules
// stripped from rule providers, compile verdicts applied. A definition whose
// `type` key this fork does not recognize is skipped entirely (`continue`), so
// a mixed-case spelling used to hand the core an unsanitized file.
func TestStagingSeesAFileProviderWhateverTheKeyCase(t *testing.T) {
	home := compileStagingHome(t)
	source := filepath.Join(C.Path.HomeDir(), "nodes.yaml")
	if err := os.WriteFile(source,
		[]byte("proxies:\n  - name: a\n    type: ss\n    server: 1.2.3.4\n    port: 443\n    cipher: aes-128-gcm\n    password: x\n    interface-name: en0\n"),
		0o600); err != nil {
		t.Fatal(err)
	}

	raw, err := config.UnmarshalRawConfig([]byte(
		"proxy-providers:\n  air:\n    Type: file\n    Path: " + source + "\n"))
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	canonicalizeProviderDefinitionKeys(raw)

	runtime, err := stageProviderRuntime(raw, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true), false)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	if runtime == nil {
		t.Fatal("a mixed-case file provider was skipped by staging; its payload reaches the core unsanitized")
	}
	defer runtime.close()

	staged, err := os.ReadFile(raw.ProxyProvider["air"]["path"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(staged), "interface-name") {
		t.Fatal("the staged copy still carries an egress override; sanitization did not run")
	}
	if !strings.HasPrefix(raw.ProxyProvider["air"]["path"].(string), home) {
		t.Fatal("the definition does not point at the staged copy")
	}
}

// FinalizeForIOS is the App-side entry that rewrites every provider to the
// materialized path the extension will read (config_finalize.go:208-218). It
// walks free-form YAML rather than RawConfig, so it needs the same
// canonicalization: a `Type: http` provider that walks past the rewrite keeps
// its remote definition into the published revision.
func TestFinalizeRewritesARemoteProviderWhateverTheKeyCase(t *testing.T) {
	merged := "proxy-providers:\n  air:\n    Type: http\n    URL: http://example.com/nodes.yaml\n" +
		"rules:\n  - MATCH,DIRECT\n"
	resourceMap := `{"providerPaths":{"proxy:air":"/tmp/hako-finalize-air.yaml"}}`

	box, err := FinalizeForIOS(merged, resourceMap)
	if err != nil {
		t.Fatalf("FinalizeForIOS: %v", err)
	}
	finalized := box.Value
	if strings.Contains(finalized, "http://example.com") {
		t.Fatalf("a mixed-case remote provider survived finalization with its URL; the extension would download it:\n%s", finalized)
	}
	if !strings.Contains(finalized, "type: file") {
		t.Fatalf("the provider was not rewritten to a file provider:\n%s", finalized)
	}
}

// Canonicalization must not invent or merge: a definition that already spells a
// key in lowercase, and one that spells the SAME key twice in different cases,
// must not lose the reader's own value silently.
func TestCanonicalizationKeepsAnExistingLowercaseKey(t *testing.T) {
	raw := canonicalizedRawConfig(t, `
proxy-providers:
  air:
    type: file
    Type: http
    path: ./real.yaml
`)
	// The lowercase key the reader wrote is authoritative; a variant must never
	// overwrite it (that would let `Type: http` win over `type: file`).
	if got := raw.ProxyProvider["air"]["type"]; got != "file" {
		t.Fatalf("a mixed-case duplicate overwrote the canonical key: type=%v", got)
	}
}
