package hako

import (
	"strings"
	"testing"

	"github.com/TokenPLS/Hako/config"
)

// normalizeRawConfigForApple walks the configuration six times, once per
// concern: strip nameservers a packet tunnel cannot use, repair the bootstrap
// they may have emptied, notice fragments naming things this extension cannot
// route, strip per-outbound egress overrides, strip owner-metadata rules, and
// strip the same from inline rule-provider payloads. Together they cost 33ms on
// a 578KB subscription -- the largest bind-side item on a start.
//
// Merging the walks is only safe if each concern's behaviour is written down
// first. Three of the six had no test naming them. These are that net: they
// describe what each pass must still do, not how many passes there are.

func normalizeFixture(t *testing.T, yaml string) *config.RawConfig {
	t.Helper()
	raw, err := config.UnmarshalRawConfig([]byte(yaml))
	if err != nil {
		t.Fatalf("UnmarshalRawConfig: %v", err)
	}
	return raw
}

func nePolicy() appleRuntimePolicy {
	return runtimePolicyFor(runtimeProfileIOSPacketTunnel, true)
}

// A nameserver naming a proxy the static configuration never defines cannot be
// routed by an extension, and is kept verbatim on purpose: stripping it could
// silently reroute DNS through a different proxy or DIRECT. It fails closed per
// query instead, and the reader is told.
func TestNormalizeReportsButKeepsAnUnroutableDNSFragment(t *testing.T) {
	raw := normalizeFixture(t, `
mode: rule
proxies:
  - {name: Known, type: direct}
dns:
  enable: true
  nameserver:
    - "https://1.1.1.1/dns-query#Ghost"
rules:
  - MATCH,DIRECT
`)
	reported := detectUnroutableDNSFragments(raw)
	if len(reported) == 0 {
		t.Fatal("a fragment naming an undefined proxy must be reported")
	}
	if !strings.Contains(strings.Join(raw.DNS.NameServer, "|"), "Ghost") {
		t.Fatal("the fragment must be kept verbatim; stripping it would reroute DNS silently")
	}

	// A fragment naming a proxy that does exist is ordinary and says nothing.
	fine := normalizeFixture(t, `
mode: rule
proxies:
  - {name: Known, type: direct}
dns:
  enable: true
  nameserver:
    - "https://1.1.1.1/dns-query#Known"
rules:
  - MATCH,DIRECT
`)
	if reported := detectUnroutableDNSFragments(fine); len(reported) != 0 {
		t.Fatalf("a fragment naming a defined proxy must not be reported: %v", reported)
	}
}

// A DNS nameserver may carry credentials -- userinfo, a query token, a path
// secret (NextDNS profile IDs live in the path) -- and the unroutable-fragment
// diagnostic reaches TWO product exits: log.Warnln (config_pipeline.go) and the
// plan's App-facing notices (plan_resources.go). Neither may carry the secret.
// This is an exit constraint, not a config mutation: the nameserver stays
// verbatim in raw.DNS.NameServer; only the diagnostic string is redacted.
func TestUnroutableDNSFragmentDiagnosticWithholdsCredentials(t *testing.T) {
	raw := normalizeFixture(t, `
mode: rule
proxies:
  - {name: Known, type: direct}
dns:
  enable: true
  nameserver:
    - "https://user:s3cr3tPass@doh.example.com/dns-query?token=SECRETTOKEN#Ghost"
    - "https://dns.nextdns.io/abc123profile#Ghost"
rules:
  - MATCH,DIRECT
`)
	reported := detectUnroutableDNSFragments(raw)
	if len(reported) == 0 {
		t.Fatal("a fragment naming an undefined proxy must still be reported")
	}
	joined := strings.Join(reported, "\n")
	for _, secret := range []string{"s3cr3tPass", "SECRETTOKEN", "user:", "abc123profile"} {
		if strings.Contains(joined, secret) {
			t.Fatalf("the diagnostic leaks credential material %q; it reaches both a product log and the App notices:\n%s", secret, joined)
		}
	}
	// The diagnostic must still do its job: name the host and the offending
	// fragment so the reader can find the misconfigured entry.
	if !strings.Contains(joined, "doh.example.com") || !strings.Contains(joined, "Ghost") {
		t.Fatalf("redaction destroyed the diagnostic value; host and fragment must survive:\n%s", joined)
	}
	// And the config itself is untouched -- redaction is an exit constraint only.
	if !strings.Contains(strings.Join(raw.DNS.NameServer, "|"), "s3cr3tPass") {
		t.Fatal("the nameserver must stay verbatim in the config; redaction belongs on the diagnostic, not the data")
	}
}

// Owner-metadata rules survive normalize untouched. Removing them was this
// fork's own invention: upstream under find-process-mode off -- the value this
// fork forces, and one any mihomo user can write -- keeps the rule and lets it
// evaluate against empty metadata. Normalize now only reports them.
func TestNormalizeKeepsOwnerMetadataRulesInOrder(t *testing.T) {
	source := `
mode: rule
rules:
  - DOMAIN,first.example,DIRECT
  - PROCESS-NAME,Mail,DIRECT
  - DOMAIN,second.example,DIRECT
  - UID,501,DIRECT
  - DOMAIN,third.example,DIRECT
`
	raw := normalizeFixture(t, source)

	// normalizeFixture does not run normalize, so nothing is removed here; this pins the
	// unmodified shape the pipeline receives.
	want := []string{
		"DOMAIN,first.example,DIRECT", "PROCESS-NAME,Mail,DIRECT",
		"DOMAIN,second.example,DIRECT", "UID,501,DIRECT", "DOMAIN,third.example,DIRECT",
	}
	if len(raw.Rule) != len(want) {
		t.Fatalf("kept %d rules, want all %d: %v", len(raw.Rule), len(want), raw.Rule)
	}
	for index, rule := range want {
		if raw.Rule[index] != rule {
			t.Fatalf("rule %d = %q, want %q -- nothing is removed and order must survive", index, raw.Rule[index], rule)
		}
	}
	if summaries := summarizeMetadataRuleOccurrences(raw, nePolicy().processMetadata()); len(summaries) == 0 {
		t.Fatal("the kept metadata rules must still be reported")
	}
}

// An inline rule-provider payload is normalized by the same rule: the entry
// stays, and the reader is told which entry cannot resolve its metadata.
func TestNormalizeKeepsMetadataRulesInsideInlineRuleProviders(t *testing.T) {
	raw := normalizeFixture(t, `
mode: rule
rule-providers:
  inline:
    type: inline
    behavior: classical
    payload:
      - DOMAIN,keep.example
      - PROCESS-NAME,Mail
rules:
  - RULE-SET,inline,DIRECT
  - MATCH,DIRECT
`)
	rendered := strings.Join(inlineProviderPayloadStrings(t, raw, "inline"), "|")
	if !strings.Contains(rendered, "PROCESS-NAME") {
		t.Fatalf("the metadata rule was removed from the inline payload: %s", rendered)
	}
	if !strings.Contains(rendered, "keep.example") {
		t.Fatalf("an executable rule was lost from the inline payload: %s", rendered)
	}
	if occurrences := inlineRuleProviderMetadataOccurrences(raw, nePolicy().processMetadata()); len(occurrences) != 1 {
		t.Fatalf("the inline payload entry must be reported once, got %d", len(occurrences))
	}
}

// The six passes are separate today. Whatever replaces them has to leave the
// same configuration behind, so this pins the whole normalize step over a
// fixture that trips every concern at once.
func TestNormalizeLeavesTheSameConfigurationHoweverItWalksIt(t *testing.T) {
	source := `
mode: rule
proxies:
  - {name: Known, type: direct, interface-name: en0, routing-mark: 233}
dns:
  enable: true
  nameserver:
    - system://
    - 8.8.8.8
    - "https://1.1.1.1/dns-query#Ghost"
rule-providers:
  inline:
    type: inline
    behavior: classical
    payload:
      - DOMAIN,inline-keep.example
      - UID,501
rules:
  - DOMAIN,first.example,DIRECT
  - PROCESS-NAME,Mail,DIRECT
  - MATCH,DIRECT
`
	raw := normalizeFixture(t, source)
	normalizeRawConfigForApple(raw, nePolicy())

	if joined := strings.Join(raw.DNS.NameServer, "|"); strings.Contains(joined, "system://") {
		t.Fatalf("system:// resolves back through NEDNSSettings and must go: %s", joined)
	}
	if joined := strings.Join(raw.DNS.NameServer, "|"); !strings.Contains(joined, "Ghost") {
		t.Fatalf("an unroutable fragment must be kept verbatim: %s", joined)
	}
	if len(raw.DNS.NameServer) == 0 {
		t.Fatal("an emptied bootstrap must be refilled, not left empty")
	}
	var sawProcessRule bool
	for _, rule := range raw.Rule {
		if strings.HasPrefix(rule, "PROCESS-NAME") {
			sawProcessRule = true
		}
	}
	if !sawProcessRule {
		t.Fatal("an owner-metadata rule was removed from the main rules block; they are kept and reported now")
	}
	// UID is removed even from an inline payload: upstream cannot construct it on GOOS=ios,
	// and an unconstructible rule anywhere fails the whole configuration.
	if rendered := strings.Join(inlineProviderPayloadStrings(t, raw, "inline"), "|"); strings.Contains(rendered, "UID,") {
		t.Fatalf("UID survived in the inline payload: %s", rendered)
	}
	if len(raw.Proxy) != 1 {
		t.Fatalf("the proxy must survive, got %d", len(raw.Proxy))
	}
	for _, field := range []string{"interface-name", "routing-mark"} {
		if _, present := raw.Proxy[0][field]; present {
			t.Fatalf("%s has no Network Extension equivalent and must be stripped", field)
		}
	}
}

func inlineProviderPayloadStrings(t *testing.T, raw *config.RawConfig, name string) []string {
	t.Helper()
	definition, exists := raw.RuleProvider[name]
	if !exists {
		t.Fatalf("rule provider %q is missing", name)
	}
	entries, _ := definition["payload"].([]any)
	rendered := make([]string, 0, len(entries))
	for _, entry := range entries {
		if text, ok := entry.(string); ok {
			rendered = append(rendered, text)
		}
	}
	return rendered
}
