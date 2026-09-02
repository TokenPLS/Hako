package hako

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/TokenPLS/Hako/common/orderedmap"
	"github.com/TokenPLS/Hako/component/trie"
	"github.com/TokenPLS/Hako/config"
	C "github.com/TokenPLS/Hako/constant"
)

// explainInvalidDomainPatterns turns mihomo's refusal of a Clash-style domain pattern into a
// sentence that names the field, the position and the entry -- the three things a client
// needs to put a mark on the row the user has to fix.
//
// Since v1.19.30 (6bb8b9831) mihomo validates wildcards strictly wherever a pattern feeds a
// trie: a bare "+", a "+" outside the leading label, and "*" inside a label are hard errors.
// Hako follows it and rejects too (ruled 2026-08-18: reject as mihomo does,
// the client surfaces the field-level entry). Upstream's own messages carry half of what the
// client needs -- "error in force-domain, error:invalid domain" names the field but not the
// entry, "DNS ResoverRule invalid domain: +" names the entry but not the field -- so this
// diagnostic re-walks the raw fields that feed tries with upstream's own validator and
// appends every offending entry as `field[index] "entry"` or `field["key"]`.
//
// It is a diagnostic on a verdict mihomo already gave, never a verdict of its own: it runs only
// after config.ParseRawConfig has refused for an invalid domain, it uses trie.ValidAndSplitDomain
// exactly as the parser does, and when it finds nothing to point at (a rule provider's payload,
// a shape it does not know) it hands the original error back untouched. Following mihomo means
// following it in both directions: this must never reject what mihomo accepts, and it must not
// soften what mihomo rejects.
func explainInvalidDomainPatterns(raw *config.RawConfig, cause error) error {
	if cause == nil || raw == nil {
		return cause
	}
	if !errors.Is(cause, trie.ErrInvalidDomain) && !strings.Contains(cause.Error(), "invalid domain") {
		return cause
	}
	sites := invalidDomainPatternSites(raw)
	if len(sites) == 0 {
		return cause
	}
	return fmt.Errorf("%w -- invalid domain pattern at %s (mihomo %s rejects a bare \"+\", a \"+\" outside "+
		"the leading label, and \"*\" inside a label; fix or remove the entry)",
		cause, strings.Join(sites, ", "), C.Version)
}

// invalidDomainPatternFinding is one entry upstream's validator refuses, located as precisely
// as the field allows: a list field gives Index, a policy map gives Key (the key as written,
// comma-joined keys kept whole) -- and Entry is always the offending pattern itself, the member
// when the key is a list, the key when it is not, so a consumer has one thing to show. Reason
// is a stable code laid over upstream's verdict (classifyInvalidDomainPattern).
type invalidDomainPatternFinding struct {
	Field  string
	Index  int
	Key    string
	IsKey  bool
	Entry  string
	Reason string
}

// invalidDomainPatternSites lists, as `field[index] "entry"` / `field["key"]`, every entry in the
// raw configuration's trie-fed domain fields that upstream's validator refuses. Policy keys are
// split on "," the way parseNameServerPolicy splits them, and the geosite:/rule-set: forms are
// not domain patterns and are skipped, again as upstream does.
//
// It walks a field only under the condition upstream parses it as domain patterns, because a
// pointer at an entry mihomo never looked at is the diagnostic's version of a second verdict:
// sniffer.force-domain / skip-domain and the two policy maps always (parseSniffer and parseDNS
// read them whether or not the sniffer or DNS is enabled); dns.fallback-filter.domain only when
// dns.fallback is non-empty (config.go parseDNS: `if len(cfg.Fallback) != 0`); dns.fake-ip-filter
// only under enhanced-mode fake-ip with a filter mode other than `rule`, where the entries are
// rules rather than domains (`if cfg.EnhancedMode == C.DNSFakeIP` / `FakeIPFilterMode == C.FilterRule`).
// The same walk is the corpus ruler in config_corpus_test.go and the structured export
// InvalidDomainPatternsJSON, so it must see exactly what upstream sees -- no more, no less.
func invalidDomainPatternSites(raw *config.RawConfig) []string {
	findings := invalidDomainPatternFindings(raw)
	sites := make([]string, 0, len(findings))
	for _, f := range findings {
		if f.IsKey {
			sites = append(sites, fmt.Sprintf("%s[%q]", f.Field, f.Entry))
		} else {
			sites = append(sites, fmt.Sprintf("%s[%d] %q", f.Field, f.Index, f.Entry))
		}
	}
	return sites
}

// invalidDomainPatternFindings is the walk itself; see invalidDomainPatternSites for the
// conditions it honours.
func invalidDomainPatternFindings(raw *config.RawConfig) []invalidDomainPatternFinding {
	var findings []invalidDomainPatternFinding
	list := func(field string, entries []string) {
		for index, entry := range entries {
			if _, valid := trie.ValidAndSplitDomain(entry); !valid {
				findings = append(findings, invalidDomainPatternFinding{
					Field: field, Index: index, Entry: entry, Reason: classifyInvalidDomainPattern(entry),
				})
			}
		}
	}
	list("sniffer.force-domain", raw.Sniffer.ForceDomain)
	list("sniffer.skip-domain", raw.Sniffer.SkipDomain)
	if len(raw.DNS.Fallback) != 0 {
		list("dns.fallback-filter.domain", raw.DNS.FallbackFilter.Domain)
	}
	if raw.DNS.EnhancedMode == C.DNSFakeIP && raw.DNS.FakeIPFilterMode != C.FilterRule {
		list("dns.fake-ip-filter", raw.DNS.FakeIPFilter)
	}
	policy := func(field string, keys *orderedmap.OrderedMap[string, any]) {
		if keys == nil {
			return
		}
		for pair := keys.Oldest(); pair != nil; pair = pair.Next() {
			key := pair.Key
			lower := strings.ToLower(key)
			if strings.HasPrefix(lower, "geosite:") || strings.HasPrefix(lower, "rule-set:") {
				continue
			}
			for _, member := range strings.Split(key, ",") {
				if _, valid := trie.ValidAndSplitDomain(member); !valid {
					findings = append(findings, invalidDomainPatternFinding{
						Field: field, Key: key, IsKey: true, Entry: member, Reason: classifyInvalidDomainPattern(member),
					})
				}
			}
		}
	}
	policy("dns.nameserver-policy", raw.DNS.NameServerPolicy)
	policy("dns.proxy-server-nameserver-policy", raw.DNS.ProxyServerNameserverPolicy)
	return findings
}

// classifyInvalidDomainPattern names WHY trie.ValidAndSplitDomain refuses a pattern, as a
// stable code a client can localise instead of parsing prose. It is a classification over
// upstream's verdict, never a verdict: it is only consulted for patterns upstream has already
// refused, and it mirrors the order of upstream's checks (component/trie/domain.go
// ValidAndSplitDomain) so the code names the check upstream tripped on first. Codes:
// trailing-dot, whitespace, empty, empty-segment (the pre-v1.19.30 rules), bare-plus,
// plus-outside-leading-label, star-inside-label (6bb8b9831), and other -- the bucket a future
// tightening lands in until it is named here; the test that pins this table also asserts
// every coded sample is refused upstream and every uncoded one accepted.
func classifyInvalidDomainPattern(pattern string) string {
	if pattern != "" && pattern[len(pattern)-1] == '.' {
		return "trailing-dot"
	}
	if pattern != "" {
		if r, _ := utf8.DecodeRuneInString(pattern); unicode.IsSpace(r) {
			return "whitespace"
		}
		if r, _ := utf8.DecodeLastRuneInString(pattern); unicode.IsSpace(r) {
			return "whitespace"
		}
	}
	parts := strings.Split(strings.ToLower(pattern), ".")
	if len(parts) == 1 {
		if parts[0] == "" {
			return "empty"
		}
	} else {
		for _, part := range parts[1:] {
			if part == "" {
				return "empty-segment"
			}
		}
	}
	for i, part := range parts {
		if strings.Contains(part, "+") {
			if part == "+" && len(parts) == 1 {
				return "bare-plus"
			}
			if part != "+" || i != 0 {
				return "plus-outside-leading-label"
			}
		}
		if strings.Contains(part, "*") && part != "*" {
			return "star-inside-label"
		}
	}
	return "other"
}

// invalidDomainPatternJSONFinding is the wire shape of one finding: exactly one of index/key,
// entry always present, reason always present. No version field -- the client already has
// HakoVersion(), and a second copy of one fact is how two records disagree.
type invalidDomainPatternJSONFinding struct {
	Field  string `json:"field"`
	Index  *int   `json:"index,omitempty"`
	Key    string `json:"key,omitempty"`
	Entry  string `json:"entry"`
	Reason string `json:"reason"`
}

// InvalidDomainPatternsJSON returns, for any configuration, the entries in its trie-fed
// domain fields that mihomo's validator refuses: a JSON
// array of {field, index|key, entry, reason}, "[]" when the configuration is clean.
//
// It is a pure query at YAML-decode cost -- no Setup, no provider staging, no geodata, no
// log line, nothing process-wide -- so a client can run it when a document is saved (where
// CheckConfig cannot: the editor holds source YAML with remote providers, which the
// preflight refuses before any pattern is reached) and over every stored profile after a
// core upgrade. targetProfile is the runtime profile the configuration will run under (the
// same values as SetupOptions.RuntimeProfile; "" is the iOS packet tunnel): under a packet
// tunnel the pipeline strips system/dhcp nameservers before mihomo parses, and a dns.fallback
// stripped to nothing means fallback-filter.domain is never parsed there, so the walk applies
// that same strip to a private copy first. The verdict on each entry is upstream's own
// (trie.ValidAndSplitDomain); reason is a code laid over it, see classifyInvalidDomainPattern.
// An error means only that the input could not be decoded (or the profile is unknown); a
// refusal mihomo would make for any other reason is not this function's question.
func InvalidDomainPatternsJSON(configContent string, targetProfile string) (*StringBox, error) {
	profile, err := normalizeRuntimeProfile(targetProfile)
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	if err := validateConfigurationInput(configContent); err != nil {
		return nil, bridgeSafeError(err)
	}
	raw, err := config.UnmarshalRawConfig([]byte(configContent))
	if err != nil {
		return nil, bridgeSafeError(fmt.Errorf("hako: parse config: %w", err))
	}
	// The strip mutates the RawConfig; this one was decoded for this call alone, so nothing
	// the caller holds changes. Only the packet-tunnel profiles strip (normalizeRawConfigForApple,
	// under `if policy.networkExtension`); the containing-App profile keeps dns as written.
	if runtimePolicyFor(profile, true).networkExtension {
		stripNEIncompatibleNameservers(raw)
	}
	findings := invalidDomainPatternFindings(raw)
	out := make([]invalidDomainPatternJSONFinding, 0, len(findings))
	for _, f := range findings {
		item := invalidDomainPatternJSONFinding{Field: f.Field, Entry: f.Entry, Reason: f.Reason}
		if f.IsKey {
			item.Key = f.Key
		} else {
			index := f.Index
			item.Index = &index
		}
		out = append(out, item)
	}
	data, err := json.Marshal(out)
	if err != nil {
		return nil, bridgeSafeError(fmt.Errorf("hako: encode invalid domain patterns: %w", err))
	}
	return WrapString(string(data)), nil
}
