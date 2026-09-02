package hako

import (
	"fmt"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// . The report left out the one rule removal that changes what matches.
//
// A device log showed two UID rules removed ("2 UID rules, first at rules[9] … removed") while
// the report for the same start listed nine kept-but-inert kinds and no UID row. The
// registration existed -- "rules (UID)", unavailable -- but its field is a family name, not a
// YAML path, so the path walk never found it written and the loop moved on. Registered and
// unreachable: the mirror image of the class closed (changed and unregistered), and
// the converse probe did not see it because that probe only covers forced rules.
func TestUIDRemovalIsReportedFromTheRulesList(t *testing.T) {
	const document = "rules:\n" +
		"  - DOMAIN,a.example,DIRECT\n" +
		"  - UID,501,DIRECT\n" +
		"  - AND,((UID,501),(NETWORK,udp)),REJECT\n" +
		"  - MATCH,DIRECT\n" +
		"sub-rules:\n" +
		"  s1:\n" +
		"    - UID,0,DIRECT\n" +
		"proxies: []\n"
	for _, seat := range registryProfiles {
		policy := runtimePolicyFor(seat.profile, seat.underNetworkExtension)
		rows, err := collectConfigDeviations(document, policy)
		if err != nil {
			t.Fatalf("%s: %v", seat.name, err)
		}
		var row *configDeviation
		for i := range rows {
			if rows[i].Field == "rules" && rows[i].RuleKind == "UID" {
				row = &rows[i]
			}
		}
		expected := policy.networkExtension && !policy.processMetadata().resolves("UID")
		switch {
		case expected && row == nil:
			t.Errorf("%s: three UID-bearing rules (two plain, one logic, one in sub-rules) and no rules/UID row: %v", seat.name, fieldsOf(rows))
		case !expected && row != nil:
			t.Errorf("%s: UID is constructible here, yet the report says it was removed: %+v", seat.name, *row)
		case expected:
			if row.Given != "3 rule(s), first at rules[1]" || !row.Written || row.Category != deviationUnavailable {
				t.Errorf("%s: row does not describe the removal as it happened: %+v", seat.name, *row)
			}
			if row.Effective == "" || row.Reason == "" || row.Source == "" {
				t.Errorf("%s: the synthesized row lost the registration's sentences: %+v", seat.name, *row)
			}
		}
	}

	// No UID anywhere: no row. The family row must not appear for a file that never wrote one.
	rows, err := collectConfigDeviations("rules:\n  - MATCH,DIRECT\nproxies: []\n", runtimePolicyFor(runtimeProfileIOSPacketTunnel, true))
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.RuleKind == "UID" {
			t.Fatalf("a file with no UID rule got a UID removal row: %+v", row)
		}
	}
}

// Every registration must be able to issue a row on some document, on every profile it
// claims. This is the gate the UID row lacked: the forced probe proves a forced rule moves
// the value, the completeness probe proves every change is registered, and nothing proved
// that a registered row can actually come out of the report. Two documents are enough:
// one that writes every registered path with a value the core would not leave alone, and
// one that writes nothing (the rows that exist precisely because a field was left unset).
func TestEveryRegisteredRuleIsIssuableOnSomeDocument(t *testing.T) {
	written := issuanceProbeDocument(t)
	const unwritten = "proxies: []\nrules:\n  - MATCH,DIRECT\n"
	for _, rule := range deviationRules {
		for _, seat := range registryProfiles {
			policy := runtimePolicyFor(seat.profile, seat.underNetworkExtension)
			if rule.applies != nil && !rule.applies(policy) {
				continue
			}
			issued := false
			for _, document := range []string{written, unwritten} {
				rows, err := collectConfigDeviations(document, policy)
				if err != nil {
					t.Fatalf("%s: %v", seat.name, err)
				}
				if reportsRegistration(rows, rule) {
					issued = true
					break
				}
			}
			if !issued {
				t.Errorf("%s is registered for %s but neither the everything-written document nor the "+
					"empty one makes it issue a row -- registered and unreachable, which is the duplicate-deviation "+
					"shape; either the registration's field is not an address the walk can find, or "+
					"its issue condition can never be met", rule.field, seat.name)
			}
		}
	}
}

// reportsRegistration is reportsField plus the kind, because every rules row shares the field
// "rules" and only RuleKind tells a UID row from a PROCESS-NAME one.
func reportsRegistration(rows []configDeviation, rule deviationRule) bool {
	for _, row := range rows {
		if row.Field == rule.field && (rule.ruleKind == "" || row.RuleKind == rule.ruleKind) {
			return true
		}
	}
	return false
}

// issuanceProbeDocument writes every path-addressed registration with a value the core would
// not leave alone: the opposite of a forced boolean, a different scalar otherwise, a real
// list for tun.dns-hijack (the one written value that is a non-event is any:53 alone), and
// UID-bearing rules for the rule-scan registration. default-only registrations are left
// unwritten on purpose: writing them is exactly the case that must NOT issue.
func issuanceProbeDocument(t *testing.T) string {
	t.Helper()
	root := map[string]any{"proxies": []any{}}
	rules := []any{"UID,501,DIRECT", "MATCH,DIRECT"}
	for _, rule := range deviationRules {
		if rule.ruleScan || rule.defaultOnly || strings.Contains(rule.field, " ") {
			continue
		}
		var value any
		switch {
		case rule.field == "tun.dns-hijack":
			value = []any{"198.51.100.1:53"}
		case rule.forcedValue == "true":
			value = false
		case rule.forcedValue == "false":
			value = true
		case rule.forcedValue != "":
			value = "probe-" + rule.forcedValue
		default:
			value = "probe"
		}
		setYAMLPath(root, rule.field, value)
	}
	root["rules"] = rules
	out, err := yaml.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func setYAMLPath(root map[string]any, path string, value any) {
	segments := strings.Split(path, ".")
	node := root
	for _, segment := range segments[:len(segments)-1] {
		child, ok := node[segment].(map[string]any)
		if !ok {
			child = map[string]any{}
			node[segment] = child
		}
		node = child
	}
	node[segments[len(segments)-1]] = value
}

var _ = fmt.Sprintf

// The kind rides out as data on every rules row, so a client can place and word the row
// without parsing "PROCESS-NAME rules" or "rules (UID)".
func TestRulesRowsCarryTheirKindAsData(t *testing.T) {
	const document = "rules:\n  - PROCESS-NAME,curl,DIRECT\n  - PROCESS-NAME-REGEX,.*,REJECT\n  - UID,501,DIRECT\n  - MATCH,DIRECT\nproxies: []\n"
	rows, err := collectConfigDeviations(document, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true))
	if err != nil {
		t.Fatal(err)
	}
	// field is the address; the kind is data. Three rules rows, three kinds, and every rules row
	// -- "rules" or "rules[i]" -- MUST carry a kind: with one shared field, a row without a kind
	// would render as a title identical to its neighbours (the iOS lane's condition for taking
	// the rename).
	want := map[string]bool{"PROCESS-NAME": true, "PROCESS-NAME-REGEX": true, "UID": true}
	seen := map[string]bool{}
	for _, row := range rows {
		isRulesRow := row.Field == "rules" || strings.HasPrefix(row.Field, "rules[")
		switch {
		case isRulesRow && row.RuleKind == "":
			t.Errorf("rules row without a ruleKind: %+v", row)
		case isRulesRow:
			seen[row.RuleKind] = true
			if row.RuleKind == "PROCESS-NAME-REGEX" && row.Field != "rules[1]" {
				t.Errorf("the matches-everything row keeps its indexed address: %+v", row)
			}
		case row.RuleKind != "":
			t.Errorf("%s is a setting row but carries ruleKind %q", row.Field, row.RuleKind)
		}
	}
	for kind := range want {
		if !seen[kind] {
			t.Errorf("no rules row for %s: %v", kind, fieldsOf(rows))
		}
	}
}
