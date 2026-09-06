package hako

import (
	"strings"
	"testing"

	"github.com/TokenPLS/Hako/config"
)

// A logic rule is a container, not a condition. Stripping it because ONE branch
// names metadata this platform cannot resolve throws away every other branch
// with it -- and those branches are ordinary, executable conditions.
//
// The fixture below is the smallest shape that shows the loss: an OR whose
// second branch is a plain DOMAIN-SUFFIX. Upstream's rules/logic/logic.go
// evaluates OR branch by branch and short-circuits, so the unresolvable branch
// costs nothing there. Here the whole rule disappears and bank.example falls
// through to MATCH,DIRECT -- a REJECT silently became a DIRECT.
func TestLogicRuleKeepsExecutableBranches(t *testing.T) {
	const document = `
proxies: []
proxy-groups: []
rules:
  - OR,((PROCESS-NAME,evil),(DOMAIN-SUFFIX,bank.example)),REJECT
  - MATCH,DIRECT
`
	mihomo, ours := parseBoth(t, document)

	if len(mihomo.Rules) != 2 {
		t.Fatalf("fixture is wrong, not the code: mihomo parsed %d rules, want 2", len(mihomo.Rules))
	}
	if len(ours.Rules) != len(mihomo.Rules) {
		t.Errorf("rule count: mihomo %d, ours %d -- the OR rule was dropped whole", len(mihomo.Rules), len(ours.Rules))
	}
	for index := range mihomo.Rules {
		if index >= len(ours.Rules) {
			t.Errorf("rules[%d]: mihomo has %q, ours has nothing", index, mihomo.Rules[index].Payload())
			continue
		}
		if mihomo.Rules[index].RuleType() != ours.Rules[index].RuleType() {
			t.Errorf("rules[%d] type: mihomo %v, ours %v", index, mihomo.Rules[index].RuleType(), ours.Rules[index].RuleType())
		}
	}
}

// A SUB-RULE dispatch line carrying an unresolvable branch takes its entire
// target group down with it: the group's own rules stay in the config and
// become unreachable, which no reader can see by looking at the group.
func TestSubRuleDispatchSurvivesUnresolvableBranch(t *testing.T) {
	const document = `
proxies: []
proxy-groups: []
rules:
  - SUB-RULE,(OR,((PROCESS-NAME,evil),(NETWORK,TCP))),private
  - MATCH,DIRECT
sub-rules:
  private:
    - DOMAIN-SUFFIX,internal.example,REJECT
    - MATCH,DIRECT
`
	mihomo, ours := parseBoth(t, document)

	if len(ours.Rules) != len(mihomo.Rules) {
		t.Errorf("rule count: mihomo %d, ours %d -- the SUB-RULE dispatch was dropped, orphaning the group",
			len(mihomo.Rules), len(ours.Rules))
	}
}

// The three shapes below evaluate to TRUE against empty owner metadata, so
// keeping them is what upstream itself does when it cannot resolve a process:
//
//   - PROCESS-NAME-REGEX,.*   regexp ".*" matches ""
//   - PROCESS-NAME-WILDCARD,* wildcard "*" matches ""
//   - UID,0                   component/process/process_darwin.go returns uid 0
//     on EVERY path, including success -- so this is
//     upstream's own darwin behaviour, not our artifact
//
// says one yardstick: inherit upstream's behaviour even where it is a
// bug. These must parse and be kept, exactly like any other rule.
func TestAlwaysTrueOwnerMetadataShapesAreKeptLikeUpstream(t *testing.T) {
	for name, rule := range map[string]string{
		"process name regex":    `PROCESS-NAME-REGEX,.*,REJECT`,
		"process name wildcard": `PROCESS-NAME-WILDCARD,*,REJECT`,
		// UID is deliberately absent: unlike these two it cannot be constructed on GOOS=ios at
		// all, so keeping it fails the configuration instead of matching everything. Its own
		// behaviour is pinned in uid_construction_gate_test.go.
	} {
		t.Run(name, func(t *testing.T) {
			document := "proxies: []\nproxy-groups: []\nrules:\n  - " + rule + "\n  - MATCH,DIRECT\n"
			mihomo, ours := parseBoth(t, document)
			if len(ours.Rules) != len(mihomo.Rules) {
				t.Errorf("rule count: mihomo %d, ours %d", len(mihomo.Rules), len(ours.Rules))
			}
		})
	}
}

// Whatever this core decides about an unresolvable branch, the user has to be
// able to find out. A config carrying one plain PROCESS rule must not swallow
// the report for a second, different occurrence.
func TestEveryOccurrenceIsReportedNotDedupedByKind(t *testing.T) {
	const document = `
proxies: []
proxy-groups: []
rules:
  - PROCESS-NAME,first,REJECT
  - OR,((PROCESS-NAME,second),(DOMAIN-SUFFIX,bank.example)),REJECT
  - MATCH,DIRECT
`
	raw, err := config.UnmarshalRawConfig([]byte(document))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	occurrences := unavailableMetadataRuleOccurrences(raw, appleProcessMetadataCapability{})

	locations := make([]string, 0, len(occurrences))
	for _, occurrence := range occurrences {
		locations = append(locations, occurrence.location)
	}
	if len(occurrences) < 2 {
		t.Errorf("only %d occurrence(s) reported for two distinct PROCESS-NAME rules: %v", len(occurrences), locations)
	}
	if !strings.Contains(strings.Join(locations, " "), "rules[1]") {
		t.Errorf("the logic rule at rules[1] is not reported; got %v", locations)
	}
}
