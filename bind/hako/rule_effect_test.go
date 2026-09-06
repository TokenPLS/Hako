package hako

import (
	"strings"
	"testing"
)

// "Kept" is a statement about what this core did to a rule. It is not a statement about what
// the rule does, and on this platform those two come apart in a way that matters: with
// metadata.Process empty, PROCESS-NAME,curl never fires, while PROCESS-NAME-REGEX,.* fires on
// every connection. Reporting both as "kept" tells a user who wrote the second one that their
// rule is harmless, when it is the broadest rule in their file.
//
// So the effect is computed per rule, from upstream's own matching semantics
// (rules/common/process.go Match), and not inferred from the kind.
func TestOwnerMetadataRuleEffectIsComputedPerRuleNotPerKind(t *testing.T) {
	for name, testCase := range map[string]struct {
		rule string
		want string
	}{
		"plain name never fires":        {"PROCESS-NAME,curl,REJECT", RuleEffectNeverMatches},
		"plain path never fires":        {"PROCESS-PATH,/usr/bin/curl,REJECT", RuleEffectNeverMatches},
		"in-user never fires":           {"IN-USER,alice,REJECT", RuleEffectNeverMatches},
		"source-app never fires":        {"SOURCE-APP-TEAM-ID,ABCDE12345,REJECT", RuleEffectNeverMatches},
		"anchored wildcard never fires": {"PROCESS-NAME-WILDCARD,cur*,REJECT", RuleEffectNeverMatches},
		"anchored regex never fires":    {"PROCESS-NAME-REGEX,^curl$,REJECT", RuleEffectNeverMatches},

		"open regex fires on everything":    {"PROCESS-NAME-REGEX,.*,REJECT", RuleEffectMatchesEverything},
		"open wildcard fires on everything": {"PROCESS-NAME-WILDCARD,*,REJECT", RuleEffectMatchesEverything},
		// (curl)? is optional in full; .*curl? is NOT -- the "cur" is mandatory and only the
		// "l" is optional, which is what this case asserted at first and got wrong.
		"fully optional regex fires on everything": {"PROCESS-PATH-REGEX,(curl)?,REJECT", RuleEffectMatchesEverything},
		"partially optional regex never fires":     {"PROCESS-PATH-REGEX,.*curl?,REJECT", RuleEffectNeverMatches},

		"not an owner-metadata rule": {"DOMAIN-SUFFIX,example.com,DIRECT", ""},
	} {
		t.Run(name, func(t *testing.T) {
			if got := ownerMetadataRuleEffect(testCase.rule); got != testCase.want {
				t.Errorf("effect of %q = %q, want %q", testCase.rule, got, testCase.want)
			}
		})
	}
}

// The wire shape -- whether this travels as a new category value or as its own field -- is the
// consuming lane's call, because they decode it. The predicate does not depend on that answer,
// so it is built and tested here; the deviation-report assertion lands once they reply.
// (Building the whole thing first and asking after is how the previous guard shipped a gate
// that could not catch the bug it was written for.)

// The dangerous class is the one a reader is least likely to expect, so it is named
// individually with its own rule text: a rule written to single out one process has become the
// broadest rule in the file, and it keeps its action -- DIRECT bypasses everything.
func TestAnOpenPatternIsNamedIndividuallyWithItsEffect(t *testing.T) {
	const document = `
rules:
  - PROCESS-NAME,curl,REJECT
  - PROCESS-NAME-REGEX,.*,DIRECT
  - DOMAIN-SUFFIX,bank.example,REJECT
  - MATCH,DIRECT
`
	deviations, err := collectConfigDeviations(document, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true))
	if err != nil {
		t.Fatalf("collect: %v", err)
	}

	var open, inert *configDeviation
	for index := range deviations {
		switch deviations[index].Effect {
		case RuleEffectMatchesEverything:
			open = &deviations[index]
		case RuleEffectNeverMatches:
			inert = &deviations[index]
		}
	}
	if open == nil {
		t.Fatal("a rule that bypasses every connection is not reported with an effect; the " +
			"reader wrote it to single out one process and DIRECT is still attached to it")
	}
	if open.Field != "rules[1]" {
		t.Errorf("the dangerous rule is reported as %q, not by its position; a reader cannot "+
			"find it in their file", open.Field)
	}
	if !strings.Contains(open.Given, "PROCESS-NAME-REGEX") {
		t.Errorf("given = %q, want the rule text so the reader can match it against their file", open.Given)
	}
	if open.Alternative == "" {
		t.Error("the dangerous rule offers no way out; anchoring the pattern is one")
	}

	if inert == nil {
		t.Fatal("the inert rule is not reported at all")
	}
	// The inert ones are summarised by kind on purpose: a file with three hundred PROCESS-NAME
	// rules would otherwise bury the one line that matters.
	if strings.HasPrefix(inert.Field, "rules[") {
		t.Errorf("inert rules are named individually (%q); at scale that buries the dangerous "+
			"one, which is the only reason this asymmetry exists", inert.Field)
	}
}

// Effect travels as its own field, not as a Category value. The consuming lane's decoder treats
// Category as a strict enum and drops rows carrying an unknown one, so a new category would
// have made the most important row vanish from shipped clients with no sign of the loss.
func TestEffectIsASeparateFieldAndCategoryStaysKnown(t *testing.T) {
	const document = `
rules:
  - PROCESS-NAME-REGEX,.*,DIRECT
  - MATCH,DIRECT
`
	deviations, err := collectConfigDeviations(document, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true))
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	known := map[string]bool{
		deviationStripped: true, deviationForced: true, deviationUnavailable: true,
	}
	for _, deviation := range deviations {
		if !known[deviation.Category] {
			t.Errorf("%s carries category %q, which no shipped decoder knows; that row is "+
				"dropped on the far side and nobody is told", deviation.Field, deviation.Category)
		}
	}
}
