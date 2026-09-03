package hako

import "testing"

// The consuming lane's rules overview works on a STATIC configuration: the tunnel may be
// stopped, the subscription may not be activated yet, the user may be looking at an import
// preview. /hako/v1/deviations answers for a RUNNING core and does not exist there.
//
// The judgement does not need a running core -- it is a pure function of the rule string, which
// the signature already says. So it is exported, in the same class as ValidateGeodataForIOS:
// no Setup, no network, no process state.
func TestRuleEffectForIOSAnswersWithoutSetupOrARunningCore(t *testing.T) {
	// Deliberately no Setup(), no NewService(), no Start(). If this ever starts depending on
	// process state, it stops being usable where the consuming lane needs it.
	for rule, want := range map[string]string{
		"PROCESS-NAME,curl,REJECT":          RuleEffectNeverMatches,
		"IN-USER,alice,REJECT":              RuleEffectNeverMatches,
		"PROCESS-NAME-WILDCARD,cur*,DIRECT": RuleEffectNeverMatches,
		"PROCESS-NAME-REGEX,.*,DIRECT":      RuleEffectMatchesEverything,
		"PROCESS-NAME-WILDCARD,*,REJECT":    RuleEffectMatchesEverything,
		"DOMAIN-SUFFIX,example.com,DIRECT":  "",
		"MATCH,DIRECT":                      "",
	} {
		if got := RuleEffectForIOS(rule); got != want {
			t.Errorf("RuleEffectForIOS(%q) = %q, want %q", rule, got, want)
		}
	}
}

// The empty answer means "this is not a rule whose effect this function can state" -- an
// ordinary rule, or a logic rule whose branches would each need judging. It does NOT mean
// "safe". A caller that renders "" as a clean bill of health would be making the same mistake
// the deviation report was built to end, one layer up.
func TestTheEmptyAnswerIsNotAClaimOfSafety(t *testing.T) {
	logic := "OR,((PROCESS-NAME-REGEX,.*),(DOMAIN-SUFFIX,bank.example)),REJECT"
	if got := RuleEffectForIOS(logic); got != "" {
		t.Fatalf("a logic rule was classified as %q; its branches are separate questions and "+
			"this function does not walk them", got)
	}
	// Stated as a test rather than only in a doc comment, because the doc comment is what a
	// caller reads once and the test is what fails when someone changes the meaning.
}

// UID answers "" on iOS, and that is deliberate rather than an oversight -- but it is also
// indistinguishable from an ordinary DOMAIN-SUFFIX rule, so it is pinned here before somebody
// "fixes" it and breaks a consumer's mapping.
//
// The reason UID has no effect to report is that it is not kept: upstream refuses to construct
// it off linux/android/darwin, so this core removes it (uid_construction_gate.go). "What does
// this rule do to traffic" has no subject when the rule is not there.
//
// The consuming lane resolves the ambiguity the way it has to be resolved anyway: it asks the
// runtime profile whether the kind is unresolvable on this platform BEFORE asking this
// function. That gate cannot be removed -- on a macOS packet tunnel PROCESS-* and UID resolve
// from the socket table and are ordinary rules, so an iOS answer has no authority there. Once
// inside the gate, "" means "removed, nothing to say", and mapping it to inapplicable is
// correct: a rule that is not there is not applicable.
func TestUIDAnswersEmptyBecauseItIsRemovedNotBecauseItIsOrdinary(t *testing.T) {
	for _, rule := range []string{"UID,1000,DIRECT", "UID,0,REJECT"} {
		if got := RuleEffectForIOS(rule); got != "" {
			t.Errorf("RuleEffectForIOS(%q) = %q; UID is removed on this platform, so there is no "+
				"traffic effect to state. If this is ever changed to report something, the "+
				"consuming lane's mapping of \"\" to inapplicable has to change with it", rule, got)
		}
	}
	// The ambiguity, stated so it is a known property rather than a surprise: an ordinary rule
	// answers the same way. Callers must gate on the platform first, which they must do anyway.
	if RuleEffectForIOS("DOMAIN-SUFFIX,example.com,DIRECT") != "" {
		t.Fatal("an ordinary rule stopped answering empty; the documented ambiguity between " +
			"\"removed\" and \"not an owner-metadata rule\" was the basis for telling consumers " +
			"to gate on the profile first")
	}
}
