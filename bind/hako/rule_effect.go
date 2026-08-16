package hako

import (
	"regexp"
	"strings"

	"github.com/TokenPLS/Hako/component/wildcard"
)

// A rule's EFFECT is what it does to the user's traffic. It is a different question from what
// this core did to the rule, and on an Apple packet tunnel the two come apart:
//
//	PROCESS-NAME,curl,REJECT          -> never fires; traffic falls through
//	PROCESS-NAME-REGEX,.*,REJECT      -> fires on every connection
//
// Both are "kept". Reporting them with the same word tells the reader who wrote the second one
// that their rule is harmless, when it has quietly become the broadest rule in their file --
// and it keeps whatever action was attached, so a DIRECT bypasses everything and a REJECT
// rejects everything.
//
// The predicates below are upstream's, read off rules/common/process.go Match and
// rules/common/in_user.go / source_app_identity.go: on this platform metadata.Process,
// ProcessPath, InUser and the source-app identifiers are all empty, so each rule reduces to
// "does this pattern match the empty string".
// The two effects are exported so the containing app can name them without hardcoding the
// wire strings, and so a change here is a change both sides see.
const (
	RuleEffectNeverMatches      = "never-matches"
	RuleEffectMatchesEverything = "matches-everything"
	// EffectListenerOpened marks a field this core HONOURS that opens a
	// listening socket. It rides in Effect rather than Category on purpose: the
	// client decodes Category as a strict enum and DROPS a row carrying an
	// unknown value, so a new category would have deleted these rows from
	// already-shipped clients -- the rows most worth seeing. An unknown Effect
	// is ignored and the row still renders.
	EffectListenerOpened = "listener-opened"
)

// RuleEffectForIOS reports what a single rule does to traffic on an Apple packet tunnel:
// RuleEffectNeverMatches, RuleEffectMatchesEverything, or "" when the rule is not one whose
// effect this can state.
//
// It is a pure function of the rule text -- no Setup, no running core, no network -- because
// the place that needs it most has none of those: the app's rules overview works on a static
// configuration, on a stopped tunnel, on a subscription that has not been activated, on an
// import preview. /hako/v1/deviations answers for a RUNNING core and is absent there. Without
// this, the app would have to re-derive the judgement from the rule kind, which is what it was
// doing when it labelled PROCESS-NAME-REGEX,.* "not applicable" while that rule was matching
// every connection.
//
// "" is not a claim of safety. It means an ordinary rule, or a logic rule whose branches are
// each separate questions this does not walk. A caller that renders "" as a clean bill of
// health repeats, one layer up, the mistake the deviation report exists to end.
func RuleEffectForIOS(rule string) string {
	return ownerMetadataRuleEffect(rule)
}

// ownerMetadataRuleEffect returns one of the two constants for an owner-metadata rule, or "" for
// any other rule. It answers for the platform this build runs on -- the caller decides whether
// the profile can resolve the metadata at all.
func ownerMetadataRuleEffect(rule string) string {
	kind, pattern := splitRuleKindAndPattern(rule)
	if kind == "" {
		return ""
	}
	switch strings.ToUpper(kind) {
	case "PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX":
		// Upstream: ps.regexp.MatchString(target) with target empty.
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			// Upstream would have failed to construct it; the parser reports that, not us.
			return RuleEffectNeverMatches
		}
		if compiled.MatchString("") {
			return RuleEffectMatchesEverything
		}
		return RuleEffectNeverMatches
	case "PROCESS-NAME-WILDCARD", "PROCESS-PATH-WILDCARD":
		// Upstream lowercases both sides before matching.
		if wildcard.Match(strings.ToLower(pattern), "") {
			return RuleEffectMatchesEverything
		}
		return RuleEffectNeverMatches
	case "PROCESS-NAME", "PROCESS-PATH":
		// Upstream: strings.EqualFold(target, ps.pattern) with target empty.
		if pattern == "" {
			return RuleEffectMatchesEverything
		}
		return RuleEffectNeverMatches
	case "IN-USER":
		// Upstream compares metadata.InUser against each listed user.
		if pattern == "" {
			return RuleEffectMatchesEverything
		}
		return RuleEffectNeverMatches
	case "SOURCE-APP-SIGNING-ID", "SOURCE-APP-TEAM-ID":
		// Upstream: actual == rule.pattern, with actual empty.
		if pattern == "" {
			return RuleEffectMatchesEverything
		}
		return RuleEffectNeverMatches
	default:
		return ""
	}
}

// splitRuleKindAndPattern takes "KIND,pattern,ADAPTER" apart. It deliberately does not try to
// understand logic rules: a branch inside one is reached by the caller walking the branches,
// not by this function guessing at parentheses.
func splitRuleKindAndPattern(rule string) (string, string) {
	rule = strings.TrimSpace(rule)
	if strings.HasPrefix(rule, "(") {
		rule = strings.TrimPrefix(rule, "(")
	}
	firstComma := strings.IndexByte(rule, ',')
	if firstComma < 0 {
		return "", ""
	}
	kind := strings.TrimSpace(rule[:firstComma])
	rest := rule[firstComma+1:]
	// The pattern runs to the next comma, or to the end for a branch inside a logic rule.
	if secondComma := strings.IndexByte(rest, ','); secondComma >= 0 {
		return kind, strings.TrimSpace(rest[:secondComma])
	}
	return kind, strings.TrimSpace(strings.TrimSuffix(rest, ")"))
}
