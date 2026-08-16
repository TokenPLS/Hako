package hako

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/TokenPLS/Hako/config"
)

// UID is the one owner-metadata kind upstream refuses to CONSTRUCT rather than merely
// evaluate to false. rules/common/uid.go:23 gates NewUid on
// runtime.GOOS being linux, android or darwin; every other GOOS gets an error, and an error
// from a rule constructor fails config.Parse for the entire configuration.
//
// That distinction -- construct versus evaluate -- is what an earlier pass in this batch
// missed. It removed the stripping of all ten kinds after establishing that upstream keeps
// them and evaluates them against empty metadata, which is true for nine. For UID on GOOS=ios
// it meant a subscription written for Android stopped starting at all, where before the rule
// was dropped and the rest ran.
//
// The tests could not have caught it: they run on the host, which is darwin, and darwin is on
// upstream's allow-list. So this file pairs the strip with a test that reads upstream's source
// for the platform list rather than restating it -- the correspondence is load-bearing, and
// the only cheap way to keep it honest is to check it against the thing it must correspond to.
func uidRuleConstructible(goos string) bool {
	switch goos {
	case "linux", "android", "darwin":
		return true
	default:
		return false
	}
}

// uidRuleToken matches a UID rule at the start of a rule string or immediately inside a
// logic rule's parenthesis, the two places a rule kind can appear.
var uidRuleToken = regexp.MustCompile(`(?i)(?:^|\()\s*UID\s*,`)

func ruleCarriesUID(rule string) bool {
	if strings.IndexByte(rule, '(') < 0 {
		comma := strings.IndexByte(rule, ',')
		return comma > 0 && strings.EqualFold(strings.TrimSpace(rule[:comma]), "UID")
	}
	return uidRuleToken.MatchString(rule)
}

// stripUnconstructibleUIDRules removes UID rules where upstream cannot build them. A logic
// rule carrying a UID branch goes whole: rules/logic/logic.go parsePayload returns on the
// first branch that fails, so keeping the rule fails the configuration. That loses the
// executable branches alongside it -- the harm this batch fixed for the other nine kinds --
// which is why every removal is reported rather than done quietly.
func stripUnconstructibleUIDRules(raw *config.RawConfig) []metadataRuleOccurrence {
	removed := make([]metadataRuleOccurrence, 0)
	filter := func(rules []string, location func(int) string) []string {
		kept := make([]string, 0, len(rules))
		for index, rule := range rules {
			if ruleCarriesUID(rule) {
				removed = append(removed, metadataRuleOccurrence{kind: "UID", location: location(index)})
				continue
			}
			kept = append(kept, rule)
		}
		return kept
	}
	raw.Rule = filter(raw.Rule, func(index int) string { return fmt.Sprintf("rules[%d]", index) })
	names := make([]string, 0, len(raw.SubRules))
	for name := range raw.SubRules {
		names = append(names, name)
	}
	sort.Strings(names)
	for groupIndex, name := range names {
		raw.SubRules[name] = filter(raw.SubRules[name], func(ruleIndex int) string {
			return fmt.Sprintf("sub-rules[%d][%d]", groupIndex, ruleIndex)
		})
	}
	for _, definition := range raw.RuleProvider {
		typeName, _ := definition["type"].(string)
		behavior, _ := definition["behavior"].(string)
		if typeName != "inline" || behavior != "classical" {
			continue
		}
		if payload, ok := definition["payload"].([]any); ok {
			kept := make([]any, 0, len(payload))
			for _, item := range payload {
				if rule, isString := item.(string); isString && ruleCarriesUID(rule) {
					removed = append(removed, metadataRuleOccurrence{kind: "UID", location: "rule-providers payload"})
					continue
				}
				kept = append(kept, item)
			}
			definition["payload"] = kept
		}
	}
	return removed
}

// uidRuleExplanation is what every surface says about a removed UID rule. It names the
// platform fact rather than a policy, because that is what this is.
const uidRuleExplanation = "UID names a socket owner this platform does not expose, and mihomo's own " +
	"rule constructor refuses to build it here (rules/common/uid.go), so the rule is removed " +
	"rather than allowed to fail the whole configuration"
