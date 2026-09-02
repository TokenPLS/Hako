package hako

import (
	"strings"
	"testing"
)

// The configuration a reader writes when they mean "Google's names here, the rest of .com
// there". Both transforms on the activation path used to hand the core the opposite.
const orderSensitiveConfig = `mixed-port: 7890
log-level: warning
dns:
  enable: true
  nameserver:
    - 1.1.1.1
  nameserver-policy:
    "+.google.com": 8.8.8.8
    "+.com": 223.5.5.5
  proxy-server-nameserver-policy:
    "+.zulu.example": 9.9.9.9
    "+.alpha.example": 1.0.0.1
hosts:
  "zzz.example": 1.2.3.4
  "aaa.example": 5.6.7.8
proxies: []
rules:
  - DOMAIN-SUFFIX,google.com,DIRECT
  - MATCH,DIRECT
`

func indexOfKey(t *testing.T, document, key string) int {
	t.Helper()
	at := strings.Index(document, key)
	if at < 0 {
		t.Fatalf("key %q is missing from the document entirely:\n%s", key, document)
	}
	return at
}

// The one that routes traffic. Everything else in this file is a guard around it.
func TestFinalizeKeepsTheNameserverPolicyInTheOrderItWasWritten(t *testing.T) {
	box, err := FinalizeForIOS(orderSensitiveConfig, "")
	if err != nil {
		t.Fatalf("FinalizeForIOS: %v", err)
	}
	out := box.Value
	specific := indexOfKey(t, out, "+.google.com")
	general := indexOfKey(t, out, "+.com:")
	if general < specific {
		t.Fatalf("the general '+.com' precedes the specific '+.google.com'.\n"+
			"nameserver-policy is walked in order and the resolver returns on the first match "+
			"(dns/resolver.go), so every name under .com -- google.com included -- would go to "+
			"the fallback the reader wrote for everything else.\n%s", out)
	}
}

// Finalize runs whether or not the reader set anything, which is why this defect did not need
// an override to bite.
func TestFinalizeReordersNothingWithNoOverrideInvolved(t *testing.T) {
	box, err := FinalizeForIOS(orderSensitiveConfig, "")
	if err != nil {
		t.Fatalf("FinalizeForIOS: %v", err)
	}
	out := box.Value
	if indexOfKey(t, out, "+.zulu.example") > indexOfKey(t, out, "+.alpha.example") {
		t.Fatalf("proxy-server-nameserver-policy was alphabetised; it is first-match too\n%s", out)
	}
	if indexOfKey(t, out, "zzz.example") > indexOfKey(t, out, "aaa.example") {
		t.Fatalf("hosts was alphabetised\n%s", out)
	}
}

func TestMergeKeepsTheNameserverPolicyInTheOrderItWasWritten(t *testing.T) {
	box, err := MergeOverrideForIOS(orderSensitiveConfig, `{"patch":{"log-level":"info"}}`)
	if err != nil {
		t.Fatalf("MergeOverrideForIOS: %v", err)
	}
	out := box.Value
	if indexOfKey(t, out, "+.com:") < indexOfKey(t, out, "+.google.com") {
		t.Fatalf("merging one unrelated override reordered the DNS policy\n%s", out)
	}
	if !strings.Contains(out, "log-level: info") {
		t.Fatalf("the override itself did not land\n%s", out)
	}
}

// Order is not the only thing the pass must not disturb: it re-emits the document, so it has
// to give back the same keys with the same values.
func TestRestoringOrderChangesNothingButOrder(t *testing.T) {
	transformed := "b: 2\na: 1\nc:\n    y: 2\n    x: 1\n"
	got := restoreSourceKeyOrder("a: 1\nb: 2\nc:\n  x: 1\n  y: 2\n", transformed)
	want := "a: 1\nb: 2\nc:\n    x: 1\n    y: 2\n"
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

// A key the transform introduced has no place in the source order, and inventing one would
// mean it lands somewhere different depending on what else is in the document.
func TestAddedKeysFollowTheSourceKeys(t *testing.T) {
	got := restoreSourceKeyOrder("z: 1\na: 2\n", "a: 2\nadded: 3\nz: 1\n")
	if !strings.HasPrefix(got, "z: 1\na: 2\n") {
		t.Fatalf("the source's own keys did not come back in its order:\n%s", got)
	}
	if !strings.Contains(got, "added: 3") {
		t.Fatalf("a key the transform added was dropped:\n%s", got)
	}
	if strings.Index(got, "added: 3") < strings.Index(got, "a: 2") {
		t.Fatalf("an added key jumped ahead of the source's keys:\n%s", got)
	}
}

// The pass exists to preserve an ordering. Losing the document because it could not is a
// worse outcome than the ordering it was trying to save.
func TestAnUnparseableSideLeavesTheDocumentAlone(t *testing.T) {
	transformed := "a: 1\n"
	if got := restoreSourceKeyOrder("\tthis is not yaml: [", transformed); got != transformed {
		t.Fatalf("an unparseable source changed the output: %q", got)
	}
	broken := "\tnor is this: ["
	if got := restoreSourceKeyOrder("a: 1\n", broken); got != broken {
		t.Fatalf("an unparseable transform result was rewritten: %q", got)
	}
}

// A configuration using anchors reaches the transform with them resolved, so the two sides
// disagree in shape. It must terminate and it must not lose anything.
func TestAnchorsInTheSourceDoNotDerailThePass(t *testing.T) {
	source := "base: &b\n  y: 2\n  x: 1\nuse: *b\n"
	transformed := "base:\n    x: 1\n    y: 2\nuse:\n    x: 1\n    y: 2\n"
	got := restoreSourceKeyOrder(source, transformed)
	for _, want := range []string{"x: 1", "y: 2", "use:"} {
		if !strings.Contains(got, want) {
			t.Fatalf("%q went missing:\n%s", want, got)
		}
	}
}

// Mappings nested inside a sequence are reached -- a proxy or a rule-provider holds one.
func TestAMappingInsideAListIsReordered(t *testing.T) {
	got := restoreSourceKeyOrder(
		"proxies:\n  - name: a\n    type: ss\n",
		"proxies:\n    - type: ss\n      name: a\n",
	)
	if strings.Index(got, "type: ss") < strings.Index(got, "name: a") {
		t.Fatalf("the mapping inside the list kept the alphabetised order:\n%s", got)
	}
}

// Sequences were never the problem and must not become one.
func TestListOrderIsUntouched(t *testing.T) {
	box, err := FinalizeForIOS(orderSensitiveConfig, "")
	if err != nil {
		t.Fatalf("FinalizeForIOS: %v", err)
	}
	out := box.Value
	if indexOfKey(t, out, "DOMAIN-SUFFIX,google.com,DIRECT") > indexOfKey(t, out, "MATCH,DIRECT") {
		t.Fatalf("the rule list was reordered, which would be far worse than the bug this "+
			"pass fixes\n%s", out)
	}
}

// A policy written entirely in the app, with the file never mentioning one. The override
// text is ordered JSON -- "+.google.com" first, "+.com" second -- and the merge emits it
// through a Go map. Without the override as a second reference it is "added by the
// transform", and the transform's emit order is the alphabet. The iOS lane found this one.
func TestAPolicyWrittenOnlyInTheOverrideKeepsTheOverridesOrder(t *testing.T) {
	raw := "mixed-port: 7890\nproxies: []\nrules:\n  - MATCH,DIRECT\n"
	override := `{"patch":{"dns":{"enable":true,"nameserver-policy":{"+.google.com":"8.8.8.8","+.com":"223.5.5.5"}}}}`
	box, err := MergeOverrideForIOS(raw, override)
	if err != nil {
		t.Fatalf("MergeOverrideForIOS: %v", err)
	}
	out := box.Value
	if indexOfKey(t, out, "+.com:") < indexOfKey(t, out, "+.google.com") {
		t.Fatalf("a policy the reader wrote in the app came out alphabetised -- the same defect "+
			"as the file case, for the readers who never touched a file:\n%s", out)
	}
}

// When the file and the override both carry a key, the file's position wins. The override
// only supplies order for keys the file does not have; it cannot move a key the file placed.
func TestTheFilesOrderWinsOverTheOverridesForKeysBothHave(t *testing.T) {
	raw := "dns:\n  nameserver-policy:\n    \"+.google.com\": 8.8.8.8\n    \"+.com\": 223.5.5.5\nproxies: []\nrules:\n  - MATCH,DIRECT\n"
	// The override lists them the other way round and changes one value.
	override := `{"patch":{"dns":{"nameserver-policy":{"+.com":"1.1.1.1","+.google.com":"8.8.8.8"}}}}`
	box, err := MergeOverrideForIOS(raw, override)
	if err != nil {
		t.Fatalf("MergeOverrideForIOS: %v", err)
	}
	out := box.Value
	if indexOfKey(t, out, "+.com:") < indexOfKey(t, out, "+.google.com") {
		t.Fatalf("the override's key order displaced the file's for a key both have:\n%s", out)
	}
	if !strings.Contains(out, "+.com: 1.1.1.1") {
		t.Fatalf("the override's value did not land, so the precedence test is not testing "+
			"a merge that happened:\n%s", out)
	}
}

// A malformed override must not be able to displace the file's order -- it is simply not a
// reference. (MergeOverrideForIOS rejects malformed JSON before the pass runs; this exercises
// the pass directly so the guarantee does not depend on that.)
func TestAMalformedSecondReferenceIsIgnored(t *testing.T) {
	got := restoreKeyOrderFrom("b: 2\na: 1\n", "a: 1\nb: 2\n", "{not json")
	if got != "a: 1\nb: 2\n" {
		t.Fatalf("got %q", got)
	}
}
