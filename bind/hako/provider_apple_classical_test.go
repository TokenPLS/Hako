package hako

import (
	"bytes"
	"testing"

	P "github.com/TokenPLS/Hako/constant/provider"
)

// A macOS Transparent Proxy profile trusts process metadata, so PROCESS rules are
// KEPT rather than stripped -- but an entry this pinned core cannot parse or
// support must still be SKIPPED, not fail the whole provider. Before this the
// trusted path ran a strict validator that rejected the provider outright, so a
// single RULE-SET line failed Start on macOS while the iOS path (and upstream
// classicalStrategy.Insert) skipped it and loaded the rest.
func TestSanitizeClassicalProviderForAppleTrustedSkipsUnsupportedKeepsProcess(t *testing.T) {
	payload := []byte("payload:\n  - DOMAIN,keep.example\n  - RULE-SET,unsupported\n  - PROCESS-NAME,curl\n  - DOMAIN-SUFFIX,also.example\n")
	prepared, count, stripped, err := sanitizeClassicalProviderPayloadForApple(payload, P.YamlRule, appleProcessMetadataCapability{processPath: true, socketUser: true, inboundUser: true, codeSignature: true})
	if err != nil {
		t.Fatalf("a trusted macOS provider must not fail on an unsupported entry: %v", err)
	}
	if count != 3 {
		t.Fatalf("kept entries = %d, want 3 (two domains + the trusted PROCESS rule)", count)
	}
	if len(stripped) != 1 || stripped[0].reason != providerNoopRuleUnsupported {
		t.Fatalf("want exactly one unsupported-entry skip, got %+v", stripped)
	}
	if !bytes.Contains(prepared, []byte("PROCESS-NAME,curl")) {
		t.Fatalf("a trusted profile must keep the PROCESS rule: %q", prepared)
	}
	if bytes.Contains(prepared, []byte("RULE-SET")) {
		t.Fatalf("the unsupported entry must be dropped from the runtime copy: %q", prepared)
	}
	for _, want := range []string{"DOMAIN,keep.example", "DOMAIN-SUFFIX,also.example"} {
		if !bytes.Contains(prepared, []byte(want)) {
			t.Fatalf("executable rule %q was lost: %q", want, prepared)
		}
	}
}

// Untrusted (iOS/NE) keeps the established behavior: the metadata rule is
// stripped because the packet tunnel has no process input, and the unsupported
// entry is skipped.
func TestSanitizeClassicalProviderForAppleUntrustedStripsProcess(t *testing.T) {
	payload := []byte("payload:\n  - DOMAIN,keep.example\n  - RULE-SET,unsupported\n  - PROCESS-NAME,curl\n")
	prepared, count, stripped, err := sanitizeClassicalProviderPayloadForApple(payload, P.YamlRule, appleProcessMetadataCapability{})
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("kept entries = %d, want 1 (only the domain rule)", count)
	}
	if bytes.Contains(prepared, []byte("PROCESS-NAME")) {
		t.Fatalf("an untrusted profile must strip the metadata rule: %q", prepared)
	}
	if len(stripped) != 2 {
		t.Fatalf("want two skips (metadata + unsupported), got %+v", stripped)
	}
}

// Staging and counting want different things from the same bytes, and only one
// of them needs the expensive answer.
//
// Counting is a display figure the App shows at import: "this rule set holds N
// rules" has to mean rules the core will actually execute, so it parses every
// entry. Staging only has to remove what the platform cannot evaluate --
// PROCESS/UID/SOURCE-APP metadata, which is a prefix test. It used to parse
// every entry too, building each rule to learn whether it would build and then
// discarding it: 253ms of a 413ms staging pass over twenty-one rule sets, for
// an answer upstream computes again at load. classicalStrategy.Insert
// (rules/provider/classical_strategy.go:41) warn-skips an entry it cannot
// parse and keeps the rest, so an entry left in the staged bytes matches
// exactly what a removed one matched: nothing.

func TestStagingStripsMetadataRulesWithoutBuildingEveryRule(t *testing.T) {
	payload := []byte("payload:\n" +
		"  - DOMAIN,keep.example\n" +
		"  - PROCESS-NAME,Mail\n" +
		"  - DOMAIN-SUFFIX,also.example\n")
	prepared, stripped, err := stageClassicalProviderPayloadForApple(
		payload, P.YamlRule, appleProcessMetadataCapability{})
	if err != nil {
		t.Fatalf("staging: %v", err)
	}
	if len(stripped) != 1 || stripped[0].kind != "PROCESS-NAME" {
		t.Fatalf("staging must strip exactly the metadata rule, got %v", stripped)
	}
	if bytes.Contains(prepared, []byte("PROCESS-NAME")) {
		t.Fatal("a rule this profile cannot evaluate survived staging")
	}
	for _, kept := range []string{"keep.example", "also.example"} {
		if !bytes.Contains(prepared, []byte(kept)) {
			t.Fatalf("staging dropped an executable rule: %s", kept)
		}
	}
}

// The entry upstream would skip stays in the staged bytes. Removing it cost a
// full rule construction and changed nothing a reader can observe: upstream
// skips it at load either way, and its own warning names the line.
func TestStagingLeavesAnUnparseableEntryForUpstreamToSkip(t *testing.T) {
	payload := []byte("payload:\n" +
		"  - DOMAIN,keep.example\n" +
		"  - RULE-SET,nested-set-upstream-refuses\n")
	prepared, stripped, err := stageClassicalProviderPayloadForApple(
		payload, P.YamlRule, appleProcessMetadataCapability{})
	if err != nil {
		t.Fatalf("an unparseable entry must not fail staging: %v", err)
	}
	if len(stripped) != 0 {
		t.Fatalf("staging removed an entry only upstream is asked to judge: %v", stripped)
	}
	if !bytes.Equal(prepared, payload) {
		t.Fatal("nothing to strip must mean byte-identical passthrough, so the file can be hard-linked")
	}
}

// Nothing to strip has to mean the exact original bytes: the staged copy is a
// hard link to the published revision when it is unchanged, and re-encoding
// would break that and copy every rule set instead.
func TestStagingPassesThroughWhenThereIsNothingToStrip(t *testing.T) {
	payload := []byte("payload:\n  - DOMAIN,keep.example\n  - IP-CIDR,10.0.0.0/8\n")
	prepared, stripped, err := stageClassicalProviderPayloadForApple(
		payload, P.YamlRule, appleProcessMetadataCapability{})
	if err != nil {
		t.Fatal(err)
	}
	if len(stripped) != 0 || !bytes.Equal(prepared, payload) {
		t.Fatal("an untouched payload must come back as the same bytes")
	}
}

// Counting keeps the expensive answer, because "N rules" must mean rules that
// will run. The unparseable one is not among them.
func TestCountingStillReportsOnlyExecutableEntries(t *testing.T) {
	payload := []byte("payload:\n" +
		"  - DOMAIN,keep.example\n" +
		"  - RULE-SET,nested-set-upstream-refuses\n")
	count, err := ProviderEntryCountForIOS("rule", "classical", "yaml", payload)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("executable entry count = %d, want 1", count)
	}
}

// A profile that resolves process identity keeps those rules through staging,
// exactly as it does through counting.
func TestStagingKeepsProcessRulesWhereTheProfileCanResolveThem(t *testing.T) {
	payload := []byte("payload:\n  - PROCESS-NAME,Mail\n  - DOMAIN,keep.example\n")
	prepared, stripped, err := stageClassicalProviderPayloadForApple(
		payload, P.YamlRule,
		appleProcessMetadataCapability{processPath: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(stripped) != 0 || !bytes.Equal(prepared, payload) {
		t.Fatal("a profile that resolves PROCESS-NAME must keep those rules verbatim")
	}
}
