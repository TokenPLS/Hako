package common

import (
	"strings"
	"testing"

	C "github.com/TokenPLS/Hako/constant"
)

func TestSourceAppIdentityRulesMatchOnlyTheirDedicatedMetadata(t *testing.T) {
	signing, err := NewSourceAppIdentity(
		"com.example.browser", "SIGNING", C.SourceAppSigningID,
	)
	if err != nil {
		t.Fatal(err)
	}
	team, err := NewSourceAppIdentity("ABCDE12345", "TEAM", C.SourceAppTeamID)
	if err != nil {
		t.Fatal(err)
	}
	metadata := &C.Metadata{
		Process:                    "com.example.browser",
		ProcessPath:                "/Applications/Browser.app/Contents/MacOS/Browser",
		SourceAppSigningIdentifier: "com.example.browser",
		SourceAppTeamIdentifier:    "ABCDE12345",
		SourceIdentityKnown:        true,
	}

	matched, adapter := signing.Match(metadata, C.RuleMatchHelper{})
	if !matched || adapter != "SIGNING" {
		t.Fatalf("signing match = %v/%q", matched, adapter)
	}
	matched, adapter = team.Match(metadata, C.RuleMatchHelper{})
	if !matched || adapter != "TEAM" {
		t.Fatalf("Team match = %v/%q", matched, adapter)
	}

	metadata.SourceAppSigningIdentifier = ""
	metadata.SourceAppTeamIdentifier = ""
	matched, _ = signing.Match(metadata, C.RuleMatchHelper{})
	if matched {
		t.Fatal("signing rule reused process name as signing identity")
	}
	matched, _ = team.Match(metadata, C.RuleMatchHelper{})
	if matched {
		t.Fatal("Team rule reused process path or name as Team identity")
	}
}

func TestSourceAppIdentityRulesAreExactBoundedAndRequestLookupWhenUnknown(t *testing.T) {
	signing, err := NewSourceAppIdentity(
		"com.Example.Browser", "DIRECT", C.SourceAppSigningID,
	)
	if err != nil {
		t.Fatal(err)
	}
	matched, _ := signing.Match(&C.Metadata{
		SourceIdentityKnown:        true,
		SourceAppSigningIdentifier: "com.example.browser",
	}, C.RuleMatchHelper{})
	if matched {
		t.Fatal("signing rule unexpectedly ignored case")
	}

	lookupCalled := false
	matched, adapter := signing.Match(&C.Metadata{}, C.RuleMatchHelper{
		FindProcess: func() { lookupCalled = true },
	})
	if matched || adapter != "" || !lookupCalled {
		t.Fatalf("unknown identity = %v/%q lookup=%v", matched, adapter, lookupCalled)
	}

	for _, test := range []struct {
		name     string
		payload  string
		ruleType C.RuleType
	}{
		{name: "empty", payload: "", ruleType: C.SourceAppSigningID},
		{name: "NUL", payload: "com.example\x00browser", ruleType: C.SourceAppSigningID},
		{name: "oversize signing", payload: strings.Repeat("s", 1025), ruleType: C.SourceAppSigningID},
		{name: "oversize Team", payload: strings.Repeat("T", 257), ruleType: C.SourceAppTeamID},
		{name: "wrong type", payload: "value", ruleType: C.MATCH},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewSourceAppIdentity(test.payload, "DIRECT", test.ruleType); err == nil {
				t.Fatal("NewSourceAppIdentity accepted invalid input")
			}
		})
	}
}
