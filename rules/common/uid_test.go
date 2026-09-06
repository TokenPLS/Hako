package common

import (
	"runtime"
	"strings"
	"testing"

	C "github.com/TokenPLS/Hako/constant"
)

func TestUIDRulePlatformConstruction(t *testing.T) {
	rule, err := NewUid("501", "DIRECT")
	switch runtime.GOOS {
	case "linux", "android", "darwin":
		if err != nil {
			t.Fatalf("NewUid on metadata-capable %s: %v", runtime.GOOS, err)
		}
		if rule == nil {
			t.Fatal("NewUid returned a nil rule")
		}
	default:
		if err == nil || !strings.Contains(err.Error(), "not support") {
			t.Fatalf("NewUid on unsupported %s error = %v", runtime.GOOS, err)
		}
	}
}

func TestUIDRuleMatchesInjectedNonRootMetadata(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "android" && runtime.GOOS != "darwin" {
		t.Skip("UID construction is deliberately unavailable on this platform")
	}
	rule, err := NewUid("500-502", "PROXY")
	if err != nil {
		t.Fatal(err)
	}
	matched, adapter := rule.Match(&C.Metadata{Uid: 501}, C.RuleMatchHelper{})
	if !matched || adapter != "PROXY" {
		t.Fatalf("injected UID match = %v/%q, want true/PROXY", matched, adapter)
	}
	matched, adapter = rule.Match(&C.Metadata{Uid: 503}, C.RuleMatchHelper{})
	if matched || adapter != "" {
		t.Fatalf("non-member UID match = %v/%q, want false/empty", matched, adapter)
	}
}

func TestUIDRuleDistinguishesKnownRootFromUnknownUID(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "android" && runtime.GOOS != "darwin" {
		t.Skip("UID construction is deliberately unavailable on this platform")
	}
	rule, err := NewUid("0", "ROOT")
	if err != nil {
		t.Fatal(err)
	}

	matched, adapter := rule.Match(&C.Metadata{Uid: 0, UidKnown: true}, C.RuleMatchHelper{})
	if !matched || adapter != "ROOT" {
		t.Fatalf("known root UID match = %v/%q, want true/ROOT", matched, adapter)
	}

	lookupCalled := false
	matched, adapter = rule.Match(&C.Metadata{}, C.RuleMatchHelper{
		FindProcess: func() { lookupCalled = true },
	})
	if matched || adapter != "" || !lookupCalled {
		t.Fatalf("unknown UID match = %v/%q lookup=%v, want false/empty/true",
			matched, adapter, lookupCalled)
	}
}
