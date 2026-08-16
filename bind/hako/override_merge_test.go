package hako

import (
	"strings"
	"testing"
)

func TestMergeOverrideIdentityWhenEmpty(t *testing.T) {
	raw := "mode: rule\nrules:\n  - MATCH,DIRECT\n"
	out, err := MergeOverrideForIOS(raw, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Value != raw {
		t.Fatalf("identity expected, got:\n%s", out.Value)
	}
}

func TestMergeOverridePatchesScalarAndPrependsRule(t *testing.T) {
	raw := "mode: rule\nlog-level: info\nrules:\n  - MATCH,DIRECT\n"
	override := `{"patch":{"log-level":"warning","ipv6":true},"appendRules":["DOMAIN-SUFFIX,x.com,PROXY"],"prependRules":true}`
	out, err := MergeOverrideForIOS(raw, override)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := out.Value
	if !strings.Contains(got, "log-level: warning") {
		t.Fatalf("scalar patch missing:\n%s", got)
	}
	if !strings.Contains(got, "ipv6: true") {
		t.Fatalf("added key missing:\n%s", got)
	}
	// prepended rule must appear before MATCH
	i := strings.Index(got, "DOMAIN-SUFFIX,x.com,PROXY")
	j := strings.Index(got, "MATCH,DIRECT")
	if i < 0 || j < 0 || i > j {
		t.Fatalf("prepend order wrong (i=%d j=%d):\n%s", i, j, got)
	}
}

func TestMergeOverrideDeepMergesNestedMap(t *testing.T) {
	raw := "dns:\n  enable: true\n  nameserver:\n    - 1.1.1.1\n"
	override := `{"patch":{"dns":{"ipv6":false}}}`
	out, err := MergeOverrideForIOS(raw, override)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := out.Value
	if !strings.Contains(got, "enable: true") || !strings.Contains(got, "ipv6: false") {
		t.Fatalf("deep merge lost/omitted keys:\n%s", got)
	}
}
