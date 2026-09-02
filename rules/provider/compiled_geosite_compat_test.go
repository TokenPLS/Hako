package provider

import (
	"bytes"
	"testing"

	"github.com/TokenPLS/Hako/component/geodata/compiled"
	"github.com/TokenPLS/Hako/component/trie"
	C "github.com/TokenPLS/Hako/constant"
	P "github.com/TokenPLS/Hako/constant/provider"
)

// Compiled geosite categories claim to be rule sets in the same binary layout,
// which is only worth claiming if this reader accepts them. Written as a test
// rather than a comment because the layout lives in two files now, and a field
// added to one and not the other would otherwise surface as an unreadable cache
// on a reader's device.
func TestCompiledGeositeArtifactIsReadableAsARuleSet(t *testing.T) {
	tree := trie.New[struct{}]()
	for _, domain := range []string{"+.example.com", "+.qq.com", "full.example.org"} {
		if err := tree.Insert(domain, struct{}{}); err != nil {
			t.Fatal(err)
		}
	}
	var artifact bytes.Buffer
	if err := compiled.Write(&artifact, tree.NewDomainSet(), 3, nil); err != nil {
		t.Fatal(err)
	}

	strategy, err := rulesMrsParse(artifact.Bytes(), newStrategy(P.Domain, nil))
	if err != nil {
		t.Fatalf("the rule set reader refused a compiled category: %v", err)
	}
	if strategy.Count() != 3 {
		t.Fatalf("count = %d, want 3", strategy.Count())
	}
	matches := func(host string) bool {
		return strategy.Match(&C.Metadata{Host: host}, C.RuleMatchHelper{})
	}
	for _, hit := range []string{"example.com", "www.qq.com"} {
		if !matches(hit) {
			t.Fatalf("the rule set does not match %q", hit)
		}
	}
	if matches("example.net") {
		t.Fatal("the rule set matches a domain it was not given")
	}
}
