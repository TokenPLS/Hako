package tunnel

import (
	P "github.com/TokenPLS/Hako/constant/provider"
	"sync"
	"testing"
)

func TestSnapshotRuleProvidersDuringReplacement(t *testing.T) {
	oldRules, oldSubRules, oldProviders := rules, subRules, ruleProviders
	t.Cleanup(func() { UpdateRules(oldRules, oldSubRules, oldProviders) })
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			_ = SnapshotRuleProviders()
		}
	}()
	for i := 0; i < 1000; i++ {
		UpdateRules(nil, nil, map[string]P.RuleProvider{"test": nil})
	}
	wg.Wait()
	snapshot := SnapshotRuleProviders()
	delete(snapshot, "test")
	if _, ok := SnapshotRuleProviders()["test"]; !ok {
		t.Fatal("snapshot mutation changed live table")
	}
}
