package tunnel

import (
	P "github.com/TokenPLS/Hako/constant/provider"
	"maps"
)

// SnapshotRuleProviders retains a provider generation while reload may replace
// the global table. Callers read provider metadata after releasing configMux.
func SnapshotRuleProviders() map[string]P.RuleProvider {
	configMux.RLock()
	defer configMux.RUnlock()
	return maps.Clone(ruleProviders)
}
