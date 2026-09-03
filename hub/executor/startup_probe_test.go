package executor

import (
	"slices"
	"testing"

	P "github.com/TokenPLS/Hako/constant/provider"
)

// A provider that dies while it is being built has to have been named first.
//
// The per-provider probe was emitted after Initial returned, which is the one moment a
// process killed inside Initial never reaches. On a device this was not academic: a
// 4.7 MB domain rule-set took the extension from 25 MiB to the 50 MiB ceiling inside
// Initial, and the only account that survived named the step before it -- so the
// provider that spent the memory could be identified solely by re-running the tunnel
// against cut-down subsets until one of them lived.

type probedProvider struct {
	name         string
	providerType P.ProviderType
	onInitial    func()
}

func (p *probedProvider) Name() string               { return p.name }
func (p *probedProvider) VehicleType() P.VehicleType { return P.File }
func (p *probedProvider) Type() P.ProviderType       { return p.providerType }
func (p *probedProvider) Update() error              { return nil }

func (p *probedProvider) Initial() error {
	if p.onInitial != nil {
		p.onInitial()
	}
	return nil
}

func probeStepsAround(t *testing.T, providerType P.ProviderType, name string) (during, after []string) {
	t.Helper()
	var steps []string
	StartupProbe = func(step string) { steps = append(steps, step) }
	// One at a time, so the steps this reads are this provider's and nobody else's.
	SerializeProviderLoads = func() bool { return true }
	t.Cleanup(func() {
		StartupProbe = nil
		SerializeProviderLoads = nil
	})

	provider := &probedProvider{name: name, providerType: providerType}
	provider.onInitial = func() { during = slices.Clone(steps) }
	loadProvider(map[string]P.Provider{name: provider})
	return during, steps
}

func TestARuleProviderIsNamedBeforeItIsBuilt(t *testing.T) {
	during, after := probeStepsAround(t, P.Rule, "reject")

	if !slices.Contains(after, "rule-provider:reject") {
		t.Fatalf("the built rule provider was never billed. steps=%v", after)
	}
	if !slices.Contains(during, "rule-provider-begin:reject") {
		t.Fatalf("nothing named the rule provider before Initial ran; a kill in there is anonymous. steps=%v", during)
	}
}

func TestAProxyProviderIsNamedBeforeItIsBuilt(t *testing.T) {
	during, after := probeStepsAround(t, P.Proxy, "subscription")

	if !slices.Contains(during, "proxy-provider-begin:subscription") {
		t.Fatalf("nothing named the proxy provider before Initial ran. steps=%v", during)
	}
	if !slices.Contains(after, "proxy-provider:subscription") {
		t.Fatalf("the built proxy provider was never billed. steps=%v", after)
	}
}

// The seams are nil everywhere but the Apple binding, and a build that installs neither
// must behave exactly as upstream does.
func TestLoadProviderWithoutTheSeamsInstalledDoesNotPanic(t *testing.T) {
	StartupProbe = nil
	SerializeProviderLoads = nil

	built := false
	provider := &probedProvider{name: "plain", providerType: P.Rule, onInitial: func() { built = true }}
	loadProvider(map[string]P.Provider{"plain": provider})

	if !built {
		t.Fatal("an unprobed provider was not initialised")
	}
}
