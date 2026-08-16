package hako

import (
	"strings"
	"testing"

	"github.com/TokenPLS/Hako/config"
	P "github.com/TokenPLS/Hako/constant/provider"
)

// fakeRuleProvider satisfies P.RuleProvider; only Name/VehicleType are read by
// the validator (the rest is the embedded nil interface, never called here).
type fakeRuleProvider struct {
	P.RuleProvider
	vehicle P.VehicleType
}

func (f *fakeRuleProvider) Name() string               { return "remote-rules" }
func (f *fakeRuleProvider) VehicleType() P.VehicleType { return f.vehicle }

type fakeProxyProvider struct {
	P.ProxyProvider
	vehicle P.VehicleType
}

func (f *fakeProxyProvider) Name() string               { return "remote-proxies" }
func (f *fakeProxyProvider) VehicleType() P.VehicleType { return f.vehicle }

func TestValidateProvidersRejectsRemote(t *testing.T) {
	http := &config.Config{
		DNS:           &config.DNS{Enable: false},
		RuleProviders: map[string]P.RuleProvider{"remote-rules": &fakeRuleProvider{vehicle: P.HTTP}},
	}
	err := validateForIOS(http, false)
	if err == nil || !strings.Contains(err.Error(), "remote (HTTP)") {
		t.Fatalf("expected HTTP provider rejection, got %v", err)
	}

	file := &config.Config{
		DNS:           &config.DNS{Enable: false},
		RuleProviders: map[string]P.RuleProvider{"local-rules": &fakeRuleProvider{vehicle: P.File}},
	}
	if err := validateForIOS(file, false); err != nil {
		t.Fatalf("file provider should pass: %v", err)
	}
}

func TestValidateProvidersUsesStableNamePriority(t *testing.T) {
	cfg := &config.Config{
		Providers: map[string]P.ProxyProvider{
			"zebra": &fakeProxyProvider{vehicle: P.HTTP},
			"alpha": &fakeProxyProvider{vehicle: P.HTTP},
		},
	}
	err := validateProvidersForIOS(cfg)
	if err == nil || !strings.Contains(err.Error(), `"alpha"`) {
		t.Fatalf("first provider error = %v, want alpha", err)
	}
}
