package hako

import (
	"strings"
	"testing"

	"github.com/TokenPLS/Hako/config"
)

// tun.route-address-set was rejected outright, on the stated ground that it "decides WHICH
// traffic enters the tunnel, so silently dropping it would misroute". That is not what the
// field does.
//
// In sing-tun the value reaches exactly three files -- redirect_linux.go,
// redirect_nftables.go, redirect_nftables_rules.go -- and only ever through autoRedirect,
// which is Linux-only and needs nftables. Upstream's own documentation says as much. On
// darwin, mihomo parses the field and ignores it: nothing consumes it, and nothing errors.
//
// So a rejection here is stricter than upstream without being required by the platform,
// which names as a defect outright. Concretely: a configuration that runs on mihomo
// refuses to start on this core, and the user is told their routing would be wrong.
func TestRouteAddressSetLoadsHereBecauseItLoadsUpstream(t *testing.T) {
	for _, field := range []string{"route-address-set", "route-exclude-address-set"} {
		t.Run(field, func(t *testing.T) {
			document := `
tun:
  enable: true
  ` + field + `:
    - geoip-cn
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
			if _, err := config.Parse([]byte(document)); err != nil {
				t.Fatalf("fixture is wrong, not the code: mihomo rejected it too: %v", err)
			}
			if _, err := parseConfigForIOS(document, true); err != nil {
				t.Errorf("this core refuses a configuration mihomo runs: %v", err)
			}
		})
	}
}

// Ignoring it silently is the other half of the mistake. Upstream ignores it because on that
// platform it is inert; here the reader deserves to know the line does nothing, especially
// since it was until now an error they may have written the config around.
func TestRouteAddressSetIsReportedAsInertRatherThanSilentlyDropped(t *testing.T) {
	const document = `
tun:
  enable: true
  route-address-set:
    - geoip-cn
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	deviations, err := collectConfigDeviations(document, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true))
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	for _, deviation := range deviations {
		if deviation.Field != "tun.route-address-set" {
			continue
		}
		if deviation.Category != deviationUnavailable {
			t.Errorf("category = %q, want %q: no Apple platform has the nftables set this "+
				"configures", deviation.Category, deviationUnavailable)
		}
		if !strings.Contains(strings.ToLower(deviation.Source), "linux") &&
			!strings.Contains(strings.ToLower(deviation.Source), "nftables") {
			t.Errorf("source = %q, want it to name the Linux/nftables facility this needs", deviation.Source)
		}
		return
	}
	t.Error("tun.route-address-set is accepted and ignored with nothing said; the reader has " +
		"no way to learn the line is inert")
}
