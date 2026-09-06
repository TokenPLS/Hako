package hako

import (
	"encoding/json"
	"testing"
)

// A row in "what the running core did" names something that happened. Two shapes of row that
// named nothing were found in one sweep after the store-fake-ip defect: a rule reported on a
// profile where its guard never fires, and a forced value reported for a configuration that
// wrote exactly that value.

func deviationFields(t *testing.T, yaml, profile string) map[string]map[string]any {
	t.Helper()
	box, err := ConfigDeviationsJSON(yaml, profile)
	if err != nil {
		t.Fatalf("ConfigDeviationsJSON: %v", err)
	}
	var r struct {
		Deviations []map[string]any `json:"deviations"`
	}
	if err := json.Unmarshal([]byte(box.Value), &r); err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]any{}
	for _, d := range r.Deviations {
		out[d["field"].(string)] = d
	}
	return out
}

// Class A: geodata-loader is forced only where memoryConservativeGeodata is set. On a macOS
// profile the loader stays as written, and the report must not say otherwise.
func TestGeodataLoaderIsReportedOnlyWhereItIsForced(t *testing.T) {
	cfg := "geodata-loader: standard\nproxies: []\nrules:\n  - MATCH,DIRECT\n"
	for profile, want := range map[string]bool{
		RuntimeProfileIOSPacketTunnel:   true,
		RuntimeProfileTVOSPacketTunnel:  true,
		RuntimeProfileMacOSPacketTunnel: false,
		RuntimeProfileMacOSApplication:  false,
	} {
		_, got := deviationFields(t, cfg, profile)["geodata-loader"]
		if got != want {
			t.Errorf("%s: geodata-loader reported=%v, want %v (forced only under memoryConservativeGeodata)", profile, got, want)
		}
	}
}

// Class B: a configuration that wrote exactly the forced value has no deviation.
func TestAWrittenValueEqualToTheForcedOneIsNotReported(t *testing.T) {
	cases := map[string][2]string{ // field -> {written == forced, written != forced}
		"dns.enable":                  {"dns:\n  enable: true\n", "dns:\n  enable: false\n"},
		"tun.enable":                  {"tun:\n  enable: true\n", "tun:\n  enable: false\n"},
		"tun.auto-route":              {"tun:\n  enable: true\n  auto-route: false\n", "tun:\n  enable: true\n  auto-route: true\n"},
		"tun.gso":                     {"tun:\n  enable: true\n  gso: false\n", "tun:\n  enable: true\n  gso: true\n"},
		"tun.disable-icmp-forwarding": {"tun:\n  enable: true\n  disable-icmp-forwarding: true\n", "tun:\n  enable: true\n  disable-icmp-forwarding: false\n"},
		"geo-auto-update":             {"geo-auto-update: false\n", "geo-auto-update: true\n"},
		"tun.dns-hijack":              {"tun:\n  enable: true\n  dns-hijack: ['0.0.0.0:53']\n", "tun:\n  enable: true\n  dns-hijack: ['198.18.0.2:53']\n"},
	}
	tail := "proxies: []\nrules:\n  - MATCH,DIRECT\n"
	for field, pair := range cases {
		if _, reported := deviationFields(t, pair[0]+tail, RuntimeProfileIOSPacketTunnel)[field]; reported {
			t.Errorf("%s: written equal to the forced value, yet reported -- the core changed X to X", field)
		}
		if _, reported := deviationFields(t, pair[1]+tail, RuntimeProfileIOSPacketTunnel)[field]; !reported {
			t.Errorf("%s: written DIFFERENT from the forced value, yet not reported -- that one is a real deviation", field)
		}
	}
}

// The unwritten case still reports where the moved default differs from upstream's: nothing
// else the reader can see tells them. (A forced rule with no upstreamDefault is one where the
// force equals upstream's own default; an unwritten field there deviates from nothing and was
// never reported -- that's rule, not this change's.)
func TestAnUnwrittenForcedFieldWithAMovedDefaultIsStillReported(t *testing.T) {
	rows := deviationFields(t, "proxies: []\nrules:\n  - MATCH,DIRECT\n", RuntimeProfileIOSPacketTunnel)
	for _, field := range []string{"find-process-mode", "dns.enable", "profile.store-fake-ip"} {
		row, ok := rows[field]
		if !ok {
			t.Errorf("%s: not written and not reported; the changed default is exactly what to report", field)
			continue
		}
		if given, _ := row["given"].(string); given == "" || given[:7] != "not set" {
			t.Errorf("%s: unwritten row's given = %q, want \"not set (core default: …)\"", field, given)
		}
	}
}

// Every forced rule either names the scalar it forces or is on the short list of rules whose
// value is not a constant scalar. A forced rule with neither would silently keep reporting the
// written-equals-forced non-event.
func TestEveryForcedRuleNamesItsValueOrIsExempt(t *testing.T) {
	exempt := map[string]string{
		"tun.mtu":        "chosen at startup, not a constant",
		"tun.dns-hijack": "a list; compared raw by dnsHijackAlreadyHijacksAll",
	}
	for _, rule := range deviationRules {
		if rule.category != deviationForced {
			continue
		}
		if rule.forcedValue == "" {
			if _, ok := exempt[rule.field]; !ok {
				t.Errorf("%s: forced, no forcedValue, not exempt -- a written value equal to the force would be reported as a change", rule.field)
			}
		}
	}
}
