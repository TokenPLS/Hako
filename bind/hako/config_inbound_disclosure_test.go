package hako

import (
	"strings"
	"testing"
)

// The five inbound-server fields (listeners, tunnels, ss-config, vmess-config,
// tuic-server) used to be zeroed here and are not any more -- the zero-squeeze
// ruling restored them, because upstream allows them and the platform allows
// them. The deviation report never followed: it still told the reader "no
// configured inbound listeners are opened" for a configuration that opens them.
//
// A report that states a safety property the code stopped providing is worse
// than no report: the reader checks it, sees the listener is closed, and stops
// looking. And these listeners are not covered by the allow-lan permission --
// each carries its own listen address, defaulting to 0.0.0.0
// (listener/inbound/base.go) -- so a subscription can open an unauthenticated
// proxy on every interface without the reader agreeing to anything.
//
// Threat model: the subscription author opens it, anyone on the same network
// uses it.

func deviationFor(t *testing.T, deviations []configDeviation, field string) configDeviation {
	t.Helper()
	for _, deviation := range deviations {
		if deviation.Field == field {
			return deviation
		}
	}
	t.Fatalf("no deviation reported for %q", field)
	return configDeviation{}
}

func TestInboundServerFieldsAreNoLongerReportedAsStripped(t *testing.T) {
	merged := "" +
		"dns:\n  enable: true\n  nameserver: [8.8.8.8]\n" +
		"ss-config: \"aes-128-gcm:password@:8388\"\n" +
		"listeners:\n  - name: extra\n    type: mixed\n    port: 8080\n" +
		"tunnels:\n  - tcp/udp,127.0.0.1:6553,8.8.8.8:53,DIRECT\n" +
		"rules:\n  - MATCH,DIRECT\n"

	deviations, err := collectConfigDeviations(merged, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true))
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	// These five are honoured now, so they are not deviations at all. Leaving
	// them in the table as `stripped` told the reader a listener was closed
	// while the core opened it; a new category would have been dropped whole by
	// already-shipped clients, which decode Category as a strict enum. The
	// exposure is disclosed by the notice surface instead (below).
	for _, field := range []string{"listeners", "tunnels", "ss-config", "vmess-config", "tuic-server"} {
		for _, deviation := range deviations {
			if deviation.Field == field {
				t.Fatalf("%s is still in the deviation table as %q: %q — the core honours it, so any category here states something untrue",
					field, deviation.Category, deviation.Effective)
			}
		}
	}
	_ = deviationFor
}

// Honoured is not the same as silent: a listener the subscription opened, with
// no authentication, on every interface, is exactly what the reader needs told.
func TestConfiguredInboundListenersAreDisclosedAsExposure(t *testing.T) {
	raw := normalizeFixture(t, `
mode: rule
dns:
  enable: true
  nameserver: [8.8.8.8]
listeners:
  - name: extra
    type: mixed
    port: 8080
rules:
  - MATCH,DIRECT
`)
	notices := unauthenticatedLANListenerNotices(raw)
	joined := strings.Join(notices, "\n")
	if !strings.Contains(joined, "listeners") {
		t.Fatalf("a configured listener with no authentication produced no notice:\n%s", joined)
	}
}

// `authentication` present is not the same as authentication enforced:
// skip-auth-prefixes is a bypass list, and 0.0.0.0/0 in it means everyone.
func TestSkipAuthPrefixesDoNotSilenceTheExposureNotice(t *testing.T) {
	raw := normalizeFixture(t, `
mode: rule
allow-lan: true
mixed-port: 7890
authentication:
  - "user:pass"
skip-auth-prefixes:
  - 0.0.0.0/0
  - ::/0
dns:
  enable: true
  nameserver: [8.8.8.8]
rules:
  - MATCH,DIRECT
`)
	notices := unauthenticatedLANListenerNotices(raw)
	if len(notices) == 0 {
		t.Fatal("authentication that every source is allowed to skip is not authentication; the notice must still fire")
	}
}

// Real authentication with an ordinary skip list (loopback) stays quiet: the
// notice must not become noise that readers learn to ignore.
func TestGenuineAuthenticationStaysQuiet(t *testing.T) {
	raw := normalizeFixture(t, `
mode: rule
allow-lan: true
mixed-port: 7890
authentication:
  - "user:pass"
skip-auth-prefixes:
  - 127.0.0.1/32
dns:
  enable: true
  nameserver: [8.8.8.8]
rules:
  - MATCH,DIRECT
`)
	if notices := unauthenticatedLANListenerNotices(raw); len(notices) != 0 {
		t.Fatalf("a properly authenticated listener produced a warning: %v", notices)
	}
}
