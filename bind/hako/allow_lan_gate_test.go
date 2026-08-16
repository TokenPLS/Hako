package hako

import (
	"strings"
	"testing"
)

// allow-lan is the one field in the local-proxy group that changes who can reach the device.
// genAddr (listener/listener.go:709-718) binds ":port" -- every interface -- when it is true,
// and 127.0.0.1 when it is not. The other ten fields configure a listener; this one decides
// whether the listener is on the network the device happens to have joined.
//
// Honouring it straight from an imported subscription would have changed the security posture
// of already-shipped users without anybody pressing anything: same config, same device, new
// kernel, open proxy.
//
// The precedent does not cover that. Two shipped apps establish that Apple does not object to
// the capability itself:
//
//   - Shadowrocket's Mac App Store packet tunnel declares
//     NSLocalNetworkUsageDescription = "Use local networking to provice local proxy service."
//     (sic), imports _listen/_bind/_accept/_socket, and carries app-sandbox with
//     network.server. Re-verified on this machine; the commands are in
//     CORE-FIDELITY-FINDINGS-AND-ROADMAP.md.
//   - Stash's own wiki: "Stash iOS, Stash tvOS, and Stash Mac all support providing proxy for
//     local area network devices", HTTP and SOCKS on port 7890.
//
// Both reach users the way ours must: behind a switch somebody turns on -- Stash calls it
// "Allow LAN connections". The precedent is for the capability, never for opening it unasked.
//
// So the kernel honours it only when the containing app says so, and the ruling put one hard
// constraint on the shape: the safe state must not depend on the app remembering to ask for
// it. Go's zero value carries that -- a build that never calls the setter never exposes.
func TestAllowLanIsNotHonouredUntilTheAppPermitsIt(t *testing.T) {
	const document = `
mixed-port: 7890
allow-lan: true
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	// No setter call anywhere in this test: this is the state a client that does nothing gets.
	t.Cleanup(func() { SetAllowLanPermitted(false) })

	_, ours := parseBoth(t, document)
	if ours.General.AllowLan {
		t.Error("allow-lan was honoured without the app permitting it; a shipped user's " +
			"subscription would open a proxy on every network the device joins, with nobody " +
			"having pressed anything")
	}
	if ours.General.MixedPort != 7890 {
		t.Errorf("mixed-port = %d, want 7890 -- only the LAN exposure is gated, not the listener",
			ours.General.MixedPort)
	}
}

func TestAllowLanIsHonouredOnceTheAppPermitsIt(t *testing.T) {
	const document = `
mixed-port: 7890
allow-lan: true
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	SetAllowLanPermitted(true)
	t.Cleanup(func() { SetAllowLanPermitted(false) })

	mihomo, ours := parseBoth(t, document)
	if ours.General.AllowLan != mihomo.General.AllowLan {
		t.Errorf("allow-lan: mihomo %v, ours %v -- once permitted this is upstream's field again",
			mihomo.General.AllowLan, ours.General.AllowLan)
	}
}

// Revoking has to take effect. An app-level switch that only ever turns on would leave a user
// who changed their mind exposed until the next process launch.
func TestRevokingThePermissionTakesEffectOnTheNextParse(t *testing.T) {
	const document = `
mixed-port: 7890
allow-lan: true
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	SetAllowLanPermitted(true)
	t.Cleanup(func() { SetAllowLanPermitted(false) })
	if _, ours := parseBoth(t, document); !ours.General.AllowLan {
		t.Fatal("fixture is wrong: permitted parse did not honour allow-lan")
	}

	SetAllowLanPermitted(false)
	if _, ours := parseBoth(t, document); ours.General.AllowLan {
		t.Error("allow-lan survived the permission being revoked; a reload is the moment this " +
			"has to be re-read, not the next process launch")
	}
}

// Gating it silently would be the same failure this batch exists to end, one layer over.
func TestGatingAllowLanIsReportedWithSomewhereToGo(t *testing.T) {
	const document = `
mixed-port: 7890
allow-lan: true
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	t.Cleanup(func() { SetAllowLanPermitted(false) })

	deviations, err := collectConfigDeviations(document, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true))
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	for _, deviation := range deviations {
		if deviation.Field != "allow-lan" {
			continue
		}
		if deviation.Alternative == "" {
			t.Error("the gate offers no alternative; a reader who wanted a LAN proxy is told no " +
				"and not told where yes lives")
		}
		if !strings.Contains(deviation.Source, "listener.go") {
			t.Errorf("source = %q, want the line that shows what allow-lan actually binds", deviation.Source)
		}
		// And once permitted it is not a deviation at all.
		SetAllowLanPermitted(true)
		after, _ := collectConfigDeviations(document, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true))
		for _, d := range after {
			if d.Field == "allow-lan" {
				t.Error("allow-lan is still reported as a deviation after the app permitted it")
			}
		}
		return
	}
	t.Error("allow-lan was gated and nothing was reported")
}

// The permission is a ceiling, not a request. Two different people say yes in two different
// places before anything is exposed: the person holding the device grants the permission in
// the app, and the configuration asks for it with allow-lan. Exposure is the conjunction.
//
// This pins the half that is easiest to lose later, because losing it looks like a
// simplification: "the user turned local-network sharing on, so turn allow-lan on". That would
// make an app-level switch reach into every configuration the user ever imports, including the
// ones whose authors never asked for it.
func TestPermissionAloneExposesNothingWithoutTheConfigurationAsking(t *testing.T) {
	const silentAboutLan = `
mixed-port: 7890
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	SetAllowLanPermitted(true)
	t.Cleanup(func() { SetAllowLanPermitted(false) })

	mihomo, ours := parseBoth(t, silentAboutLan)
	if ours.General.AllowLan {
		t.Error("the permission turned allow-lan on for a configuration that never asked for it; " +
			"the app-level switch is a ceiling, and a ceiling does not raise the floor")
	}
	if ours.General.AllowLan != mihomo.General.AllowLan {
		t.Errorf("allow-lan: mihomo %v, ours %v -- a configuration silent about allow-lan should "+
			"read the same on both", mihomo.General.AllowLan, ours.General.AllowLan)
	}
	if ours.General.MixedPort != 7890 {
		t.Errorf("mixed-port = %d, want 7890 -- the listener the user asked for still opens, on "+
			"127.0.0.1", ours.General.MixedPort)
	}
}
