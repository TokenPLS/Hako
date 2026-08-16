package hako

import (
	"testing"

	C "github.com/TokenPLS/Hako/constant"
)

// tun.stack was forced to gVisor unconditionally, and the record called that Apple's doing. It
// was not: overrideTunForIOS itself carries the measurement that closed the capability question
// -- the System stack's whole startup path runs under this extension's entitlements, verified
// with a positive control proving the sandbox was engaged.
//
// What kept it forced afterwards was a cost that turned out not to exist. The reasoning on
// record, mine, was "swapping the stack invalidates the device A/B that fixed
// ProcessorsPerChannel=1, so it needs re-establishing on hardware". That is true of CHANGING THE
// DEFAULT and false of HONOURING AN EXPLICIT VALUE, and the difference is one line of upstream:
//
//	constant/tun.go:15   TunGvisor TUNStack = iota
//
// gVisor is the zero value. A configuration that says nothing about tun.stack parses to gVisor
// on its own, so removing the override changes nothing for everyone who never asked. Only
// someone who writes `stack: system` lands anywhere new, which is the choice the rule exists to
// protect. The working point itself is untouched either way: ProcessorsPerChannel lives in
// third_party/sing-tun/tun_darwin_gvisor.go, on the gVisor path only.
//
// The consuming lane found the zero value; I had written the cost down without checking it.
//
// WHAT THIS TEST DOES NOT SHOW (2026-08-10 correction). It pins that an explicit value survives
// parsing. It says nothing about whether the resulting stack carries traffic, and the device
// evidence that was cited for that -- "all three values passed on a real iPhone" -- was measured
// with `curl -x 7890`, which goes through the extension's local proxy listener and never enters
// the tun at all. Three identical 200s because all three configurations take the same path.
//
// macOS then measured System and Mixed with a real data plane and found them dead: zero TCP
// sessions, UDP sessions forming but nothing returning. So whether the System stack has ever
// worked over an Apple packet tunnel is currently unknown in both directions.
//
// The field stays open regardless, and that is not a hedge: the evidence does not show the
// platform cannot do it, only that nobody has shown it can. Closing it now would seal a possible
// wiring bug as a platform limit, which is the specific move this whole batch was opened to
// undo.
func TestSilentConfigurationStillGetsGvisor(t *testing.T) {
	const document = `
tun:
  enable: true
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	mihomo, ours := parseBoth(t, document)
	if mihomo.General.Tun.Stack != C.TunGvisor {
		t.Fatalf("fixture is wrong, not the code: upstream parsed a silent tun.stack as %v, so "+
			"gVisor is not the zero value and removing the override WOULD change the default",
			mihomo.General.Tun.Stack)
	}

	finalizeConfigForIOS(ours, true)

	if ours.General.Tun.Stack != C.TunGvisor {
		t.Errorf("a configuration that never mentioned tun.stack got %v; the default has to stay "+
			"exactly where the device A/B left it", ours.General.Tun.Stack)
	}
}

func TestAnExplicitStackIsHonoured(t *testing.T) {
	for name, stack := range map[string]C.TUNStack{
		"system": C.TunSystem,
		"mixed":  C.TunMixed,
		"gvisor": C.TunGvisor,
	} {
		t.Run(name, func(t *testing.T) {
			document := `
tun:
  enable: true
  stack: ` + name + `
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
			mihomo, ours := parseBoth(t, document)
			if mihomo.General.Tun.Stack != stack {
				t.Fatalf("fixture is wrong: upstream parsed %q as %v", name, mihomo.General.Tun.Stack)
			}

			finalizeConfigForIOS(ours, true)

			if ours.General.Tun.Stack != mihomo.General.Tun.Stack {
				t.Errorf("tun.stack: mihomo %v, ours %v -- the capability was measured under this "+
					"extension's own entitlements and nothing in it is denied, so there is no "+
					"platform fact left to override the user with",
					mihomo.General.Tun.Stack, ours.General.Tun.Stack)
			}
		})
	}
}

// The deviation report has to stop claiming this one, or the silence we just fixed comes back as
// noise: a reader who writes `stack: system` and now RUNS system would be told the core forced
// gVisor. A report that says a thing that is not happening teaches people to skip the report.
func TestTunStackNoLongerAppearsInTheDeviationReport(t *testing.T) {
	const document = `
tun:
  enable: true
  stack: system
  mtu: 1400
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	deviations, err := collectConfigDeviations(document, currentRuntimePolicy(true))
	if err != nil {
		t.Fatalf("collect deviations: %v", err)
	}
	for _, deviation := range deviations {
		if deviation.Field == "tun.stack" {
			t.Errorf("tun.stack is still reported as %q -- it is honoured now, so the entry is a "+
				"false statement rendered verbatim to a user", deviation.Effective)
		}
	}

	// Positive control: the walk really did look at this configuration. Without it, a report
	// that silently collected nothing would pass this test by returning an empty list.
	sawTunMTU := false
	for _, deviation := range deviations {
		if deviation.Field == "tun.mtu" {
			sawTunMTU = true
		}
	}
	if !sawTunMTU {
		t.Fatal("the deviation walk reported nothing for tun.mtu either, so this test proved " +
			"nothing about tun.stack -- it measured an empty list")
	}
}
