package hako

import (
	"strings"
	"testing"

	"github.com/TokenPLS/Hako/config"
)

// parseBoth runs mihomo's own parser and this fork's on the same document. Reading a diff tells
// us what changed; running both tells us what it does. was found the second way.
func parseBoth(t *testing.T, document string) (*config.Config, *config.Config) {
	t.Helper()
	mihomo, err := config.Parse([]byte(document))
	if err != nil {
		t.Fatalf("mihomo's own parser rejected the fixture: %v", err)
	}
	ours, err := parseConfigForIOS(document, true)
	if err != nil {
		t.Fatalf("this core rejected the fixture: %v", err)
	}
	return mihomo, ours
}

// A reader who never writes these keys must see no deviation: this fork forces them to the value
// DefaultRawConfig already uses (config/config.go:513,517 and NTP at :563). If this test ever
// fails, the force stopped agreeing with upstream's default and became observable to everyone.
func TestSilentReaderSeesNoDeviationOnGeoAndNTPDefaults(t *testing.T) {
	const silent = `
mixed-port: 7890
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	mihomo, ours := parseBoth(t, silent)

	if mihomo.General.GeoAutoUpdate != ours.General.GeoAutoUpdate {
		t.Errorf("geo-auto-update: mihomo %v, ours %v", mihomo.General.GeoAutoUpdate, ours.General.GeoAutoUpdate)
	}
	if mihomo.General.GeodataLoader != ours.General.GeodataLoader {
		t.Errorf("geodata-loader: mihomo %q, ours %q", mihomo.General.GeodataLoader, ours.General.GeodataLoader)
	}
	if mihomo.NTP.WriteToSystem != ours.NTP.WriteToSystem {
		t.Errorf("ntp.write-to-system: mihomo %v, ours %v", mihomo.NTP.WriteToSystem, ours.NTP.WriteToSystem)
	}
}

// The same three keys, written by a reader who explicitly asked for the other value. Whatever this
// prints is the finding: it is the exact deviation an opted-in reader gets, and B1's verdict for
// these three fields rests on it.
func TestOptedInReaderGetsTheOverride(t *testing.T) {
	const optedIn = `
mixed-port: 7890
geo-auto-update: true
geodata-loader: standard
ntp:
  enable: true
  server: time.apple.com
  write-to-system: true
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	mihomo, ours := parseBoth(t, optedIn)

	t.Logf("geo-auto-update      mihomo=%v ours=%v", mihomo.General.GeoAutoUpdate, ours.General.GeoAutoUpdate)
	t.Logf("geodata-loader       mihomo=%q ours=%q", mihomo.General.GeodataLoader, ours.General.GeodataLoader)
	t.Logf("ntp.write-to-system  mihomo=%v ours=%v", mihomo.NTP.WriteToSystem, ours.NTP.WriteToSystem)

	if mihomo.General.GeoAutoUpdate == ours.General.GeoAutoUpdate &&
		mihomo.General.GeodataLoader == ours.General.GeodataLoader &&
		mihomo.NTP.WriteToSystem == ours.NTP.WriteToSystem {
		t.Fatal("expected the documented override to be observable for an opted-in reader; " +
			"if this passes, config_pipeline.go:122,138,408 no longer force these and the " +
			"inventory's `force` disposition is stale")
	}
}

// find-process-mode is not forced everywhere. override.go:40 applies it only where the runtime
// profile cannot name the owner of a connection, so an iOS packet tunnel gets FindProcessOff and
// a macOS one keeps what the reader configured. Both branches are pinned: a conditional force
// with only one branch under test can be made unconditional later and nothing notices.
//
// Upstream's default is FindProcessStrict at e26714a18:config/config.go:498. That line number
// resolves against the pinned upstream only — this fork added 57 lines to config/config.go, so
// line 498 in the working tree is `func Parse`.
func TestFindProcessModeIsForcedOffOnlyWhereNoProcessPathExists(t *testing.T) {
	const silent = `
mixed-port: 7890
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	t.Run("iOS packet tunnel has no process path, so the force applies", func(t *testing.T) {
		restoreRuntimeProfileForTest(t)

		mihomo, ours := parseBoth(t, silent)
		t.Logf("find-process-mode  mihomo=%v ours=%v", mihomo.General.FindProcessMode, ours.General.FindProcessMode)

		if mihomo.General.FindProcessMode == ours.General.FindProcessMode {
			t.Fatal("expected find-process-mode to be forced Off under the iOS packet-tunnel " +
				"profile; if it no longer is, override.go:40 and the `force` disposition " +
				"disagree with the code")
		}
	})

	t.Run("macOS packet tunnel does the lookup itself, so the reader keeps their value", func(t *testing.T) {
		previous := setupRuntimeProfile.Load()
		setupRuntimeProfile.Store(uint32(runtimeProfileMacOSPacketTunnel))
		t.Cleanup(func() { setupRuntimeProfile.Store(previous) })

		mihomo, ours := parseBoth(t, silent)
		t.Logf("find-process-mode  mihomo=%v ours=%v", mihomo.General.FindProcessMode, ours.General.FindProcessMode)

		if mihomo.General.FindProcessMode != ours.General.FindProcessMode {
			t.Fatalf("macOS reads net.inet.{tcp,udp}.pcblist_n itself and the App Sandbox does "+
				"not deny it — measured, with a positive control — so this profile must keep "+
				"upstream's value: mihomo %v, ours %v",
				mihomo.General.FindProcessMode, ours.General.FindProcessMode)
		}
	})
}

// ruled dns.enable is a product-level requirement of the Apple packet tunnel: with it false
// DefaultService is nil, ServeMsg returns ErrIPNotFound, every hijacked query answers SERVFAIL,
// and ShouldHijackDns matches port 53 unconditionally so no configuration avoids the hijack. This
// test does not re-litigate the ruling. It checks the code still implements it, and that upstream
// still honours the value this fork overrides — a force is only a force while the two disagree.
func TestDNSEnableIsForcedOnAsD184Ruled(t *testing.T) {
	restoreRuntimeProfileForTest(t)

	const disabled = `
mixed-port: 7890
dns:
  enable: false
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	mihomo, ours := parseBoth(t, disabled)

	if mihomo.DNS.Enable {
		t.Fatal("upstream did not honour dns.enable: false, so there is no deviation to judge; " +
			"the fixture is wrong or upstream changed")
	}
	if !ours.DNS.Enable {
		t.Fatal("dns.enable is no longer forced on. An Apple packet tunnel requires it, " +
			"so either the code regressed or the ruling needs revisiting — not a test to fix")
	}
}

// default-nameserver is the one CORE-TASK-DNS-CONFIG-PARITY files as class C, "forced today,
// disposition unresolved". Nothing is asserted about which side is right: this records what a
// reader who wrote `system` actually gets, which is the input to that verdict and not the verdict.
func TestDefaultNameserverSubstitutionIsObservable(t *testing.T) {
	restoreRuntimeProfileForTest(t)

	const systemBootstrap = `
mixed-port: 7890
dns:
  enable: true
  default-nameserver:
    - system
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	mihomo, ours := parseBoth(t, systemBootstrap)
	t.Logf("default-nameserver  mihomo=%v", addressesOf(mihomo.DNS.DefaultNameserver))
	t.Logf("default-nameserver  ours=%v", addressesOf(ours.DNS.DefaultNameserver))
}

// The substitution above replaces a stripped bootstrap with a list — and the list matters as much
// as the stripping. These four are mihomo's own DefaultNameserver at
// e26714a18:config/config.go:516-521, so the repair hands the reader upstream's default rather
// than a set this fork chose. Pinned here because that is the difference between a
// platform-required repair and an invented one, and nothing else in the tree asserts it.
func TestStrippedBootstrapIsReplacedWithUpstreamsOwnDefault(t *testing.T) {
	restoreRuntimeProfileForTest(t)

	const systemBootstrap = `
mixed-port: 7890
dns:
  enable: true
  default-nameserver:
    - system
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	_, ours := parseBoth(t, systemBootstrap)

	upstreamDefault := config.DefaultRawConfig().DNS.DefaultNameserver
	if len(upstreamDefault) == 0 {
		t.Fatal("upstream stopped shipping a default bootstrap; the repair has nothing to inherit")
	}

	got := addressesOf(ours.DNS.DefaultNameserver)
	if len(got) != len(upstreamDefault) {
		t.Fatalf("substituted %d resolvers, upstream's default has %d: %v vs %v",
			len(got), len(upstreamDefault), got, upstreamDefault)
	}
	for i, want := range upstreamDefault {
		if !strings.Contains(got[i], want) {
			t.Errorf("bootstrap %d: substituted %q, upstream's default is %q — the repair is no "+
				"longer handing the reader mihomo's own list", i, got[i], want)
		}
	}
}

// This test used to record the strongest form of "not as written": mihomo accepted these keys
// and this fork refused the whole configuration. The refusal is gone, and this is now the
// regression guard for it -- because the reason it was there sounded convincing. It said the
// keys "decide WHICH traffic enters the tunnel, so silently dropping them would misroute".
//
// They do not. sing-tun reads the value only in redirect_linux.go and the two nftables files,
// always through autoRedirect, which is Linux-only; upstream's documentation says "Linux only,
// requires nftables". mihomo on darwin parses the field and ignores it. Refusing it was
// stricter than upstream and not required by the platform --'s definition of a defect --
// and the user-visible cost was that a configuration mihomo runs would not start here at all.
func TestRouteAddressSetLoadsExactlyAsUpstreamDoes(t *testing.T) {
	restoreRuntimeProfileForTest(t)

	const routeSet = `
mixed-port: 7890
tun:
  enable: true
  stack: system
  route-address-set:
    - cn
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	if _, err := config.Parse([]byte(routeSet)); err != nil {
		t.Fatalf("upstream rejected it too, so this fixture proves nothing: %v", err)
	}
	if _, err := parseConfigForIOS(routeSet, true); err != nil {
		t.Fatalf("this fork still refuses a configuration mihomo runs: %v", err)
	}
}

// The second refused key, on its own. validate.go:54 tests both in one condition today, so one
// case would cover both — which is exactly why this exists: split that condition, get one branch
// wrong, and a single-key test still passes.
func TestRouteExcludeAddressSetLoadsOnItsOwn(t *testing.T) {
	restoreRuntimeProfileForTest(t)

	const excludeSet = `
mixed-port: 7890
tun:
  enable: true
  stack: system
  route-exclude-address-set:
    - cn
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	if _, err := config.Parse([]byte(excludeSet)); err != nil {
		t.Fatalf("upstream rejected it too, so this is not a deviation: %v", err)
	}

	if _, err := parseConfigForIOS(excludeSet, true); err != nil {
		t.Fatalf("this fork still refuses a configuration mihomo runs: %v", err)
	}

}

// B2's thesis is that all 48 stripped fields are inbound/server surfaces, and an Apple packet
// tunnel has exactly one inbound — its own TUN. The thesis is cheap to state and worth attacking,
// because a field swept in by prefix rather than by meaning would take an outbound capability with
// it. config_pipeline.go:392 shows the surgical version already exists for one cluster:
// raw.TLS.CustomTrustCert is deliberately left alone while its five inbound siblings are cleared.
//
// These are the two clusters where an outbound sibling shares the vocabulary of a stripped
// inbound one: tuic-server.* against an outbound tuic proxy, and inbound-tfo/inbound-mptcp
// against the per-proxy tfo/mptcp options.
func TestStrippingInboundSurfacesLeavesOutboundAlone(t *testing.T) {
	restoreRuntimeProfileForTest(t)

	const withOutbounds = `
mixed-port: 7890
inbound-tfo: true
inbound-mptcp: true
tuic-server:
  enable: true
  listen: 127.0.0.1:10443
  token:
    - inbound-secret
proxies:
  - name: out-tuic
    type: tuic
    server: example.invalid
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
    password: outbound-secret
    tfo: true
    mptcp: true
  - name: out-ss
    type: ss
    server: example.invalid
    port: 8388
    cipher: aes-128-gcm
    password: outbound-secret
    tfo: true
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	mihomo, ours := parseBoth(t, withOutbounds)

	carriedTFO := false
	for _, name := range []string{"out-tuic", "out-ss"} {
		theirs, ok := mihomo.Proxies[name]
		if !ok {
			t.Fatalf("upstream did not build outbound %q; the fixture is wrong", name)
		}
		mine, ok := ours.Proxies[name]
		if !ok {
			t.Fatalf("this fork dropped outbound %q while stripping inbound surfaces — a strip "+
				"reached past the inbound face it was aimed at", name)
		}
		if theirs.Type() != mine.Type() {
			t.Errorf("outbound %q: upstream type %v, ours %v", name, theirs.Type(), mine.Type())
		}
		if theirs.Addr() != mine.Addr() {
			t.Errorf("outbound %q: upstream addr %q, ours %q", name, theirs.Addr(), mine.Addr())
		}

		// Type and address surviving proves the proxy was built; it does not prove its dial
		// options survived, and per-proxy tfo/mptcp are the exact options that share their
		// vocabulary with the stripped inbound-tfo/inbound-mptcp. Compare them directly.
		theirInfo, myInfo := theirs.ProxyInfo(), mine.ProxyInfo()

		if theirInfo.TFO {
			carriedTFO = true
		}
		if theirInfo.TFO != myInfo.TFO {
			t.Errorf("outbound %q tfo: upstream %v, ours %v — a global inbound strip reached a "+
				"per-proxy dial option", name, theirInfo.TFO, myInfo.TFO)
		}
		if theirInfo.MPTCP != myInfo.MPTCP {
			t.Errorf("outbound %q mptcp: upstream %v, ours %v — a global inbound strip reached a "+
				"per-proxy dial option", name, theirInfo.MPTCP, myInfo.MPTCP)
		}
	}

	// Positive control for the dial-option comparisons. Not every outbound type accepts tfo --
	// TuicOption carries no such field upstream, so tuic reads false on both sides and comparing
	// it proves nothing. The invariant is still "whatever upstream does, we do", so the equality
	// checks stay for every proxy; this asserts the fixture made at least one of them mean
	// something. Without it the whole group could pass on false == false.
	if !carriedTFO {
		t.Fatal("no proxy in the fixture carried tfo upstream, so every tfo comparison above was " +
			"false == false — fix the fixture, not the assertions")
	}

	// The inbound half now matches upstream too. It used to be asserted gone, on the ground
	// that a Network Extension could not listen -- a claim this core's own proxy_share.go
	// disproved in the same process, and one the market settles: Shadowrocket ships a local
	// proxy service from a sandboxed packet tunnel on the Mac App Store. These two fields
	// configure the listener the user asked for, so they follow it.
	if ours.General.InboundTfo != mihomo.General.InboundTfo {
		t.Errorf("inbound-tfo: mihomo %v, ours %v", mihomo.General.InboundTfo, ours.General.InboundTfo)
	}
	if ours.General.InboundMPTCP != mihomo.General.InboundMPTCP {
		t.Errorf("inbound-mptcp: mihomo %v, ours %v", mihomo.General.InboundMPTCP, ours.General.InboundMPTCP)
	}
}

// B3 covers the fields the ledger files as `apple` (the Apple layer takes over) and `split` (the
// client writes it, the kernel consumes it). Two of them read like they were filed under the wrong
// disposition, and a misfiled deviation is invisible to every review that trusts the filing.
//
// store-fake-ip is filed `split`, but its note says the value is defaulted on when the reader omits
// it — that changes what a silent reader gets, which is the shape of a `force`, not of a layering.
func TestStoreFakeIPDefaultForASilentReader(t *testing.T) {
	restoreRuntimeProfileForTest(t)

	const silent = `
mixed-port: 7890
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	mihomo, ours := parseBoth(t, silent)
	t.Logf("profile.store-fake-ip  mihomo=%v ours=%v", mihomo.Profile.StoreFakeIP, ours.Profile.StoreFakeIP)

	if mihomo.Profile.StoreFakeIP == ours.Profile.StoreFakeIP {
		t.Fatal("the note on store-fake-ip says an omitted value is defaulted on for Apple; if " +
			"that is no longer true the ledger row is stale, and if it is true this is a force " +
			"filed as a split")
	}
}

// The same field written explicitly. The note claims an explicit true/false is preserved verbatim,
// which is the difference between defaulting and overriding — and the difference decides whether
// the reader's file ran as written.
func TestStoreFakeIPIsPreservedWhenTheReaderIsExplicit(t *testing.T) {
	restoreRuntimeProfileForTest(t)

	for _, want := range []bool{true, false} {
		document := `
mixed-port: 7890
profile:
  store-fake-ip: ` + map[bool]string{true: "true", false: "false"}[want] + `
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
		mihomo, ours := parseBoth(t, document)
		if mihomo.Profile.StoreFakeIP != want {
			t.Fatalf("upstream did not take store-fake-ip: %v, so the fixture proves nothing", want)
		}
		if ours.Profile.StoreFakeIP != want {
			t.Errorf("store-fake-ip: reader wrote %v, this core produced %v — an explicit value "+
				"was overridden, which the ledger row says does not happen", want, ours.Profile.StoreFakeIP)
		}
	}
}

// tun.* is filed `apple` — the Apple layer owns the device — but the same note says stack, mtu,
// dns-hijack, icmp, gso and auto-route are pinned to iOS-safe values. Pinning a reader's value is
// an override whoever owns the device, so this records what a reader who set them actually gets.
func TestTunKnobsAReaderSetsAreReplaced(t *testing.T) {
	restoreRuntimeProfileForTest(t)

	const tunSet = `
mixed-port: 7890
tun:
  enable: true
  stack: gvisor
  mtu: 9000
  auto-route: false
  dns-hijack:
    - 1.1.1.1:53
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	mihomo, ours := parseBoth(t, tunSet)

	t.Logf("tun.stack       mihomo=%v ours=%v", mihomo.General.Tun.Stack, ours.General.Tun.Stack)
	t.Logf("tun.mtu         mihomo=%v ours=%v", mihomo.General.Tun.MTU, ours.General.Tun.MTU)
	t.Logf("tun.auto-route  mihomo=%v ours=%v", mihomo.General.Tun.AutoRoute, ours.General.Tun.AutoRoute)
	t.Logf("tun.dns-hijack  mihomo=%v ours=%v", mihomo.General.Tun.DNSHijack, ours.General.Tun.DNSHijack)
}

// B4's 16 `na` fields are the ones nobody looks at, which is reason enough to look. Fifteen are
// Android or Linux surfaces; the interesting question is not whether iOS can honour them — it
// cannot — but what a reader who writes one actually gets. `na` says "not applicable"; it does not
// say "stripped", and a field that is neither honoured nor removed is a third thing.
func TestLinuxOnlyKnobsSurviveIntoTheConfigUnchanged(t *testing.T) {
	restoreRuntimeProfileForTest(t)

	const linuxKnobs = `
mixed-port: 7890
iptables:
  enable: true
  inbound-interface: eth0
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	mihomo, ours := parseBoth(t, linuxKnobs)

	t.Logf("iptables.enable            mihomo=%v ours=%v", mihomo.IPTables.Enable, ours.IPTables.Enable)
	t.Logf("iptables.inbound-interface mihomo=%q ours=%q", mihomo.IPTables.InboundInterface, ours.IPTables.InboundInterface)

	// Whichever way this goes it is a result. Equal means the knob is carried into a core that
	// will never act on it; unequal means something strips it and the ledger says `na` where it
	// should say `strip`.
	if mihomo.IPTables.Enable != ours.IPTables.Enable {
		t.Logf("FINDING: iptables.enable is not carried through — `na` describes the wrong mechanism")
	}
}

// geo-update-interval is the one `na` field that is not platform-specific. Its note says it is
// inert once auto-update is off — but auto-update is off because this fork forces it off (B1,
// config_pipeline.go:138). So its inertness is derived from a deviation this fork chose, not from
// anything the platform imposes, and `na` records the wrong reason.
func TestGeoUpdateIntervalIsInertOnlyBecauseWeForcedAutoUpdateOff(t *testing.T) {
	restoreRuntimeProfileForTest(t)

	const withInterval = `
mixed-port: 7890
geo-auto-update: true
geo-update-interval: 6
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	mihomo, ours := parseBoth(t, withInterval)

	t.Logf("geo-update-interval  mihomo=%v ours=%v", mihomo.General.GeoUpdateInterval, ours.General.GeoUpdateInterval)
	t.Logf("geo-auto-update      mihomo=%v ours=%v", mihomo.General.GeoAutoUpdate, ours.General.GeoAutoUpdate)

	if ours.General.GeoAutoUpdate {
		t.Fatal("this fork stopped forcing geo-auto-update off, which is the only reason " +
			"geo-update-interval is filed `na` — the row now describes nothing")
	}
}
