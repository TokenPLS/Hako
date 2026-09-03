package hako

import (
	"testing"
)

// `ipv6: false` is a user saying "do not carry IPv6". Upstream honours it in
// one place, config/config.go parseIPV6: with IPv6 off -- or with it on but no
// global-unicast v6 address on the host, verifyIP6() -- it clears
// Tun.Inet6Address outright.
//
// This core then refilled it from a hardcoded default, and the Swift side turns
// a non-empty v6 address into NEIPv6Settings plus a ::/0 default route. So a
// configuration that asks for no IPv6 hands the entire v6 default route to a
// tunnel whose core is running with DisableIPv6 -- it will not resolve AAAA and
// will not proxy v6. Traffic goes into a hole neither half admits to owning.
//
// The fixture goes through the real Start-time path, finalizeConfigForIOS, not
// a bare LC.Tun: the refill only ever ran there, which is why the older
// override_test.go could pass while a parsed configuration diverged.
//
// A subtlety that costs a day if you meet it as "the network is slow": the
// verifyIP6() half of that condition is satisfied by a ULA. Go reports fc00::/7
// as global unicast -- IsGlobalUnicast() only excludes unspecified, loopback,
// multicast and link-local -- so a router that advertises a v6 default route
// with no real uplink leaves the host holding an fd00: address, verifyIP6()
// returns true, Tun.Inet6Address survives, the Swift side installs
// NEIPv6Settings plus ::/0, and every dual-stack site pays a connect timeout
// before falling back to v4. Measured 2026-08-10 on macOS: 1144 v6 i/o timeouts
// in a day and speedtest.net stuck on "Finding provider", while the tunnel
// itself carried 462 Mbps once v6 was out of the way.
//
// Upstream behaves identically on the same host -- same verifyIP6, same ULA,
// same advertised default route -- so this is deliberately NOT tightened (user
// ruling 2026-08-10: do not be stricter than upstream).
//
// The user-side fix is the GLOBAL `ipv6: false`. The one under `dns:` governs
// AAAA answers only and never reaches config/config.go:1722, the single caller
// that clears Tun.Inet6Address -- a user who changes only the dns one sees no
// change at all. SKIP_SYSTEM_IPV6_CHECK is not an escape hatch here either: it
// can only force verifyIP6() to true, never to false.
func TestIPv6DisabledLeavesNoTunV6AddressForTheTunnelToClaim(t *testing.T) {
	const document = `
ipv6: false
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	mihomo, ours := parseBoth(t, document)

	if len(mihomo.General.Tun.Inet6Address) != 0 {
		t.Fatalf("fixture is wrong, not the code: mihomo kept %v with ipv6 false", mihomo.General.Tun.Inet6Address)
	}

	finalizeConfigForIOS(ours, true)

	if len(ours.General.Tun.Inet6Address) != 0 {
		t.Errorf("tun.inet6-address = %v with ipv6 false; mihomo clears it, and a non-empty value "+
			"makes the extension install a ::/0 default route the core will not serve",
			ours.General.Tun.Inet6Address)
	}
}

// The v4 refill was dead code, and proving it matters: deleting a branch is only
// safe if the value it guarded is already there. Upstream's parseTun always sets
// Inet4Address from dns.fake-ip-range, falling back to 198.18.0.1/16, so a parsed
// configuration never reaches the tunnel without one.
func TestParsedConfigAlwaysCarriesATunV4AddressWithoutOurRefill(t *testing.T) {
	for name, document := range map[string]string{
		"no dns block": `
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`,
		"custom fake-ip-range": `
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.19.0.1/16
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`,
	} {
		t.Run(name, func(t *testing.T) {
			mihomo, ours := parseBoth(t, document)
			if len(mihomo.General.Tun.Inet4Address) == 0 {
				t.Fatal("upstream left tun.inet4-address empty; the refill would not be dead code after all")
			}
			finalizeConfigForIOS(ours, true)
			if len(ours.General.Tun.Inet4Address) == 0 {
				t.Fatal("tun.inet4-address is empty after finalize")
			}
			if ours.General.Tun.Inet4Address[0] != mihomo.General.Tun.Inet4Address[0] {
				t.Errorf("tun.inet4-address: mihomo %v, ours %v", mihomo.General.Tun.Inet4Address[0], ours.General.Tun.Inet4Address[0])
			}
		})
	}
}

// With ipv6 on, whatever upstream decided must survive verbatim -- including
// upstream's own host check. A guard that only tested cfg.General.IPv6 would
// pass this test and still refill on a host with no v6 address, because
// upstream's condition is two terms, not one.
func TestIPv6EnabledKeepsExactlyWhatUpstreamDecided(t *testing.T) {
	const document = `
ipv6: true
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	mihomo, ours := parseBoth(t, document)
	finalizeConfigForIOS(ours, true)

	if len(ours.General.Tun.Inet6Address) != len(mihomo.General.Tun.Inet6Address) {
		t.Errorf("tun.inet6-address: mihomo %v, ours %v -- with ipv6 true the decision is still upstream's, "+
			"and it also requires verifyIP6() to find a global-unicast v6 address on this host",
			mihomo.General.Tun.Inet6Address, ours.General.Tun.Inet6Address)
	}
}
