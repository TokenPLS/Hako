package hako

import (
	"testing"

	"github.com/TokenPLS/Hako/component/auth"
	"github.com/TokenPLS/Hako/config"
)

// The parity test written when the local-proxy surface was opened stopped at parseBoth. Its
// failure message said "the listener the user asked for is not opened" -- a claim about the
// listener layer, from a measurement at the parse layer. Between those two layers,
// override.go:70 replaced the entire Inbound struct, so every one of those ten fields was
// zeroed again and no listener was ever opened. The gate was green and the port was closed.
//
// That is the same defect this batch diagnosed in the old override_test.go, which fed a bare
// LC.Tun{} and passed while real configurations diverged. Writing the tun tests against
// finalizeConfigForIOS and then not doing it here is what let it back in.
//
// So these run where the runtime runs: after finalize. A test that claims something about
// listeners has to measure the value updateListeners will actually read.
func TestLocalProxySurfaceSurvivesFinalizeNotJustParse(t *testing.T) {
	const document = `
port: 7890
socks-port: 7891
mixed-port: 7892
allow-lan: true
authentication:
  - "alice:correct-horse"
skip-auth-prefixes:
  - 127.0.0.1/32
lan-allowed-ips:
  - 192.168.0.0/16
inbound-tfo: true
inbound-mptcp: true
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	SetAllowLanPermitted(true)
	t.Cleanup(func() { SetAllowLanPermitted(false) })

	_, ours := parseBoth(t, document)
	finalizeConfigForIOS(ours, true)

	for name, got := range map[string]int{
		"port": ours.General.Port, "socks-port": ours.General.SocksPort, "mixed-port": ours.General.MixedPort,
	} {
		if got == 0 {
			t.Errorf("%s = 0 after finalize; hub/executor updateListeners reads this value, and "+
				"zero is what ReCreateMixed treats as 'no listener'", name)
		}
	}
	if !ours.General.AllowLan {
		t.Error("allow-lan = false after finalize, with the permission granted")
	}
	// authentication lands in cfg.Users, not General.Authentication -- upstream's
	// config.go:785 does `config.Users = parseAuthentication(rawCfg.Authentication)`. Asserting
	// on General.Authentication read as "the credentials were dropped" when they had never been
	// there on either side; checking against mihomo is what catches that.
	if len(ours.Users) != len(mihomoUsers(t, document)) || len(ours.Users) == 0 {
		t.Errorf("authentication users after finalize = %d, mihomo has %d; a LAN listener would "+
			"come up with no credentials", len(ours.Users), len(mihomoUsers(t, document)))
	}
	if len(ours.General.SkipAuthPrefixes) == 0 {
		t.Error("skip-auth-prefixes was emptied after finalize")
	}
	if len(ours.General.LanAllowedIPs) == 0 {
		t.Error("lan-allowed-ips was emptied after finalize")
	}
	if !ours.General.InboundTfo || !ours.General.InboundMPTCP {
		t.Errorf("inbound socket options were reset after finalize: tfo=%v mptcp=%v",
			ours.General.InboundTfo, ours.General.InboundMPTCP)
	}
}

// genAddr (listener/listener.go:709-718) only produces ":port" -- every interface -- when the
// bind address is "*" or empty. Forcing it to 127.0.0.1 makes allow-lan a no-op even when the
// port survives and the permission is granted: the listener comes up on loopback and the user
// is told, by their own configuration and by the app's switch, that it is shared.
func TestFinalizeDoesNotPinBindAddressToLoopback(t *testing.T) {
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
	finalizeConfigForIOS(ours, true)

	if ours.General.BindAddress == "127.0.0.1" && mihomo.General.BindAddress != "127.0.0.1" {
		t.Errorf("bind-address was pinned to 127.0.0.1 (upstream has %q); genAddr then binds "+
			"loopback and allow-lan does nothing", mihomo.General.BindAddress)
	}
}

// What still goes at finalize: the surfaces the raw layer already cleared, kept here as
// defence in depth rather than as a second policy.
func TestFinalizeStillClosesTheServerSurfaces(t *testing.T) {
	const document = `
mixed-port: 7890
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	_, ours := parseBoth(t, document)
	finalizeConfigForIOS(ours, true)

	if ours.General.RedirPort != 0 || ours.General.TProxyPort != 0 {
		t.Errorf("a platform-impossible port survived finalize: redir=%d tproxy=%d",
			ours.General.RedirPort, ours.General.TProxyPort)
	}
	if ours.General.ShadowSocksConfig != "" || ours.General.VmessConfig != "" {
		t.Error("a protocol server surface survived finalize")
	}
	if len(ours.Listeners) != 0 {
		t.Error("configured listeners survived finalize")
	}
}

func mihomoUsers(t *testing.T, document string) []auth.AuthUser {
	t.Helper()
	parsed, err := config.Parse([]byte(document))
	if err != nil {
		t.Fatalf("mihomo rejected the fixture: %v", err)
	}
	return parsed.Users
}
