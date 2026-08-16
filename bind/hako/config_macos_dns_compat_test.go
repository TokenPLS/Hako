package hako

import (
	"testing"

	"github.com/TokenPLS/Hako/dns"
)

func setMacOSDNSProfileForTest(t *testing.T, profile runtimeProfile) {
	t.Helper()
	restoreRuntimeProfileForTest(t)
	setupRuntimeProfile.Store(uint32(profile))
}

// A configuration with no dns block starts, and DNS is turned on for it -- the one field an
// Apple packet tunnel requires. The requirement is mechanical rather than stylistic:
// updateDNS tears the resolver down when enable is false
// (hub/executor/executor.go:238-247), ServeMsg then returns ErrIPNotFound and relayDnsPacket
// answers SERVFAIL, while the tunnel keeps capturing every port 53 packet because
// ShouldHijackDns (sing_tun/dns.go:21-27) never asks whether a resolver exists. A desktop
// user reaches that only by enabling tun and can step back out; a packet tunnel cannot.
//
// It is not refused either: refusing made this the only tunnel such a configuration would
// not start on. It starts, with DNS on and nothing else touched.
func TestPacketTunnelEnablesDNSAndChangesNothingElse(t *testing.T) {
	setMacOSDNSProfileForTest(t, runtimeProfileMacOSPacketTunnel)
	cfg, err := parseConfigForIOS("rules:\n  - MATCH,DIRECT\n", true)
	if err != nil {
		t.Fatalf("a configuration mihomo accepts must start here too: %v", err)
	}
	if cfg.DNS == nil || !cfg.DNS.Enable {
		t.Fatal("dns.enable must be on: the tunnel captures port 53 regardless, and with the " +
			"resolver down every hijacked query answers SERVFAIL")
	}
}

func TestMacOSPacketTunnelRepairsSystemOnlyDNS(t *testing.T) {
	setMacOSDNSProfileForTest(t, runtimeProfileMacOSPacketTunnel)
	config := `
dns:
  enable: true
  respect-rules: true
  nameserver: [system]
  proxy-server-nameserver: [system]
  default-nameserver: [system]
rules:
  - MATCH,DIRECT
`
	cfg, err := parseConfigForIOS(config, true)
	if err != nil {
		t.Fatalf("system-only upstream DNS must receive safe packet-tunnel fallbacks: %v", err)
	}
	for field, servers := range map[string][]dns.NameServer{
		"nameserver":              cfg.DNS.NameServer,
		"proxy-server-nameserver": cfg.DNS.ProxyServerNameserver,
		"default-nameserver":      cfg.DNS.DefaultNameserver,
	} {
		for _, server := range servers {
			if server.Net == "system" || server.Net == "dhcp" {
				t.Fatalf("%s retained incompatible resolver %+v", field, server)
			}
		}
	}
	if len(cfg.DNS.NameServer) == 0 || len(cfg.DNS.ProxyServerNameserver) == 0 || len(cfg.DNS.DefaultNameserver) == 0 {
		t.Fatalf("packet-tunnel DNS fallback is incomplete: %+v", cfg.DNS)
	}
}
