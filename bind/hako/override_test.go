package hako

import (
	"net/netip"
	"testing"

	"github.com/TokenPLS/Hako/component/process"
	"github.com/TokenPLS/Hako/config"
	C "github.com/TokenPLS/Hako/constant"
	LC "github.com/TokenPLS/Hako/listener/config"
	"github.com/TokenPLS/Hako/log"
)

func TestOverrideForIOSForcesTunParams(t *testing.T) {
	setTunMTU(0)
	cfg := &config.Config{
		General: &config.General{
			GeoAutoUpdate: true,
			Inbound: config.Inbound{
				Tun: LC.Tun{
					Enable:                true,
					Stack:                 C.TunSystem, // honoured now: upstream allows it, the platform allows it
					MTU:                   1500,
					AutoRoute:             true,
					AutoDetectInterface:   true,
					GSO:                   true,
					GSOMaxSize:            65536,
					DisableICMPForwarding: false,
					FileDescriptor:        42, // injected fd must survive override
				},
			},
		},
		Controller: &config.Controller{
			ExternalController: "127.0.0.1:9090",
			ExternalUI:         "ui",
			ExternalUIURL:      "https://example.invalid/ui.zip",
			ExternalUIName:     "dashboard",
		},
	}

	overrideForIOS(cfg)

	tun := cfg.General.Tun
	// Stack is deliberately absent from this test now. It stopped being forced on 2026-08-10:
	// the platform half was closed by measurement long before, and the cost that kept it -- "a
	// swap invalidates the ProcessorsPerChannel=1 device A/B" -- was true of changing the
	// DEFAULT and false of honouring an explicit value, because constant/tun.go:15 already makes
	// gVisor the zero value. tun_stack_test.go pins both halves.
	if tun.Stack != C.TunSystem {
		t.Errorf("Stack = %v, want the System the configuration asked for", tun.Stack)
	}
	if tun.MTU != uint32(defaultTunMTU) {
		t.Errorf("MTU = %d, want %d", tun.MTU, defaultTunMTU)
	}
	if tun.AutoRoute || tun.AutoDetectInterface {
		t.Error("AutoRoute/AutoDetectInterface must be false (routing is NE-owned)")
	}
	if tun.GSO || tun.GSOMaxSize != 0 {
		t.Error("GSO must be off")
	}
	if tun.Device != packetFlowBridgeDevice {
		t.Errorf("Device = %q, want PacketFlow bridge marker %q", tun.Device, packetFlowBridgeDevice)
	}
	if tun.RecvMsgX || tun.SendMsgX {
		t.Errorf("utun-only msgx survived PacketFlow override: recv=%v send=%v", tun.RecvMsgX, tun.SendMsgX)
	}
	if !tun.DisableICMPForwarding {
		t.Error("DisableICMPForwarding must be true")
	}
	if tun.FileDescriptor != 42 {
		t.Errorf("override clobbered injected fd: %d", tun.FileDescriptor)
	}
	if cfg.General.GeoAutoUpdate {
		t.Error("GeoAutoUpdate must be disabled")
	}
	// ExternalController is no longer cleared, and that is not the same as honouring it:
	// executor.go:83 configures every part "without ExternalController" and nothing in this
	// build reaches route.ReCreateServer from configuration. Carrying it is inert; clearing it
	// was too, and clearing it made the ledger's word for these fields impossible to keep true.
	// The External UI fields are honoured now: the hold was, an architecture decision,
	// and the standard is that only a platform fact justifies holding a field back.
	if cfg.Controller.ExternalUI == "" {
		t.Error("external-ui was cleared; upstream keeps it and the platform permits it")
	}

	// the advertised DNS server (gateway+1) must be within the
	// hijack set after override.
	if !dnsHijackCovers(&cfg.General.Tun) {
		t.Errorf("advertised DNS not covered by DNSHijack %v", cfg.General.Tun.DNSHijack)
	}

	// find-process-mode forced off.
	if cfg.General.FindProcessMode != process.FindProcessOff {
		t.Errorf("FindProcessMode = %v, want off", cfg.General.FindProcessMode)
	}
}

func TestOverrideForNetworkExtensionKeepsOnlyTunInbound(t *testing.T) {
	tun := LC.Tun{Enable: true, FileDescriptor: 42}
	cfg := &config.Config{
		General: &config.General{Inbound: config.Inbound{
			Port:              7890,
			SocksPort:         7891,
			RedirPort:         7892,
			TProxyPort:        7893,
			MixedPort:         7894,
			ShadowSocksConfig: "server",
			VmessConfig:       "server",
			AllowLan:          true,
			BindAddress:       "*",
			Tun:               tun,
		}},
		Listeners: map[string]C.InboundListener{"custom": nil},
		Tunnels:   []LC.Tunnel{{Network: []string{"tcp"}}},
		IPTables:  &config.IPTables{Enable: true},
	}

	overrideForNetworkExtension(cfg)

	inbound := cfg.General.Inbound
	if inbound.Tun.FileDescriptor != 42 || !inbound.Tun.Enable {
		t.Fatalf("tun inbound was not preserved: %+v", inbound.Tun)
	}
	// The local proxy surface survives on purpose now: hub/executor's updateListeners reads
	// these fields, and zeroing them here was what made the batch that opened them a no-op.
	if inbound.Port == 0 || inbound.SocksPort == 0 || inbound.MixedPort == 0 {
		t.Fatalf("the local proxy ports were zeroed again: %+v", inbound)
	}
	if !inbound.AllowLan {
		t.Fatalf("allow-lan was zeroed at finalize; the app-level gate is the only thing that "+
			"should decide it, and it decides at the raw layer: %+v", inbound)
	}
	if inbound.BindAddress == "127.0.0.1" {
		t.Fatalf("bind-address was pinned to loopback; genAddr then makes allow-lan a no-op: %+v", inbound)
	}
	// What still goes: the surfaces no Apple platform can serve, or that are a different
	// product entirely.
	if inbound.RedirPort != 0 || inbound.TProxyPort != 0 {
		t.Fatalf("a platform-impossible port survived: %+v", inbound)
	}
	// The protocol server surface is honoured now: upstream allows it, the platform allows it,
	// and hub/executor wires ReCreateShadowSocks/Vmess/Tuic. The ledger note that used to
	// justify removing it said in so many words that the capability was proven and the removal
	// was a product decision -- which is not a reason under the standard.
	if inbound.ShadowSocksConfig == "" || inbound.VmessConfig == "" {
		t.Fatalf("a protocol server surface was stripped: %+v", inbound)
	}
	// Listeners and tunnels are honoured now; iptables is not, and that one is genuinely a
	// platform answer -- the whole block is consumed by Linux netfilter.
	if cfg.IPTables.Enable {
		t.Fatal("iptables must stay disabled: no Apple platform has netfilter")
	}
}

func TestDNSHijackCovers(t *testing.T) {
	base := []netip.Prefix{netip.MustParsePrefix("172.19.0.1/30")} // gateway+1 = .2
	cases := []struct {
		name   string
		hijack []string
		want   bool
	}{
		{"hijack-all covers", []string{"0.0.0.0:53"}, true},
		{"any covers", []string{"any:53"}, true},
		{"exact match covers", []string{"172.19.0.2:53"}, true},
		{"wrong address does not cover", []string{"10.0.0.2:53"}, false},
		{"empty does not cover", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tun := &LC.Tun{Inet4Address: base, DNSHijack: c.hijack}
			if got := dnsHijackCovers(tun); got != c.want {
				t.Fatalf("dnsHijackCovers = %v, want %v", got, c.want)
			}
		})
	}
}

func TestEnsureTunEnabled(t *testing.T) {
	// It enables tun and changes nothing else. Feeding it a bare LC.Tun is why
	// this test used to pass while a parsed configuration diverged: the addresses
	// it once filled in are decided by upstream's parseTun and parseIPV6, and
	// overwriting them here overrode the user's `ipv6: false`. Address parity is
	// covered against real parse output in tun_ipv6_parity_test.go.
	tun := &LC.Tun{Enable: false}
	ensureTunEnabled(tun)
	if !tun.Enable {
		t.Fatal("ensureTunEnabled must enable tun")
	}
	if len(tun.Inet4Address) != 0 || len(tun.Inet6Address) != 0 {
		t.Fatalf("ensureTunEnabled invented addresses: inet4=%v inet6=%v", tun.Inet4Address, tun.Inet6Address)
	}

	// Existing addresses are preserved.
	custom := &LC.Tun{Inet4Address: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/30")}}
	ensureTunEnabled(custom)
	if custom.Inet4Address[0].String() != "10.0.0.1/30" {
		t.Fatal("ensureTunEnabled must not clobber existing addresses")
	}
	if len(custom.Inet6Address) != 0 {
		t.Fatalf("ensureTunEnabled added a v6 address to a v4-only tun: %v", custom.Inet6Address)
	}
}

func TestOverrideForIOSLeavesTunAloneWhenDisabled(t *testing.T) {
	cfg := &config.Config{
		General: &config.General{
			Inbound: config.Inbound{
				Tun: LC.Tun{Enable: false, Stack: C.TunSystem, MTU: 1500},
			},
		},
	}
	overrideForIOS(cfg)
	// No-tun path: tun params are not rewritten.
	if cfg.General.Tun.Stack != C.TunSystem || cfg.General.Tun.MTU != 1500 {
		t.Error("disabled tun should not be rewritten")
	}
}

func TestOverrideForIOSPreservesConfiguredLogLevel(t *testing.T) {
	cfg := &config.Config{
		General:    &config.General{LogLevel: log.WARNING},
		Controller: &config.Controller{},
	}
	overrideForIOS(cfg)
	if cfg.General.LogLevel != log.WARNING {
		t.Fatalf("log level = %v, want configured warning", cfg.General.LogLevel)
	}
}
