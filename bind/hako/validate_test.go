package hako

import (
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/config"
	C "github.com/TokenPLS/Hako/constant"
	"github.com/TokenPLS/Hako/dns"
	LC "github.com/TokenPLS/Hako/listener/config"
)

func TestValidateForIOS(t *testing.T) {
	t.Run("carries dhcp and system rather than refusing them", func(t *testing.T) {
		// These used to be refused in every slot. Upstream refuses neither: it
		// carries both as transports and reports failure per query
		// (component/dhcp/dhcp.go:15 returns ErrNotResponding from the resolver),
		// and sing-box ships DHCP in its Apple build and still only logs
		// (dns/transport/dhcp/dhcp.go:95-113). The packet-tunnel path strips them
		// with a warning before validation runs (the call at config_pipeline.go:159); the
		// validator's job is not to make the leftovers fatal.
		cfg := &config.Config{DNS: &config.DNS{
			Enable:     true,
			NameServer: []dns.NameServer{{Addr: "1.1.1.1:53"}, {Net: "dhcp", Addr: "en0"}, {Net: "system"}},
		}}
		if err := validateForIOS(cfg, false); err != nil {
			t.Fatalf("dhcp/system nameserver refused the config: %v", err)
		}
	})

	t.Run("rejects empty nameserver when DNS enabled", func(t *testing.T) {
		cfg := &config.Config{DNS: &config.DNS{Enable: true}}
		err := validateForIOS(cfg, false)
		if err == nil || !strings.Contains(err.Error(), "nameserver must be set") {
			t.Fatalf("expected empty-nameserver rejection, got %v", err)
		}
	})

	t.Run("accepts explicit nameserver", func(t *testing.T) {
		cfg := &config.Config{DNS: &config.DNS{
			Enable:     true,
			NameServer: []dns.NameServer{{Net: "", Addr: "8.8.8.8:53"}},
		}}
		if err := validateForIOS(cfg, false); err != nil {
			t.Fatalf("valid config rejected: %v", err)
		}
	})

	t.Run("tolerates DNS fragment naming an unroutable proxy (fails closed at runtime)", func(t *testing.T) {
		// Rewriting/rejecting could silently reroute or block a startable
		// config; the resolver simply fails closed unless the name appears.
		cfg := &config.Config{DNS: &config.DNS{
			Enable:     true,
			NameServer: []dns.NameServer{{Addr: "1.1.1.1:53", ProxyName: "en0"}},
		}}
		if err := validateForIOS(cfg, true); err != nil {
			t.Fatalf("unroutable DNS fragment should be tolerated: %v", err)
		}
	})

	t.Run("allows DNS physical interface fragment outside NetworkExtension", func(t *testing.T) {
		cfg := &config.Config{DNS: &config.DNS{
			Enable:     true,
			NameServer: []dns.NameServer{{Addr: "1.1.1.1:53", ProxyName: "en0"}},
		}}
		if err := validateForIOS(cfg, false); err != nil {
			t.Fatalf("non-NE DNS interface fragment rejected: %v", err)
		}
	})

	t.Run("accepts DNS fragment naming a configured proxy or RULES", func(t *testing.T) {
		for _, proxyName := range []string{"DNS-PROXY", dns.RespectRules} {
			cfg := &config.Config{
				DNS: &config.DNS{
					Enable:     true,
					NameServer: []dns.NameServer{{Addr: "1.1.1.1:53", ProxyName: proxyName}},
				},
				Proxies: map[string]C.Proxy{"DNS-PROXY": nil},
			}
			if err := validateForIOS(cfg, true); err != nil {
				t.Fatalf("DNS proxy fragment %q rejected: %v", proxyName, err)
			}
		}
	})

	t.Run("no resolver slot makes dhcp or system fatal", func(t *testing.T) {
		// The mirror of the subtest above, held across every slot the walk used
		// to cover, so the overreach cannot come back one field at a time.
		for _, scheme := range []dns.NameServer{{Net: "dhcp", Addr: "en0"}, {Net: "system"}} {
			setters := map[string]func(*config.DNS){
				"nameserver":              func(c *config.DNS) { c.NameServer = append(c.NameServer, scheme) },
				"fallback":                func(c *config.DNS) { c.Fallback = []dns.NameServer{scheme} },
				"default-nameserver":      func(c *config.DNS) { c.DefaultNameserver = []dns.NameServer{scheme} },
				"proxy-server-nameserver": func(c *config.DNS) { c.ProxyServerNameserver = []dns.NameServer{scheme} },
				"direct-nameserver":       func(c *config.DNS) { c.DirectNameServer = []dns.NameServer{scheme} },
				"nameserver-policy": func(c *config.DNS) {
					c.NameServerPolicy = []dns.Policy{{Domain: "example.com", NameServers: []dns.NameServer{scheme}}}
				},
				"proxy-server-nameserver-policy": func(c *config.DNS) {
					c.ProxyServerPolicy = []dns.Policy{{Domain: "example.com", NameServers: []dns.NameServer{scheme}}}
				},
			}
			for name, set := range setters {
				t.Run(scheme.Net+"/"+name, func(t *testing.T) {
					cfg := &config.Config{DNS: &config.DNS{
						Enable:     true,
						NameServer: []dns.NameServer{{Addr: "1.1.1.1:53"}},
					}}
					set(cfg.DNS)
					if err := validateForIOS(cfg, true); err != nil {
						t.Fatalf("%s resolver in %s refused the config: %v", scheme.Net, name, err)
					}
				})
			}
		}
	})

	t.Run("DNS disabled skips validation", func(t *testing.T) {
		cfg := &config.Config{DNS: &config.DNS{Enable: false}}
		if err := validateForIOS(cfg, false); err != nil {
			t.Fatalf("disabled DNS should pass: %v", err)
		}
	})

	t.Run("DNS disabled is accepted, as mihomo accepts it", func(t *testing.T) {
		cfg := &config.Config{DNS: &config.DNS{Enable: false}}
		if err := validateForIOS(cfg, true); err != nil {
			t.Fatalf("mihomo accepts dns.enable false and so must this core: %v", err)
		}
	})

	// An nftables bypass set that upstream ignores off Linux is not grounds to refuse a
	// whole profile. See TestRouteAddressSetLoadsExactlyAsUpstreamDoes for the evidence.
	t.Run("route address sets load, because upstream ignores them off Linux", func(t *testing.T) {
		cfg := &config.Config{
			General: &config.General{Inbound: config.Inbound{Tun: LC.Tun{
				RouteAddressSet: []string{"private"},
			}}},
			DNS: &config.DNS{Enable: false},
		}
		if err := validateForIOS(cfg, false); err != nil {
			t.Fatalf("route set must not refuse the configuration: %v", err)
		}
	})
}

func TestValidateRawNetworkExtensionIntentToleratesUnexecutableMetadataRules(t *testing.T) {
	// iOS NE cannot execute PROCESS/UID/IN-USER rules (the sandbox exposes no
	// process metadata), but overrideForIOS forces FindProcessMode Off so they
	// safely no-op — they match nothing and the connection falls through to the
	// next rule. Preflight must therefore TOLERATE them rather than reject the
	// whole config, so any real mihomo subscription (which routinely carries a
	// PROCESS-NAME rule for the client's own binary) starts on iOS unchanged.
	tests := map[string]string{
		"process name":     "rules:\n  - PROCESS-NAME,curl,DIRECT\n",
		"process wildcard": "rules:\n  - PROCESS-PATH-WILDCARD,/private/*,DIRECT\n",
		"uid":              "rules:\n  - UID,501,DIRECT\n",
		"in user":          "rules:\n  - IN-USER,alice,DIRECT\n",
		"signing id":       "rules:\n  - SOURCE-APP-SIGNING-ID,com.example.cli,DIRECT\n",
		"Team id":          "rules:\n  - SOURCE-APP-TEAM-ID,ABCDE12345,DIRECT\n",
		"logic nested":     "rules:\n  - AND,((PROCESS-NAME-REGEX,^curl$),(NETWORK,TCP)),DIRECT\n",
		"sub-rule":         "sub-rules:\n  child:\n    - PROCESS-NAME-WILDCARD,curl*,DIRECT\n",
	}
	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			raw, err := config.UnmarshalRawConfig([]byte(content))
			if err != nil {
				t.Fatal(err)
			}
			if err := validateRawNetworkExtensionIntent(raw); err != nil {
				t.Fatalf("unexecutable metadata rule should be tolerated (no-op), got: %v", err)
			}
		})
	}
}

func TestValidateRawNetworkExtensionIntentToleratesHostRouteKnobs(t *testing.T) {
	// interface-name, routing-mark, find-process-mode and every tun host-route
	// filter (include/exclude interface, uid, package, android-user, mac,
	// src/dst port, auto-redirect, iproute2 marks) are desktop/Android routing
	// primitives with no iOS equivalent: the NE selects its egress via
	// NWPathMonitor and the sandbox exposes no UID/package/MAC/port host filter.
	// They can never take effect AND they never change which proxy handles a
	// flow, so normalizeRawNetworkExtensionSurfaces strips them (tolerate +
	// strip) and the config starts unchanged rather than being hard-rejected.
	// This is the "every upstream config must start; unsupported settings are tolerated and stripped" contract.
	tolerated := map[string]string{
		"interface-name":     "interface-name: en0\n",
		"routing-mark":       "routing-mark: 233\n",
		"find-process-mode":  "find-process-mode: always\n",
		"tun auto-redirect":  "tun:\n  auto-redirect: true\n",
		"tun iproute2":       "tun:\n  iproute2-table-index: 100\n",
		"tun include-if":     "tun:\n  include-interface: [en0]\n",
		"tun exclude-if":     "tun:\n  exclude-interface: [en1]\n",
		"tun include-uid":    "tun:\n  include-uid: [501]\n",
		"tun exclude-uid":    "tun:\n  exclude-uid: [0]\n",
		"tun include-uid-rg": "tun:\n  include-uid-range: ['1000:2000']\n",
		"tun exclude-dst":    "tun:\n  exclude-dst-port: [443]\n",
		"tun exclude-src":    "tun:\n  exclude-src-port: [53]\n",
		"tun package":        "tun:\n  include-package: [com.example.app]\n",
		"tun android-user":   "tun:\n  include-android-user: [0]\n",
		"tun mac":            "tun:\n  include-mac-address: ['00:11:22:33:44:55']\n",
	}
	for name, content := range tolerated {
		t.Run(name, func(t *testing.T) {
			raw, err := config.UnmarshalRawConfig([]byte(content))
			if err != nil {
				t.Fatal(err)
			}
			if err := validateRawNetworkExtensionIntent(raw); err != nil {
				t.Fatalf("host-route knob should be tolerated (stripped later), got: %v", err)
			}
		})
	}
}

func TestValidateRawNetworkExtensionIntentDoesNotMatchOrdinaryPayload(t *testing.T) {
	content := "rules:\n  - DOMAIN,process-name,DIRECT\n  - DOMAIN-SUFFIX,uid.example,DIRECT\n"
	raw, err := config.UnmarshalRawConfig([]byte(content))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRawNetworkExtensionIntent(raw); err != nil {
		t.Fatalf("ordinary domain payload was mistaken for metadata rule: %v", err)
	}
}

func TestValidateRawNetworkExtensionIntentToleratesOutboundEgressOverrides(t *testing.T) {
	// A per-proxy interface-name/routing-mark egress override selects a physical
	// interface/mark the NE does not expose, but it never changes which proxy
	// handles a flow — stripOutboundEgressOverrides removes it (tolerate + strip).
	// The preflight must therefore accept a config carrying one, not reject it.
	for name, content := range map[string]string{
		"proxy interface": `
proxies:
  - {name: node, type: socks5, server: 127.0.0.1, port: 1080, interface-name: en0}
`,
		"proxy routing mark": `
proxies:
  - {name: node, type: socks5, server: 127.0.0.1, port: 1080, routing-mark: 233}
`,
		"group ignored field": `
proxy-groups:
  - {name: group, type: select, proxies: [DIRECT], interface-name: en0}
`,
		"provider override": `
proxy-providers:
  nodes:
    type: http
    url: https://example.com/proxies.yaml
    override: {routing-mark: 233}
`,
		"inline provider payload": `
proxy-providers:
  nodes:
    type: inline
    payload:
      - {name: node, type: socks5, server: 127.0.0.1, port: 1080, interface-name: en0}
`,
	} {
		t.Run(name, func(t *testing.T) {
			raw, err := config.UnmarshalRawConfig([]byte(content))
			if err != nil {
				t.Fatal(err)
			}
			if err := validateRawNetworkExtensionIntent(raw); err != nil {
				t.Fatalf("outbound egress override should be tolerated (stripped), got: %v", err)
			}
		})
	}
}

func TestValidateRawNetworkExtensionIntentRejectsOutboundDNSInterfaceFragments(t *testing.T) {
	for name, content := range map[string]string{
		"top-level wireguard": `
proxies:
  - name: tunnel
    type: wireguard
    remote-dns-resolve: true
    dns: ["https://dns.example/dns-query#en0"]
`,
		"inline provider masque": `
proxy-providers:
  nodes:
    type: inline
    payload:
      - name: tunnel
        type: masque
        remote-dns-resolve: true
        dns: ["tls://dns.example#pdp_ip0"]
`,
	} {
		t.Run(name, func(t *testing.T) {
			raw, err := config.UnmarshalRawConfig([]byte(content))
			if err != nil {
				t.Fatal(err)
			}
			err = validateRawNetworkExtensionIntent(raw)
			if err == nil || !strings.Contains(err.Error(), ".dns") {
				t.Fatalf("outbound DNS interface fragment accepted: %v", err)
			}
		})
	}
}

func TestValidateRawNetworkExtensionIntentRejectsIgnoredOutboundDNSProxyFragment(t *testing.T) {
	content := `
proxy-groups:
  - {name: DNS PROXY, type: select, proxies: [DIRECT]}
proxies:
  - name: tunnel
    type: wireguard
    remote-dns-resolve: true
    dns: ["https://dns.example/dns-query#DNS%20PROXY"]
`
	raw, err := config.UnmarshalRawConfig([]byte(content))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRawNetworkExtensionIntent(raw); err == nil || !strings.Contains(err.Error(), ".dns") {
		t.Fatalf("ignored outbound DNS proxy fragment accepted: %v", err)
	}
}

func TestUnsafeOutboundRuntimeOptionPreservesNonPositiveTransportDisableSemantics(t *testing.T) {
	tests := []map[string]any{
		{
			"type": "vmess", "network": "grpc",
			"grpc-opts": map[string]any{"ping-interval": -1},
		},
		{
			"type": "vless", "network": "xhttp",
			"xhttp-opts": map[string]any{
				"reuse-settings": map[string]any{"h-keep-alive-period": -1},
			},
		},
		{
			"type": "anytls", "idle-session-check-interval": -1,
			"idle-session-timeout": -1,
		},
	}
	for _, mapping := range tests {
		if field, reason := unsafeOutboundRuntimeOption(mapping); field != "" {
			t.Fatalf("non-positive disable/default semantics rejected at %s: %s", field, reason)
		}
	}
}

func TestUnsafeOutboundRuntimeOptionIgnoresUnselectedMekyaOptions(t *testing.T) {
	mapping := map[string]any{
		"type": "vmess", "network": "ws",
		"mekya-opts": map[string]any{
			"polling-interval-initial": int64(9223372036855),
			"max-write-delay":          int64(9223372036855),
		},
	}
	if field, reason := unsafeOutboundRuntimeOption(mapping); field != "" {
		t.Fatalf("unselected Mekya options rejected at %s: %s", field, reason)
	}
}

func TestUnsafeOutboundRuntimeOptionIgnoresUnselectedOrDisabledKcptunTiming(t *testing.T) {
	tests := []map[string]any{
		{
			"type": "ss", "plugin": "v2ray-plugin",
			"plugin-opts": map[string]any{
				"keepalive": int64(9223372037), "conn": 65536,
				"datashard": int64(2147483648), "parityshard": int64(2147483648),
				"smuxbuf": int64(2147483648), "framesize": 65536,
				"ratelimit": int64(4294967296), "rcvwnd": 65536, "dscp": 64,
			},
		},
		{
			"type": "ss", "plugin": "kcptun",
			"plugin-opts": map[string]any{
				"autoexpire": 0, "scavengettl": int64(9223372037),
			},
		},
	}
	for _, mapping := range tests {
		if field, reason := unsafeOutboundRuntimeOption(mapping); field != "" {
			t.Fatalf("unconsumed kcptun option rejected at %s: %s", field, reason)
		}
	}
}

func TestUnsafeOutboundRuntimeOptionAllowsKcptunConnectionBoundaries(t *testing.T) {
	for _, connections := range []int{0, math.MaxUint16} {
		mapping := map[string]any{
			"type": "ss", "plugin": "kcptun",
			"plugin-opts": map[string]any{"conn": connections},
		}
		if field, reason := unsafeOutboundRuntimeOption(mapping); field != "" {
			t.Fatalf("safe kcptun connection count %d rejected at %s: %s", connections, field, reason)
		}
	}
}

func TestUnsafeOutboundRuntimeOptionAllowsKcptunFECShardBoundaries(t *testing.T) {
	for _, options := range []map[string]any{
		{},
		{"datashard": 253},
		{"datashard": 253, "parityshard": 3},
		{"datashard": 1, "parityshard": 1},
	} {
		mapping := map[string]any{
			"type": "ss", "plugin": "kcptun", "plugin-opts": options,
		}
		if field, reason := unsafeOutboundRuntimeOption(mapping); field != "" {
			t.Fatalf("safe kcptun FEC shards %#v rejected at %s: %s", options, field, reason)
		}
	}
}

func TestUnsafeOutboundRuntimeOptionAllowsKcptunSmuxBoundaries(t *testing.T) {
	for _, options := range []map[string]any{
		{},
		{"smuxver": 0},
		{"smuxver": 999},
		{
			"smuxbuf": int64(math.MaxInt32), "streambuf": int64(math.MaxInt32),
			"framesize": 65535, "keepalive": int64(math.MaxInt64 / 3 / int64(time.Second)),
		},
		{"smuxbuf": 1, "streambuf": 1, "framesize": 1},
	} {
		mapping := map[string]any{
			"type": "ss", "plugin": "kcptun", "plugin-opts": options,
		}
		if field, reason := unsafeOutboundRuntimeOption(mapping); field != "" {
			t.Fatalf("safe kcptun smux settings %#v rejected at %s: %s", options, field, reason)
		}
	}
}

func TestUnsafeOutboundRuntimeOptionAllowsKcptunTransportBoundaries(t *testing.T) {
	for _, options := range []map[string]any{
		{},
		{"mtu": 0, "ratelimit": 0, "sndwnd": 0, "rcvwnd": 0, "sockbuf": 0, "dscp": 0},
		{"crypt": "aes", "mtu": 78},
		{"crypt": "aes-128-gcm", "mtu": 86},
		{"crypt": "null", "mtu": 58},
		{"mtu": 9000},
		{
			"ratelimit": int64(math.MaxUint32), "sndwnd": math.MaxUint16,
			"rcvwnd": math.MaxUint16, "sockbuf": int64(math.MaxInt32), "dscp": 63,
		},
	} {
		mapping := map[string]any{
			"type": "ss", "plugin": "kcptun", "plugin-opts": options,
		}
		if field, reason := unsafeOutboundRuntimeOption(mapping); field != "" {
			t.Fatalf("safe kcptun transport settings %#v rejected at %s: %s", options, field, reason)
		}
	}
}

func TestUnsafeOutboundRuntimeOptionIgnoresTUICPacketSizeOverriddenByFrameSize(t *testing.T) {
	mapping := map[string]any{
		"type": "tuic", "max-datagram-frame-size": 1400,
		"max-udp-relay-packet-size": -1,
	}
	if field, reason := unsafeOutboundRuntimeOption(mapping); field != "" {
		t.Fatalf("overridden TUIC UDP packet size rejected at %s: %s", field, reason)
	}
}

func TestUnsafeOutboundRuntimeOptionAllowsHysteriaRateBoundaries(t *testing.T) {
	mapping := map[string]any{
		"type":       "hysteria",
		"up":         "18446744 TBps",
		"down":       "18446744 Tbps",
		"up-speed":   int64(73786976294838),
		"down-speed": int64(73786976294838),
	}
	if field, reason := unsafeOutboundRuntimeOption(mapping); field != "" {
		t.Fatalf("valid Hysteria rate boundary rejected at %s: %s", field, reason)
	}
}

func TestUnsafeOutboundRuntimeOptionAllowsHysteria2AndBrutalRateBoundaries(t *testing.T) {
	tests := []map[string]any{
		{
			"type": "hysteria2", "up": "18446744 TBps", "down": "18446744 Tbps",
		},
		{
			"type": "direct",
			"smux": map[string]any{
				"enabled": true,
				"brutal-opts": map[string]any{
					"enabled": true, "up": "18446744 TBps", "down": "18446744 Tbps",
				},
			},
		},
	}
	for _, mapping := range tests {
		if field, reason := unsafeOutboundRuntimeOption(mapping); field != "" {
			t.Fatalf("valid outbound rate boundary rejected at %s: %s", field, reason)
		}
	}
}

func TestUnsafeOutboundRuntimeOptionIgnoresDisabledBrutalRates(t *testing.T) {
	tests := []map[string]any{
		{
			"type": "direct",
			"smux": map[string]any{
				"enabled": false,
				"brutal-opts": map[string]any{
					"enabled": true, "up": "18446745 TBps",
				},
			},
		},
		{
			"type": "direct",
			"smux": map[string]any{
				"enabled": true,
				"brutal-opts": map[string]any{
					"enabled": false, "down": "18446745 TBps",
				},
			},
		},
	}
	for _, mapping := range tests {
		if field, reason := unsafeOutboundRuntimeOption(mapping); field != "" {
			t.Fatalf("disabled Brutal rate rejected at %s: %s", field, reason)
		}
	}
}

func TestUnsafeOutboundRuntimeOptionRejectsActiveBBRCongestionWindows(t *testing.T) {
	tests := []map[string]any{
		{"type": "hysteria2", "cwnd": -1},
		{"type": "tuic", "congestion-controller": "bbr_meta_v1", "cwnd": int64(7205759403792794)},
		{"type": "masque", "congestion-controller": "bbr", "cwnd": -1},
		{"type": "trusttunnel", "quic": true, "congestion-controller": "bbr_meta_v2", "cwnd": -1},
	}
	for _, mapping := range tests {
		field, reason := unsafeOutboundRuntimeOption(mapping)
		if field != "cwnd" || reason == "" {
			t.Fatalf("unsafe BBR congestion window accepted: field=%q reason=%q", field, reason)
		}
	}
}

func TestUnsafeOutboundRuntimeOptionAllowsBBRCongestionWindowBoundary(t *testing.T) {
	mapping := map[string]any{
		"type": "hysteria2", "cwnd": int64(7205759403792793),
	}
	if field, reason := unsafeOutboundRuntimeOption(mapping); field != "" {
		t.Fatalf("valid BBR congestion window boundary rejected at %s: %s", field, reason)
	}
}

func TestUnsafeOutboundRuntimeOptionIgnoresInactiveCongestionWindows(t *testing.T) {
	tests := []map[string]any{
		{"type": "tuic", "congestion-controller": "cubic", "cwnd": -1},
		{"type": "masque", "congestion-controller": "new_reno", "cwnd": -1},
		{"type": "trusttunnel", "quic": false, "congestion-controller": "bbr", "cwnd": -1},
	}
	for _, mapping := range tests {
		if field, reason := unsafeOutboundRuntimeOption(mapping); field != "" {
			t.Fatalf("inactive congestion window rejected at %s: %s", field, reason)
		}
	}
}

func TestUnsafeOutboundRuntimeOptionAllowsSafeHysteria2UDPMTU(t *testing.T) {
	for _, value := range []int{0, minimumSafeHysteria2UDPMTU} {
		mapping := map[string]any{"type": "hysteria2", "udp-mtu": value}
		if field, reason := unsafeOutboundRuntimeOption(mapping); field != "" {
			t.Fatalf("safe Hysteria2 UDP MTU %d rejected at %s: %s", value, field, reason)
		}
	}
}

func TestUnsafeOutboundRuntimeOptionValidatesTUICMaxOpenStreams(t *testing.T) {
	for _, value := range []int64{-1, math.MaxInt64} {
		mapping := map[string]any{"type": "tuic", "max-open-streams": value}
		field, reason := unsafeOutboundRuntimeOption(mapping)
		if field != "max-open-streams" || reason == "" {
			t.Fatalf("unsafe TUIC maximum open streams %d accepted: field=%q reason=%q", value, field, reason)
		}
	}
	for _, value := range []int64{0, 100, math.MaxInt64 / 2} {
		mapping := map[string]any{"type": "tuic", "max-open-streams": value}
		if field, reason := unsafeOutboundRuntimeOption(mapping); field != "" {
			t.Fatalf("safe TUIC maximum open streams %d rejected at %s: %s", value, field, reason)
		}
	}
}

func TestUnsafeOutboundRuntimeOptionAllowsBoundedXHTTPGeneratedBuffers(t *testing.T) {
	mapping := map[string]any{
		"type": "vless", "network": "xhttp",
		"xhttp-opts": map[string]any{
			"x-padding-bytes":        fmt.Sprintf("1-%d", maximumConfigurationBytes),
			"sc-max-each-post-bytes": maximumConfigurationBytes,
			"session-table":          "Alphabet",
			"session-length":         maximumConfigurationBytes,
		},
	}
	if field, reason := unsafeOutboundRuntimeOption(mapping); field != "" {
		t.Fatalf("bounded XHTTP generated buffer rejected at %s: %s", field, reason)
	}
}

func TestUnsafeOutboundRuntimeOptionIgnoresInactiveXHTTPGeneratedBuffers(t *testing.T) {
	tests := []map[string]any{
		{
			"type": "vless", "network": "ws",
			"xhttp-opts": map[string]any{"x-padding-bytes": maximumConfigurationBytes + 1},
		},
		{
			"type": "vless", "network": "xhttp",
			"xhttp-opts": map[string]any{
				"session-table": "uuid", "session-length": maximumConfigurationBytes + 1,
			},
		},
	}
	for _, mapping := range tests {
		if field, reason := unsafeOutboundRuntimeOption(mapping); field != "" {
			t.Fatalf("inactive XHTTP generated buffer rejected at %s: %s", field, reason)
		}
	}
}

func TestUnsafeOutboundRuntimeOptionAllowsSafeXHTTPReuseRanges(t *testing.T) {
	mapping := map[string]any{
		"type": "vless", "network": "xhttp",
		"xhttp-opts": map[string]any{
			"reuse-settings": map[string]any{
				"max-concurrency":     "0-1024",
				"max-connections":     "0-1024",
				"c-max-reuse-times":   math.MaxInt32,
				"h-max-request-times": math.MaxInt32,
				"h-max-reusable-secs": math.MaxInt64 / int64(time.Second),
			},
		},
	}
	if field, reason := unsafeOutboundRuntimeOption(mapping); field != "" {
		t.Fatalf("safe XHTTP reuse range rejected at %s: %s", field, reason)
	}
}

func TestUnsafeOutboundRuntimeOptionMatchesDownloadReuseActivation(t *testing.T) {
	unsafeDownload := map[string]any{
		"reuse-settings": map[string]any{"max-concurrency": "0-9223372036854775807"},
	}
	withoutUpload := map[string]any{
		"type": "vless", "network": "xhttp",
		"xhttp-opts": map[string]any{"download-settings": unsafeDownload},
	}
	if field, reason := unsafeOutboundRuntimeOption(withoutUpload); field != "" {
		t.Fatalf("inactive download reuse range rejected at %s: %s", field, reason)
	}
	withUpload := map[string]any{
		"type": "vless", "network": "xhttp",
		"xhttp-opts": map[string]any{
			"reuse-settings":    map[string]any{},
			"download-settings": unsafeDownload,
		},
	}
	field, reason := unsafeOutboundRuntimeOption(withUpload)
	if field != "xhttp-opts.download-settings.reuse-settings.max-concurrency" || reason == "" {
		t.Fatalf("active download reuse range accepted: field=%q reason=%q", field, reason)
	}
}

func TestUnsafeOutboundRuntimeOptionAllowsSafeXHTTPPacketUpSchedule(t *testing.T) {
	mapping := map[string]any{
		"type": "vless", "network": "xhttp",
		"xhttp-opts": map[string]any{
			"mode":                     "packet-up",
			"sc-min-posts-interval-ms": math.MaxInt64 / int64(time.Millisecond),
		},
	}
	if field, reason := unsafeOutboundRuntimeOption(mapping); field != "" {
		t.Fatalf("safe XHTTP packet-up schedule rejected at %s: %s", field, reason)
	}
}

func TestUnsafeOutboundRuntimeOptionIgnoresInactiveXHTTPPacketUpSchedule(t *testing.T) {
	for _, mode := range []string{"stream-one", "stream-up"} {
		mapping := map[string]any{
			"type": "vless", "network": "xhttp",
			"xhttp-opts": map[string]any{
				"mode": mode, "sc-min-posts-interval-ms": int64(9223372036855),
			},
		}
		if field, reason := unsafeOutboundRuntimeOption(mapping); field != "" {
			t.Fatalf("inactive %s packet-up schedule rejected at %s: %s", mode, field, reason)
		}
	}
	withReality := map[string]any{
		"type": "vless", "network": "xhttp",
		"reality-opts": map[string]any{"public-key": "selected"},
		"xhttp-opts": map[string]any{
			"mode": "auto", "sc-min-posts-interval-ms": int64(9223372036855),
		},
	}
	if field, reason := unsafeOutboundRuntimeOption(withReality); field != "" {
		t.Fatalf("Reality auto-mode packet-up schedule rejected at %s: %s", field, reason)
	}
}

func TestValidateRawNetworkExtensionIntentAllowsInactiveOrParameterizedOutboundDNS(t *testing.T) {
	for name, content := range map[string]string{
		"remote resolution disabled": `
proxies:
  - name: tunnel
    type: wireguard
    remote-dns-resolve: false
    dns: ["https://dns.example/dns-query#en0"]
`,
		"fragment contains parameters only": `
proxies:
  - name: tunnel
    type: masque
    remote-dns-resolve: true
    dns: ["https://dns.example/dns-query#h3=true&skip-cert-verify=false"]
`,
	} {
		t.Run(name, func(t *testing.T) {
			raw, err := config.UnmarshalRawConfig([]byte(content))
			if err != nil {
				t.Fatal(err)
			}
			if err := validateRawNetworkExtensionIntent(raw); err != nil {
				t.Fatalf("valid nested DNS configuration rejected: %v", err)
			}
		})
	}
}

// TestValidateDNSUsesStableFieldPriority is gone with its subject. It pinned
// which slot's error surfaced first when several carried a dhcp:// or system://
// resolver -- a determinism property of the per-slot rejection walk. No slot
// rejects those schemes any more, so there is no ordering left to be stable
// about; "no resolver slot makes dhcp or system fatal" above covers every slot
// the walk used to visit.

func TestDNSFragmentProxyNameMatchesMihomoURIParsing(t *testing.T) {
	for input, want := range map[string]string{
		"https://dns.example/dns-query#DNS%20PROXY&h3=true": "DNS PROXY",
		"quic://dns.example#h3=true":                        "",
		"tls://dns.example#first&skip-cert-verify=true":     "first",
	} {
		if got := dnsFragmentProxyName(input); got != want {
			t.Fatalf("dnsFragmentProxyName(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestOutboundEgressOverrideFieldsReportsEveryPresentField(t *testing.T) {
	mapping := map[string]any{"interface-name": "en0", "routing-mark": 233}
	if got, want := outboundEgressOverrideFields(mapping), []string{"interface-name", "routing-mark"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("outbound egress override fields = %v, want %v", got, want)
	}
}
