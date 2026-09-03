package hako

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/TokenPLS/Hako/adapter"
)

// One Shadowrocket dialect, one answer. The exporter spells websocket the same
// way for every protocol that has it -- obfs=websocket, obfsParam for the Host,
// path for the path -- so a reader who pastes the trojan form and the vless form
// of the same node must get the same transport out. Before this gate the dialect
// lived in two layers times one branch per protocol, and each branch had copied
// however much of it its author needed: vmess complete, vless dropping obfs in
// silence, trojan refusing obfsParam outright.
func TestShadowrocketWebsocketDialectIsUniformAcrossProtocols(t *testing.T) {
	const host, path = "cdn.example.invalid", "/ray"
	dialect := "?obfs=websocket&obfsParam=" + host + "&path=" + path + "&tls=1&peer=sni.example.invalid"
	vmessInner := base64.RawURLEncoding.EncodeToString(
		[]byte("auto:b831381d-6324-4d53-ad4f-8cda48b30811@example.invalid:443"))

	for name, link := range map[string]string{
		"vmess":  "vmess://" + vmessInner + dialect + "#n",
		"vless":  "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.invalid:443" + dialect + "#n",
		"trojan": "trojan://secret@example.invalid:443" + dialect + "#n",
	} {
		t.Run(name, func(t *testing.T) {
			report := inspectProxyPayloadReport(t, link, "singleNode")
			if len(report.Proxies) != 1 {
				t.Fatalf("the dialect was refused instead of translated: rejected=%+v unsupported=%+v",
					report.Skipped, report.Skipped)
			}
			proxy := report.Proxies[0]
			if network, _ := proxy["network"].(string); network != "ws" {
				t.Fatalf("network = %q, want ws -- obfs=websocket was dropped in silence", network)
			}
			opts, _ := proxy["ws-opts"].(map[string]any)
			if opts == nil {
				t.Fatalf("no ws-opts: the transport is ws but its host and path went nowhere")
			}
			if got, _ := opts["path"].(string); got != path {
				t.Fatalf("ws-opts.path = %q, want %q", got, path)
			}
			headers, _ := opts["headers"].(map[string]any)
			if got, _ := headers["Host"].(string); got != host {
				t.Fatalf("ws-opts.headers.Host = %q, want %q (obfsParam carries it)", got, host)
			}
			// tls is asserted only where mihomo has the field. trojan carries TLS
			// implicitly and its option struct has no tls key (adapter/outbound:
			// only sni and skip-cert-verify), so tls=1 there is a dialect key that
			// is accepted and deliberately ignored -- the third case the ledger's
			// own comment names and the implementation never had a place for.
			if name != "trojan" {
				if tls, _ := proxy["tls"].(bool); !tls {
					t.Fatalf("tls = false, want true")
				}
			}
		})
	}
}

// vless://encryption:uuid@host is the legacy authority form. Whether it arrives
// plain or base64-wrapped, the uuid is the half after the colon -- taking the
// half before it yields a node that looks complete and cannot connect.
// TestLegacyCredentialAuthorityKeepsTheIDNotTheMethod covers the
// `[method]:id@host:port` authority across every way the exporter writes it. The
// slot before the colon holds four different things depending on how the node was
// entered -- `auto:` (its vmess cipher name, reused), `none:`, an empty string, or
// the colon omitted entirely -- and all four describe the same node, because vless
// does not negotiate encryption at all and an absent vmess cipher means the
// default. Reading that slot literally refused Shadowrocket's own default vless
// export with "invaild vless encryption value: auto".
func TestLegacyCredentialAuthorityKeepsTheIDNotTheMethod(t *testing.T) {
	const id = "a71f3b5b-6657-435b-ba6e-0dfbf8fe984f"
	for _, scheme := range []string{"vless", "vmess"} {
		for _, prefix := range []string{"auto:", "none:", ":", ""} {
			inner := prefix + id + "@198.51.100.50:443"
			for name, host := range map[string]string{
				"plain":  inner,
				"base64": base64.RawURLEncoding.EncodeToString([]byte(inner)),
			} {
				label := scheme + "/" + strings.TrimSuffix(prefix, ":") + "/" + name
				if prefix == "" {
					label = scheme + "/omitted/" + name
				}
				t.Run(label, func(t *testing.T) {
					link := scheme + "://" + host + "?security=tls&type=ws#n"
					report := inspectProxyPayloadReport(t, link, "singleNode")
					if len(report.Proxies) != 1 {
						t.Fatalf("refused: %+v %+v", report.Skipped, report.Skipped)
					}
					proxy := report.Proxies[0]
					raw, _ := json.Marshal(proxy)
					if got, _ := proxy["uuid"].(string); got != id {
						t.Fatalf("uuid = %q, want %q -- the method half was taken instead\n  %s", got, id, raw)
					}
					if got, _ := proxy["server"].(string); got != "198.51.100.50" {
						t.Fatalf("server = %q -- userinfo leaked into the endpoint\n  %s", got, raw)
					}
				})
			}
		}
	}
}

// TestShadowrocketObfuscationDialectReachesShadowsocks is the ss cell of the same
// dialect: the exporter writes `obfs=websocket&obfsParam=…&path=…` on ss exactly
// as on vmess, and lands it in plugin/plugin-opts because that is where mihomo
// keeps an ss obfuscation (ss.md: v2ray-plugin for websocket, obfs for http/tls).
// The authority is the exporter's default whole-authority base64, which is the
// path on which upstream reads no plugin at all -- so the `plugin=` spelling is
// covered too, and both are handed to adapter.ParseProxy.
func TestShadowrocketObfuscationDialectReachesShadowsocks(t *testing.T) {
	const authority = "YWVzLTEyOC1nY206c2FtcGxlQDE5OC41MS4xMDAuNTA6ODM4OA" // aes-128-gcm:sample@198.51.100.50:8388
	for name, want := range map[string]struct {
		link   string
		plugin string
		mode   string
		host   string
	}{
		"websocket via obfs=": {
			"ss://" + authority + "?obfs=websocket&obfsParam=example.invalid&path=/w#S-ws",
			"v2ray-plugin", "websocket", "example.invalid",
		},
		"http via plugin=": {
			"ss://" + authority + "?plugin=obfs-local;obfs%3Dhttp;obfs-host%3Dexample.invalid#S-http",
			"obfs", "http", "example.invalid",
		},
	} {
		t.Run(name, func(t *testing.T) {
			report := inspectProxyPayloadReport(t, want.link, "singleNode")
			if len(report.Proxies) != 1 {
				t.Fatalf("refused: rejected=%+v unsupported=%+v", report.Skipped, report.Skipped)
			}
			proxy := report.Proxies[0]
			if got, _ := proxy["plugin"].(string); got != want.plugin {
				raw, _ := json.Marshal(proxy)
				t.Fatalf("plugin = %q, want %q -- the obfuscation went nowhere\n  %s", got, want.plugin, raw)
			}
			opts, _ := proxy["plugin-opts"].(map[string]any)
			if got, _ := opts["mode"].(string); got != want.mode {
				t.Fatalf("plugin-opts.mode = %q, want %q", got, want.mode)
			}
			if got, _ := opts["host"].(string); got != want.host {
				t.Fatalf("plugin-opts.host = %q, want %q", got, want.host)
			}
			if _, err := adapter.ParseProxy(proxy); err != nil {
				t.Fatalf("the kernel refused what this importer built: %v", err)
			}
		})
	}
}

// TestUnauthenticatedSocksSurvivesTheExportersBase64Authority: the exporter
// base64s `host:port` for a socks node with no credentials exactly as it base64s
// `user:pass@host:port` for one with them, and the unwrapping used to require an
// `@` -- so the credential-free node, legal per socks.en.md, never unwrapped and
// upstream refused it as format invalid.
func TestUnauthenticatedSocksSurvivesTheExportersBase64Authority(t *testing.T) {
	for name, want := range map[string]struct {
		link     string
		username string
	}{
		"no credentials": {"socks://MTk4LjUxLjEwMC41MDoxMDgw?remarks=S-noauth", ""},                   // 198.51.100.50:1080
		"credentials":    {"socks://dXNlcjpzYW1wbGVAMTk4LjUxLjEwMC41MDoxMDgw?remarks=S-auth", "user"}, // user:sample@198.51.100.50:1080
	} {
		t.Run(name, func(t *testing.T) {
			report := inspectProxyPayloadReport(t, want.link, "singleNode")
			if len(report.Proxies) != 1 {
				t.Fatalf("refused: rejected=%+v unsupported=%+v", report.Skipped, report.Skipped)
			}
			proxy := report.Proxies[0]
			if got := anyString(proxy["server"]); got != "198.51.100.50" {
				t.Fatalf("server = %q", got)
			}
			if got := anyString(proxy["port"]); got != "1080" {
				t.Fatalf("port = %q", got)
			}
			if got := anyString(proxy["username"]); got != want.username {
				t.Fatalf("username = %q, want %q", got, want.username)
			}
			if _, err := adapter.ParseProxy(proxy); err != nil {
				t.Fatalf("the kernel refused what this importer built: %v", err)
			}
		})
	}
}
