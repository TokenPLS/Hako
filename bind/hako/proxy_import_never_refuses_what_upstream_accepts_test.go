package hako

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/TokenPLS/Hako/adapter"
	"github.com/TokenPLS/Hako/common/convert"
	"gopkg.in/yaml.v3"
)

// This tree never refuses a share link mihomo's own converter accepts.
//
// Thirteen families of query key were doing exactly that on 2026-08-28 -- a
// keepalive on anytls, Reality keys on tuic, an sni on WireGuard -- and each
// was found by a person pasting a link and reporting it, one at a time. The
// refusal registry that exists to catch this class -- "stricter than upstream
// is a defect unless a platform requirement forces it" -- scans
// plan_resources.go and validate.go only, so the whole import surface has been
// outside it since it was written. Its own comment says what that means: a
// refusal the gate cannot see is the same as no gate at all.
//
// Hand-registering the import surface would not have worked either, because
// half of it has no upstream to register against: mihomo does not read
// sing-box, v2ray or surge configurations, so "what does upstream do with
// this" has no answer there. Where the question does have an answer -- a
// share link, which upstream parses with the same convert.ConvertsV2Ray this
// test calls -- it can be asked mechanically for every scheme and every key
// at once, and asking is better than registering: a registry records a
// judgement made once, and this re-measures it.
//
// The comparison is one-directional on purpose. Accepting a key upstream
// ignores is not a defect; refusing a link upstream converts is.
func TestThisTreeNeverRefusesAShareLinkUpstreamAccepts(t *testing.T) {
	// One base link per scheme upstream converts. A scheme upstream does not
	// know is not in scope: there is nothing to be stricter than.
	bases := map[string]string{
		"ss":        "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwd2Q@e.example:1080#N",
		"trojan":    "trojan://pw@e.example:443#N",
		"vless":     "vless://11111111-1111-1111-1111-111111111111@e.example:443#N",
		"vmess":     "vmess://11111111-1111-1111-1111-111111111111@e.example:443#N",
		"anytls":    "anytls://pw@e.example:443#N",
		"hysteria2": "hysteria2://pw@e.example:443#N",
		"tuic":      "tuic://11111111-1111-1111-1111-111111111111:pw@e.example:443#N",
		"socks5":    "socks5://dXNlcjpwYXNz@e.example:1080#N",
		"http":      "http://dXNlcjpwYXNz@e.example:8080#N",
		"hysteria":  "hysteria://e.example:443?auth=pw&up=50&down=100#N",
	}
	// A value per key that is plausible for it. A key probed with a value its
	// own format rejects would make both sides refuse and prove nothing.
	values := map[string]string{
		"udp": "1", "uot": "1", "udp-over-tcp": "true", "tfo": "1", "fastopen": "1",
		"sni": "p.example", "peer": "p.example", "serverName": "p.example", "tlsServerName": "p.example",
		"alpn": "h2", "fingerprint": "chrome", "fp": "chrome", "client-fingerprint": "chrome",
		"hpkp": "aa", "pinSHA256": "aa", "skip-cert-verify": "1", "insecure": "1",
		"allowInsecure": "1", "allow_insecure": "1", "tls": "1", "xtls": "1", "security": "tls",
		"keepalive": "10", "reuse": "1", "version": "4", "psk": "cHNr", "password": "pw",
		"pbk": "aaaa", "publicKey": "aaaa", "sid": "ab", "shortId": "ab", "pcs": "1",
		"up": "50", "upmbps": "50", "down": "100", "downmbps": "100", "auth": "pw",
		"obfs": "salamander", "obfs-password": "opw", "obfsParam": "op", "protocol": "udp",
		"type": "ws", "headerType": "none", "host": "h.example", "path": "/p", "mode": "gun",
		"serviceName": "svc", "ed": "2048", "eh": "X", "extra": "{}", "flow": "xtls-rprx-vision",
		"encryption": "none", "packetEncoding": "packetaddr", "padding": "1", "fragment": "1",
		"alterId": "0", "method": "GET", "title": "T", "remark": "R", "remarks": "R", "name": "N",
		"ports": "443-444", "mport": "443-444", "hop-interval": "30", "hopInterval": "30",
		"stun": "s.example:3478", "disable_sni": "1", "congestion_control": "bbr",
		"congestion-controller": "bbr", "udp_relay_mode": "quic", "udp-relay-mode": "quic",
		"proto": "udp", "network": "ws", "obfs-mode": "http", "obfs-host": "h.example",
	}
	schemes := make([]string, 0, len(bases))
	for scheme := range bases {
		schemes = append(schemes, scheme)
	}
	sort.Strings(schemes)

	var probed int
	for _, scheme := range schemes {
		base := bases[scheme]
		// The reference point. If upstream cannot convert the bare link, every
		// row for this scheme would be vacuously equal and the scheme would pass
		// without being tested at all.
		if converted, err := convert.ConvertsV2Ray([]byte(base)); err != nil || len(converted) != 1 {
			t.Fatalf("%s: upstream does not convert the base link, so nothing below it means anything: %v", scheme, err)
		}
		keys := make([]string, 0)
		for key := range proxyImportQueryFieldLedger[scheme] {
			if _, known := values[key]; known {
				keys = append(keys, key)
			}
		}
		sort.Strings(keys)
		for _, key := range keys {
			link := base[:strings.Index(base, "#")] + probeSeparator(base) + key + "=" + values[key] + "#N"
			if !upstreamBuildsALoadableNode(link) {
				continue
			}
			probed++
			assertBothDoorsImport(t, scheme+"?"+key, link)
		}
	}
	if probed < 200 {
		t.Fatalf("only %d scheme/key pairs were compared; the fixtures have stopped covering the ledger", probed)
	}

	// A key nobody here has ever heard of, which is the case the loop above
	// cannot reach and the one that actually happened.
	//
	// That loop draws its keys from this build's own ledger, so every key it
	// tries is registered by construction and the question of what happens to an
	// unregistered one never comes up. The two links a person reported on
	// 2026-08-28 were refused for exactly that: `socks5://…?security=tls` and
	// `ss://…?udp=1`, both spellings the ledger did not carry. Poisoning
	// ConvertProxiesForIOS back to refusing unregistered keys left the loop above
	// entirely green, which is how this came to be written.
	//
	// The ledger is a whitelist and a whitelist is never finished; upstream reads
	// the keys it knows and ignores the rest, and so must this. A gate that only
	// checks registered keys is a gate against the wrong half.
	for _, scheme := range schemes {
		base := bases[scheme]
		link := base[:strings.Index(base, "#")] + probeSeparator(base) + "hako-no-such-key=1#N"
		if !upstreamBuildsALoadableNode(link) {
			t.Fatalf("%s: upstream does not build a loadable node from an unknown query key, "+
				"which contradicts what this test is for", scheme)
		}
		assertBothDoorsImport(t, scheme+" with an unknown key", link)
	}

	t.Logf("compared %d scheme/key pairs against upstream's own converter, plus one unknown key per scheme", probed)
}

// The other spelling of vmess: a base64 JSON body, which is what v2rayN and
// most airports actually hand out, and the one the loop above cannot reach --
// its probes are query keys, and a JSON body has no query.
//
// A person's subscription was refused on 2026-09-02 for exactly this: seven
// nodes, every one carrying `"class": 0` and `"verify_cert": true`, keys no
// specification names and upstream never reads. Upstream decodes the body
// into a map and takes the keys it knows (common/convert/converter.go, the
// vmess case); this tree decoded the same body and refused the node over the
// first key it did not list. Seven for seven upstream, zero for seven here,
// and the message blamed the field for being "recognized but unsupported"
// when the truth was that nobody had heard of it.
//
// Same rule as the query keys, then: a body key upstream ignores cannot cost a
// node here. The probes are the two keys that were reported, two keys other
// exporters write (`remark`, `headerType`), and one nobody has ever heard of.
func TestThisTreeNeverRefusesAVMessBodyKeyUpstreamIgnores(t *testing.T) {
	body := map[string]any{
		"v": "2", "ps": "N", "add": "e.example", "port": "443",
		"id": "11111111-1111-1111-1111-111111111111", "aid": "0", "scy": "auto",
		"net": "ws", "type": "none", "host": "h.example", "path": "/p", "tls": "tls", "sni": "p.example",
	}
	probes := map[string]any{
		"class":            json.Number("0"),
		"verify_cert":      true,
		"remark":           "R",
		"headerType":       "none",
		"hako-no-such-key": json.Number("1"),
	}
	keys := make([]string, 0, len(probes))
	for key := range probes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		probed := make(map[string]any, len(body)+1)
		for field, value := range body {
			probed[field] = value
		}
		probed[key] = probes[key]
		encoded, err := json.Marshal(probed)
		if err != nil {
			t.Fatalf("%s: encode: %v", key, err)
		}
		link := "vmess://" + base64.StdEncoding.EncodeToString(encoded)
		if !upstreamBuildsALoadableNode(link) {
			t.Fatalf("vmess body with %s: upstream does not build a loadable node, "+
				"which contradicts what this test is for", key)
		}
		assertBothDoorsImport(t, "vmess body with "+key, link)
	}
}

func probeSeparator(link string) string {
	if strings.Contains(link[:strings.Index(link, "#")], "?") {
		return "&"
	}
	return "?"
}

// assertBothDoorsImport checks the two entry points a link can arrive through.
//
// They disagreed. ConvertProxiesForIOS tolerated a key the whitelist did not
// list and InspectProxyPayloadForIOS skipped the node over it, and inspect is
// the one the client calls first -- so a person pasting such a link was told
// nothing imported while the other door, given the same bytes, built the node.
// A gate that measures one door proves nothing about the other, and the gate
// written the same day measured only the door that had been fixed.
func assertBothDoorsImport(t *testing.T, what, link string) {
	t.Helper()
	box, err := ConvertProxiesForIOS([]byte(link))
	if err != nil {
		t.Errorf("%s: upstream converts this link and ConvertProxiesForIOS refuses it: %v", what, err)
	} else {
		var out struct {
			Proxies []map[string]any `yaml:"proxies"`
		}
		if err := yaml.Unmarshal([]byte(box.Value), &out); err != nil || len(out.Proxies) != 1 {
			t.Errorf("%s: ConvertProxiesForIOS produced %d nodes", what, len(out.Proxies))
		}
	}
	inspected, err := InspectProxyPayloadForIOS([]byte(link), "singleNode")
	if err != nil {
		t.Errorf("%s: upstream converts this link and InspectProxyPayloadForIOS refuses it: %v", what, err)
		return
	}
	var report struct {
		Proxies []map[string]any `json:"proxies"`
		Skipped []struct {
			Message string `json:"message"`
		} `json:"skipped"`
	}
	if err := json.Unmarshal([]byte(inspected.Value), &report); err != nil {
		t.Errorf("%s: decode: %v", what, err)
		return
	}
	if len(report.Proxies) != 1 {
		reason := ""
		if len(report.Skipped) > 0 {
			reason = report.Skipped[0].Message
		}
		t.Errorf("%s: upstream converts this link and inspect returned %d nodes: %s", what, len(report.Proxies), reason)
	}
}

// upstreamBuildsALoadableNode is the comparison's own calibration: a pair is
// only worth measuring if upstream turns the link into something the kernel
// will actually load.
//
// Upstream's converter does not validate -- it fills a map and hands it over --
// so it "accepts" links whose values the outbound then rejects. Probing
// hysteria with `fingerprint=chrome` is one: on that protocol the field is a
// certificate pin and wants sha256 hex, and mihomo says so through
// adapter.ParseProxy, not through the converter. Counting those as this tree
// being stricter than upstream would be counting the kernel's own judgement
// against it, and the fixtures would have to encode a correct value per scheme
// per key to avoid it -- a second copy of the outbounds' validation, kept by
// hand, wrong the day one of them changes.
func upstreamBuildsALoadableNode(link string) bool {
	converted, err := convert.ConvertsV2Ray([]byte(link))
	if err != nil || len(converted) != 1 {
		return false
	}
	outbound, err := adapter.ParseProxy(converted[0])
	if err != nil {
		return false
	}
	_ = outbound.Close()
	return true
}

// A node's name comes back exactly as the person's link spelled it.
//
// The comparison above counts nodes, and counting nodes cannot see a node that
// arrived under a different name. That is the arm the macOS lane added when it
// built the same differential independently, and it is the arm that found the
// defect: an airport name ending in `)` -- `(hy2)`, `(IEPL)`, ordinary suffixes
// Shadowrocket writes unencoded -- lost its last character to the trim that
// peels prose off a pasted link. The person's node was renamed and nothing
// said so, which is worse than refusing it: a refusal is visible.
//
// The known positives are kept as rows rather than removed once fixed. The
// macOS lane's note on that is the reason: its first run of this differential
// reported zero divergences, and only reintroducing cases it had already found
// showed the harness was reaching them at all.
func TestANodeKeepsTheNameItsLinkGaveIt(t *testing.T) {
	for _, test := range []struct {
		name string
		link string
		want string
	}{
		{
			name: "a bare closing bracket in the fragment",
			link: "hysteria2://pw@e.example:443#A(B)",
			want: "A(B)",
		},
		{
			name: "an airport suffix the way Shadowrocket exports it",
			link: "hysteria2://pw@e.example:443?insecure=1#\U0001F1EE\U0001F1F314印度-移动/南方联通(hy2)",
			want: "\U0001F1EE\U0001F1F314印度-移动/南方联通(hy2)",
		},
		{
			name: "a name carrying a colon and a slash",
			link: "hysteria2://pw@e.example:443#\U0001F30F自动最优线路(hy2)-网址: new.example.me",
			want: "\U0001F30F自动最优线路(hy2)-网址: new.example.me",
		},
		{
			// Full-width, because the half-width rows alone let a poison that
			// only handles ASCII brackets pass. Chinese prose uses these more
			// often than the ASCII pair, and an airport writing a Chinese name
			// can end it with one.
			name: "a full-width closing bracket in the fragment",
			link: "hysteria2://pw@e.example:443#香港（备用）",
			want: "香港（备用）",
		},
		{
			name: "a percent-encoded bracket, which was never at risk",
			link: "hysteria2://pw@e.example:443#A%28B%29",
			want: "A(B)",
		},
		{
			name: "trailing prose punctuation with no opener of its own",
			link: "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwd2Q@e.example:1080#香港01",
			want: "香港01",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			box, err := ConvertProxiesForIOS([]byte(test.link))
			if err != nil {
				t.Fatalf("the link was refused: %v", err)
			}
			var out struct {
				Proxies []map[string]any `yaml:"proxies"`
			}
			if err := yaml.Unmarshal([]byte(box.Value), &out); err != nil || len(out.Proxies) != 1 {
				t.Fatalf("expected one node: %v", err)
			}
			name, _ := out.Proxies[0]["name"].(string)
			if name != test.want {
				t.Fatalf("the node was renamed: got %q, want %q", name, test.want)
			}
		})
	}
}

// Only some outbounds verify the certificate pin while the node is parsed, and
// the list this importer filters against says which.
//
// Filtering everywhere would refuse values the kernel accepts -- `fingerprint:
// chrome` loads on trojan, vmess, vless, anytls and ss -- and filtering nowhere
// loses the node on the three that do verify. So the set is measured here
// against adapter.ParseProxy rather than trusted, in both directions: a type
// that starts verifying and a type that stops both make this red.
func TestOnlySomeOutboundsVerifyTheirFingerprint(t *testing.T) {
	required := map[string]map[string]any{
		"trojan":    {"password": "pw"},
		"vmess":     {"uuid": "11111111-1111-1111-1111-111111111111", "alterId": 0, "cipher": "auto"},
		"vless":     {"uuid": "11111111-1111-1111-1111-111111111111"},
		"anytls":    {"password": "pw"},
		"ss":        {"cipher": "chacha20-ietf-poly1305", "password": "pw"},
		"hysteria2": {"password": "pw"},
		"tuic":      {"uuid": "11111111-1111-1111-1111-111111111111", "password": "pw"},
	}
	for proxyType, extra := range required {
		t.Run(proxyType, func(t *testing.T) {
			proxy := map[string]any{"name": "N", "type": proxyType, "server": "e.example", "port": 443}
			for key, value := range extra {
				proxy[key] = value
			}
			// A uTLS browser name, which is what exporters paste into this field
			// and what a certificate pin is not.
			proxy["fingerprint"] = "chrome"
			outbound, err := adapter.ParseProxy(proxy)
			if err == nil {
				_ = outbound.Close()
			}
			_, listed := proxyTypesThatVerifyTheirFingerprint[proxyType]
			if listed != (err != nil) {
				t.Fatalf("%s: listed as verifying = %v, but adapter.ParseProxy said %v", proxyType, listed, err)
			}
		})
	}
	for proxyType := range proxyTypesThatVerifyTheirFingerprint {
		if proxyType == "hysteria" {
			continue // built from a share link elsewhere; no minimal map here
		}
		if _, covered := required[proxyType]; !covered {
			t.Fatalf("%s is filtered but never measured, so the list could be wrong without saying so", proxyType)
		}
	}
}

// A plugin this build cannot construct leaves the node without one, rather than
// costing the node.
//
// Upstream's converter looks the plugin name up, finds nothing, and returns a
// map with no plugin key -- and the kernel loads that map. Measured on all
// three schemes that carry a plugin. This tree refused instead, on the argument
// that a node missing its obfs cannot reach a server expecting one; the
// argument is true and it is equally true of the node upstream produces, and it
// costs a working node every time the plugin was junk an exporter left behind.
//
// The reader's ruling of 2026-08-28 settles which way that trade goes: what
// upstream ignores must not cost us the node.
//
// The kernel's verdict is the judge here, not an expectation written down, so
// the day mihomo starts refusing one of these the row moves on its own.
func TestAnUnbuildablePluginLeavesTheNodeWithoutOne(t *testing.T) {
	for _, test := range []struct{ name, link string }{
		{"ss with a plugin name that is not a plugin", "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwd2Q@e.example:1080?plugin=0#N"},
		{"ss with a plugin mihomo does not have", "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwd2Q@e.example:1080?plugin=weird#N"},
		{"trojan with a plugin mihomo does not have", "trojan://pw@e.example:443?plugin=weird#N"},
		{"trojan with an obfs mode that is not websocket", "trojan://pw@e.example:443?plugin=obfs-local;obfs%3Dtls#N"},
		{"snell with a plugin mihomo does not have", "snell://cHNr@e.example:443?plugin=weird&version=4#N"},
	} {
		t.Run(test.name, func(t *testing.T) {
			report := readImportReport(t, []byte(test.link))
			if len(report.Proxies) != 1 {
				t.Fatalf("an unbuildable plugin cost the node: %#v", report)
			}
			if plugin, present := report.Proxies[0]["plugin"]; present {
				t.Fatalf("a plugin was set from a name that cannot be built: %v", plugin)
			}
			var named bool
			for _, notice := range report.NotHonoured {
				if strings.Contains(notice.Message, "plugin") {
					named = true
				}
			}
			if !named {
				t.Fatalf("the plugin was dropped without saying so: %#v", report.NotHonoured)
			}
		})
	}

	// The negative control: a plugin that can be built still is.
	report := readImportReport(t, []byte("ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwd2Q@e.example:1080?plugin=obfs-local;obfs%3Dhttp#N"))
	if len(report.Proxies) != 1 || report.Proxies[0]["plugin"] != "obfs" {
		t.Fatalf("a buildable plugin was dropped too: %#v", report.Proxies)
	}
}

// A plugin written in any case builds, and whatever is written is something the
// kernel will load.
//
// Exporters do not agree on case, and this build recognised the plugin's name
// case-insensitively and then read its subfields case-sensitively, so
// `obfs-local;OBFS=http` came out as a node with an empty obfs mode -- which
// the kernel refuses. It came out that way because upstream's converter had
// already written it (converter.go:303 reads the subfields case-sensitively
// too) and this tree deferred to whatever was already there instead of
// correcting it.
//
// Every row asserts against adapter.ParseProxy rather than against a value
// written here: the property is not "the mode is http", it is "whatever we
// wrote, the kernel accepts". A mode with no accepted spelling means no plugin,
// which is upstream's own outcome, not no node.
func TestAPluginBuildsWhateverCaseItIsWrittenIn(t *testing.T) {
	for _, test := range []struct {
		spec   string
		plugin any
	}{
		{"obfs-local;obfs=http", "obfs"},
		{"OBFS-LOCAL;OBFS=HTTP", "obfs"},
		{"Obfs-Local;Obfs=Http", "obfs"},
		{"obfs-local;OBFS=http", "obfs"},
		{"obfs-local;obfs=tls;obfs-host=cdn.example", "obfs"},
		{"V2RAY-PLUGIN;MODE=WS", "v2ray-plugin"},
		{"v2ray-plugin;mode=websocket", "v2ray-plugin"},
		// No accepted spelling: no plugin, and still a node.
		{"obfs-local;obfs=nonsense", nil},
		{"weird;x=1", nil},
	} {
		t.Run(test.spec, func(t *testing.T) {
			link := "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwd2Q@e.example:1080?plugin=" +
				url.QueryEscape(test.spec) + "#N"
			report := readImportReport(t, []byte(link))
			if len(report.Proxies) != 1 {
				t.Fatalf("the link did not import: %#v", report)
			}
			if got := report.Proxies[0]["plugin"]; got != test.plugin {
				t.Fatalf("plugin = %v, want %v", got, test.plugin)
			}
			outbound, err := adapter.ParseProxy(report.Proxies[0])
			if err != nil {
				t.Fatalf("this importer produced a node the kernel refuses: %v", err)
			}
			_ = outbound.Close()
		})
	}
}
