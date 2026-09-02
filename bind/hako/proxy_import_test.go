package hako

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

type decodedProxyImportReport struct {
	Format  string           `json:"format"`
	Context string           `json:"context"`
	Proxies []map[string]any `json:"proxies"`
	// One field, because the report has one outcome for "did not become a node".
	// The two it replaced were concatenated by every consumer that read them.
	Skipped     []decodedProxyImportIssue `json:"skipped"`
	NotHonoured []decodedProxyImportIssue `json:"notHonoured"`
}

type decodedProxyImportIssue struct {
	Index           int      `json:"index"`
	Scheme          string   `json:"scheme"`
	Code            string   `json:"code"`
	Message         string   `json:"message"`
	Proxy           string   `json:"proxy"`
	AlsoNotHonoured []string `json:"alsoNotHonoured"`
}

type shadowrocketFixtureDocument struct {
	Source struct {
		Version      string `json:"version"`
		Build        string `json:"build"`
		BinarySHA256 string `json:"binarySHA256"`
	} `json:"source"`
	Fixtures []struct {
		CanonicalType string         `json:"canonicalType"`
		Variant       string         `json:"variant"`
		SourceInput   string         `json:"sourceInput"`
		Exported      string         `json:"exported"`
		Expected      map[string]any `json:"expected"`
	} `json:"fixtures"`
}

func decodeProxyImportReport(t *testing.T, box *StringBox) decodedProxyImportReport {
	t.Helper()
	if box == nil {
		t.Fatal("nil report")
	}
	var report decodedProxyImportReport
	if err := json.Unmarshal([]byte(box.Value), &report); err != nil {
		t.Fatalf("decode report: %v\n%s", err, box.Value)
	}
	return report
}

func nestedProxyValue(proxy map[string]any, path string) (any, bool) {
	parts := strings.Split(path, ".")
	var current any = proxy
	for _, part := range parts {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = object[part]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func assertProxyFields(t *testing.T, proxy map[string]any, expected map[string]any) {
	t.Helper()
	for path, want := range expected {
		got, exists := nestedProxyValue(proxy, path)
		if !exists || !reflect.DeepEqual(got, want) {
			t.Errorf("%s = %#v (exists %t), want %#v; proxy = %#v", path, got, exists, want, proxy)
		}
	}
}

func TestProxyImportCapabilitiesForIOSOwnsTheCompleteSchemeRegistry(t *testing.T) {
	box := ProxyImportCapabilitiesForIOS()
	var capabilities struct {
		Schemes []struct {
			Scheme        string `json:"scheme"`
			CanonicalType string `json:"canonicalType"`
			Status        string `json:"status"`
		} `json:"schemes"`
	}
	if err := json.Unmarshal([]byte(box.Value), &capabilities); err != nil {
		t.Fatalf("decode capabilities: %v", err)
	}
	got := make([]string, 0, len(capabilities.Schemes))
	for _, item := range capabilities.Schemes {
		got = append(got, item.Scheme)
		if item.Status == "" {
			t.Fatalf("scheme %q has no status", item.Scheme)
		}
	}
	want := []string{
		"vmess", "http", "https", "http2", "http3", "socks", "socks5", "socks5h",
		"ssocks", "ssocks5", "lua", "ssr", "sub", "trojan", "trojan-go",
		"ss", "gp", "snell", "vless", "relay", "hysteria", "hy",
		"hysteria2", "hy2",
		// Upstream builds proxies from the +realm spellings; the registry follows the
		// core it feeds rather than only what one exporter emits.
		"hysteria2+realm", "hy2+realm",
		"tuic", "juicity", "wireguard", "wg", "masque",
		"ssh", "anytls", "openconnect", "tt", "mierus", "mieru", "brook",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("schemes = %#v, want %#v", got, want)
	}
	wantStatuses := map[string]string{
		// Adjudicated against the exporter's own output rather than the scheme
		// name: trojan-go and ssocks5 are input aliases it normalises away
		// -- it re-exports them as trojan:// and ssocks:// -- while relay:// turned
		// out to be a single node whose authority is base64(host:port), not the
		// multi-hop both lanes read into the name. http2 and http3 keep their own
		// scheme and mihomo has no HTTP/2 or HTTP/3 CONNECT outbound to build.
		"http2": "coreUnsupported", "http3": "coreUnsupported",
		"ssocks": "supported", "ssocks5": "supported",
		// Upstream's converter lists socks5h alongside socks and socks5
		// (common/convert/converter.go); this registry simply never carried it.
		"socks5h":   "supported",
		"trojan-go": "supported", "relay": "coreUnsupported",
		"lua": "coreUnsupported", "gp": "coreUnsupported", "juicity": "coreUnsupported",
		"openconnect": "coreUnsupported", "brook": "coreUnsupported", "sub": "wrapper",
		// mieru:// is the standard format upstream also accepts; it carries a whole
		// multi-profile client config, so it is named and refused, not constructed.
		"mieru": "coreUnsupported",
	}
	for _, item := range capabilities.Schemes {
		wantStatus := wantStatuses[item.Scheme]
		if wantStatus == "" {
			wantStatus = "supported"
		}
		if item.Status != wantStatus {
			t.Errorf("%s status = %q, want %q", item.Scheme, item.Status, wantStatus)
		}
	}
}

func TestEverySupportedImportSchemeHasAConstructibleFixture(t *testing.T) {
	privateKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	publicKeyBytes := make([]byte, 32)
	publicKeyBytes[0] = 1
	publicKey := base64.StdEncoding.EncodeToString(publicKeyBytes)

	masqueKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	masquePrivate, err := x509.MarshalECPrivateKey(masqueKey)
	if err != nil {
		t.Fatal(err)
	}
	masquePublic, err := x509.MarshalPKIXPublicKey(&masqueKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	masque := "masque://example.invalid:443?privateKey=" +
		urlQueryEscape(base64.StdEncoding.EncodeToString(masquePrivate)) +
		"&publicKey=" + urlQueryEscape(base64.StdEncoding.EncodeToString(masquePublic)) +
		"&ip=10.0.0.2%2F32&allowInsecure=1#masque"

	trustTunnelPayload := appendTLV(nil, 0x01, []byte("vpn.example.invalid"))
	trustTunnelPayload = appendTLV(trustTunnelPayload, 0x02, []byte("198.51.100.7:443"))
	trustTunnelPayload = appendTLV(trustTunnelPayload, 0x03, []byte("sni.example.invalid"))
	trustTunnelPayload = appendTLV(trustTunnelPayload, 0x05, []byte("user"))
	trustTunnelPayload = appendTLV(trustTunnelPayload, 0x06, []byte("secret"))
	trustTunnelPayload = appendTLV(trustTunnelPayload, 0x07, []byte{1})
	trustTunnelPayload = appendTLV(trustTunnelPayload, 0x09, []byte{2})
	trustTunnelPayload = appendTLV(trustTunnelPayload, 0x0c, []byte("Trust Tunnel"))

	ssPassword := base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:secret"))
	ssrPassword := base64.RawURLEncoding.EncodeToString([]byte("secret"))
	ssrPayload := "example.invalid:443:origin:aes-256-cfb:plain:" + ssrPassword +
		"/?remarks=" + base64.RawURLEncoding.EncodeToString([]byte("ssr"))
	fixtures := map[string]string{
		"vmess":     "vmess://YXV0bzpiODMxMzgxZC02MzI0LTRkNTMtYWQ0Zi04Y2RhNDhiMzA4MTFAZXhhbXBsZS5pbnZhbGlkOjQ0Mw?remarks=vmess",
		"http":      "http://user:secret@example.invalid:8080#http",
		"https":     "https://user:secret@example.invalid:443#https",
		"socks":     "socks://user:secret@example.invalid:1080#socks",
		"socks5":    "socks5://user:secret@example.invalid:1080#socks5",
		"ssr":       "ssr://" + base64.RawURLEncoding.EncodeToString([]byte(ssrPayload)),
		"trojan":    "trojan://secret@example.invalid:443#trojan",
		"ss":        "ss://" + ssPassword + "@example.invalid:8388#ss",
		"snell":     "snell://secret@example.invalid:443?version=4#snell",
		"vless":     "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.invalid:443?type=tcp#vless",
		"hysteria":  "hysteria://secret@example.invalid:443?peer=sni.example.invalid&upmbps=10&downmbps=20#hysteria",
		"hy":        "hy://secret@example.invalid:443?peer=sni.example.invalid&upmbps=10&downmbps=20#hy",
		"hysteria2": "hysteria2://secret@example.invalid:443#hysteria2",
		"hy2":       "hy2://secret@example.invalid:443#hy2",
		"tuic":      "tuic://00000000-0000-0000-0000-000000000001:secret@example.invalid:443#tuic",
		"wireguard": "wireguard://example.invalid:51820?publicKey=" + urlQueryEscape(publicKey) +
			"&privateKey=" + urlQueryEscape(privateKey) + "&ip=10.0.0.2%2F32#wireguard",
		"wg": "wg://example.invalid:51820?publicKey=" + urlQueryEscape(publicKey) +
			"&privateKey=" + urlQueryEscape(privateKey) + "&ip=10.0.0.2%2F32#wg",
		"masque": masque,
		"ssh":    "ssh://user:secret@example.invalid:22#ssh",
		"anytls": "anytls://secret@example.invalid:443#anytls",
		"tt":     "tt://?" + base64.RawURLEncoding.EncodeToString(trustTunnelPayload),
		"mierus": "mierus://user:secret@example.invalid:443?proto=TCP&profile=profile#mieru",
		// The +realm spellings are upstream's own (converter.go switches on the
		// suffix); the shape is upstream's test input with a documentation host.
		"hysteria2+realm": "hysteria2+realm://tok3n@example.invalid:8443/rid42?auth=letmein&stun=stun1.example.invalid:3478&sni=example.invalid#realm",
		"hy2+realm":       "hy2+realm://tok3n@example.invalid:8443/rid42?auth=letmein&stun=stun1.example.invalid:3478&sni=example.invalid#realm",
		// The exporter's own shapes: ssocks carries a base64 authority and states
		// TLS in the scheme, trojan-go spells its websocket transport through the
		// Shadowrocket obfs plugin.
		"ssocks":    "ssocks://dXNlcjpzZWNyZXRAZXhhbXBsZS5pbnZhbGlkOjQ0Mw?remarks=ssocks",
		"ssocks5":   "ssocks5://dXNlcjpzZWNyZXRAZXhhbXBsZS5pbnZhbGlkOjQ0Mw?remarks=ssocks5",
		"trojan-go": "trojan-go://secret@example.invalid:443?peer=sni.example.invalid&plugin=obfs-local;obfs%3Dwebsocket;obfs-host%3Dsni.example.invalid;path%3D/go",
		"socks5h":   "socks5h://dXNlcjpzZWNyZXQ@example.invalid:1080#socks5h",
	}

	for _, capability := range proxyImportCapabilities {
		fixture, exists := fixtures[capability.Scheme]
		if capability.Status != proxyImportSupported {
			if exists {
				t.Errorf("%s has a construct fixture but status %s", capability.Scheme, capability.Status)
			}
			continue
		}
		if !exists {
			t.Errorf("supported scheme %s has no construct fixture", capability.Scheme)
			continue
		}
		t.Run(capability.Scheme, func(t *testing.T) {
			box, inspectErr := InspectProxyPayloadForIOS([]byte(fixture), "singleNode")
			if inspectErr != nil {
				diagnostic, _ := InspectProxyPayloadForIOS([]byte(fixture), "nodeBundle")
				if diagnostic != nil {
					t.Fatalf("inspect: %v; report: %s", inspectErr, diagnostic.Value)
				}
				t.Fatalf("inspect: %v", inspectErr)
			}
			report := decodeProxyImportReport(t, box)
			if len(report.Proxies) != 1 || len(report.Skipped) != 0 {
				t.Fatalf("report = %#v", report)
			}
		})
	}
}

func TestImportsRealShadowrocketExporterFixturesForEveryCanonicalProtocol(t *testing.T) {
	contents, err := os.ReadFile("testdata/shadowrocket-2.2.90-3378.json")
	if err != nil {
		t.Fatal(err)
	}
	var document shadowrocketFixtureDocument
	if err := json.Unmarshal(contents, &document); err != nil {
		t.Fatalf("decode fixture document: %v", err)
	}
	if document.Source.Version != "2.2.90" || document.Source.Build != "3378" ||
		document.Source.BinarySHA256 != "56682316baf087eff7f784f72523f39a18be4facfb0ab30e771ac5b3d0577015" {
		t.Fatalf("unexpected Shadowrocket source identity: %#v", document.Source)
	}
	if len(document.Fixtures) != 17 {
		t.Fatalf("fixture count = %d, want 17 canonical protocols", len(document.Fixtures))
	}
	seen := make(map[string]bool, len(document.Fixtures))
	for _, fixture := range document.Fixtures {
		fixture := fixture
		t.Run(fixture.CanonicalType+"/"+fixture.Variant, func(t *testing.T) {
			if seen[fixture.CanonicalType] {
				t.Fatalf("duplicate canonical fixture %q", fixture.CanonicalType)
			}
			seen[fixture.CanonicalType] = true
			box, inspectErr := InspectProxyPayloadForIOS([]byte(fixture.Exported), "singleNode")
			if inspectErr != nil {
				diagnostic, _ := InspectProxyPayloadForIOS([]byte(fixture.Exported), "nodeBundle")
				if diagnostic != nil {
					t.Fatalf("inspect Shadowrocket export: %v; report: %s", inspectErr, diagnostic.Value)
				}
				t.Fatalf("inspect Shadowrocket export: %v", inspectErr)
			}
			proxy := decodeProxyImportReport(t, box).Proxies[0]
			for path, want := range fixture.Expected {
				got, exists := nestedProxyValue(proxy, path)
				if !exists || !reflect.DeepEqual(got, want) {
					t.Errorf("%s = %#v (exists %t), want %#v; proxy = %#v", path, got, exists, want, proxy)
				}
			}
			if fixture.SourceInput != "" {
				sourceBox, sourceErr := InspectProxyPayloadForIOS([]byte(fixture.SourceInput), "singleNode")
				if sourceErr != nil {
					t.Fatalf("inspect the source format accepted by Shadowrocket: %v", sourceErr)
				}
				if sourceType := decodeProxyImportReport(t, sourceBox).Proxies[0]["type"]; sourceType != fixture.CanonicalType {
					t.Fatalf("source input type = %#v, want %q", sourceType, fixture.CanonicalType)
				}
			}
		})
	}
	for _, canonical := range []string{
		"vmess", "http", "socks5", "ssr", "trojan", "ss", "snell", "vless", "hysteria",
		"hysteria2", "tuic", "wireguard", "masque", "ssh", "anytls", "trusttunnel", "mieru",
	} {
		if !seen[canonical] {
			t.Errorf("missing Shadowrocket exporter fixture for %q", canonical)
		}
	}
}

func TestImportsEveryRealShadowrocketExportFromOneBase64SubscriptionBundle(t *testing.T) {
	payload, err := os.ReadFile("testdata/shadowrocket-2.2.90-3378.json")
	if err != nil {
		t.Fatalf("read fixture corpus: %v", err)
	}
	var document shadowrocketFixtureDocument
	if err := json.Unmarshal(payload, &document); err != nil {
		t.Fatalf("decode fixture corpus: %v", err)
	}
	links := make([]string, 0, len(document.Fixtures))
	for _, fixture := range document.Fixtures {
		links = append(links, fixture.Exported)
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n")))
	box, err := InspectProxyPayloadForIOS([]byte(encoded), "subscriptionBody")
	if err != nil {
		t.Fatalf("inspect base64 Shadowrocket bundle: %v", err)
	}
	report := decodeProxyImportReport(t, box)
	if report.Format != "base64-share-links" || len(report.Proxies) != 17 || len(report.Skipped) != 0 {
		t.Fatalf("report = %#v", report)
	}
	for index, fixture := range document.Fixtures {
		if got := report.Proxies[index]["type"]; got != fixture.CanonicalType {
			t.Errorf("proxy %d type = %#v, want %q", index, got, fixture.CanonicalType)
		}
		assertProxyFields(t, report.Proxies[index], fixture.Expected)
	}
}

// Fields an exporter writes that mihomo has nowhere to put arrive as notices,
// and the node arrives with them.
//
// This gate asserted the opposite until 2026-08-28: each of these refused the
// whole node, and the two cases removed from the list below -- a WireGuard link
// carrying sni, an AnyTLS link carrying keepalive -- were refused for naming a
// layer their outbound does not have. The reader's ruling that day was that
// there is no "recognized but unsupported" outcome: parse what can be parsed,
// skip what cannot, and count what was skipped. A field with nowhere to go is
// not a reason to throw away a node that would have connected.
//
// What stays here is the other shape: a field that changes the bytes on the
// wire. A snell link naming a plugin we cannot build, a trojan obfs mode that
// is not websocket -- drop those and the node still looks like a node but no
// longer talks to that server. Those are skipped, with the reason.
func TestFieldsThatChangeTheWireAreSkippedAndOthersArrive(t *testing.T) {
	const masquePublic = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEr%2BS%2B1lurxAxUbuPi4RhUv%2FaZ5CVG%2FBr79BRi0b%2BQX%2B7oBc5Yx2eQ7OMYFGQ6%2BlqPLWkEr1pl1nZg%2BRoEzg1Jqg%3D%3D"
	const masquePrivate = "MHcCAQEEIIDzwMdDFdFe3jj4vanTuI2sdBFaUjjPnV%2F68XaVWfwfoAoGCCqGSM49AwEHoUQDQgAEr%2BS%2B1lurxAxUbuPi4RhUv%2FaZ5CVG%2FBr79BRi0b%2BQX%2B7oBc5Yx2eQ7OMYFGQ6%2BlqPLWkEr1pl1nZg%2BRoEzg1Jqg%3D%3D"
	tests := []struct {
		name  string
		link  string
		field string
	}{
		{
			name:  "Snell custom simple-obfs URI",
			link:  "snell://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpzZWNyZXQ@example.invalid:443?plugin=obfs-local;obfs%3Dtls;obfs-host%3Dcdn.example.invalid;obfs-uri%3D/ray&version=4#snell",
			field: "obfs-uri",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			box, err := InspectProxyPayloadForIOS([]byte(test.link), "nodeBundle")
			if err != nil {
				t.Fatalf("inspect: %v", err)
			}
			report := decodeProxyImportReport(t, box)
			if len(report.Proxies) != 0 || len(report.Skipped) != 1 {
				t.Fatalf("report = %#v", report)
			}
			issue := report.Skipped[0]
			if issue.Code != "recognizedUnsupportedField" || !strings.Contains(issue.Message, test.field) {
				t.Fatalf("issue = %#v, want field %q", issue, test.field)
			}
		})
	}
}

// The second half of this test asserted a refusal until 2026-09-02: a body key
// this build did not list threw the node away. That is the day a person's
// subscription arrived with `"class": 0` on every node and none of them
// imported, while upstream -- which decodes the same body and reads only the
// keys it knows -- built all seven. The reader's ruling: the same rule as the
// query keys, for every JSON body this importer reads. The node arrives; the
// key is named as not honoured, under the node's name, so it is louder than
// upstream and no longer stricter.
func TestVMessBase64JSONConsumesDeepFieldsAndReportsUnknownChildren(t *testing.T) {
	const pin = "65b3acd7db555768304a16abb6f4366c1a0c0bb5cec81429617f0150d7d66726"
	jsonFixture := `{"v":"2","ps":"vmess-json-deep","add":"example.invalid","port":"443",` +
		`"id":"b831381d-6324-4d53-ad4f-8cda48b30811","aid":"0","scy":"auto","net":"ws","type":"none",` +
		`"host":"cdn.example.invalid","path":"/ray","tls":"reality","sni":"sni.example.invalid",` +
		`"alpn":"h2,http/1.1","allowInsecure":true,"fp":"chrome","hpkp":"` + pin + `",` +
		`"pbk":"ppQ9FwLrLIa0AOrp1WvcyiaQ37vg2WSy_CD4bIdiTUw","sid":"6ba85179f3a2b4c5","tfo":true}`
	link := "vmess://" + base64.StdEncoding.EncodeToString([]byte(jsonFixture))
	box, err := InspectProxyPayloadForIOS([]byte(link), "singleNode")
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	proxy := decodeProxyImportReport(t, box).Proxies[0]
	want := map[string]any{
		"type": "vmess", "network": "ws", "tls": true, "servername": "sni.example.invalid",
		"skip-cert-verify": true, "client-fingerprint": "chrome", "fingerprint": pin, "tfo": true,
		"reality-opts.public-key": "ppQ9FwLrLIa0AOrp1WvcyiaQ37vg2WSy_CD4bIdiTUw",
		"reality-opts.short-id":   "6ba85179f3a2b4c5",
	}
	for path, expected := range want {
		got, exists := nestedProxyValue(proxy, path)
		if !exists || !reflect.DeepEqual(got, expected) {
			t.Errorf("%s = %#v (exists %t), want %#v; proxy = %#v", path, got, exists, expected, proxy)
		}
	}

	unknownJSON := strings.TrimSuffix(jsonFixture, "}") + `,"unknownTLSChild":true}`
	unknownLink := "vmess://" + base64.StdEncoding.EncodeToString([]byte(unknownJSON))
	reportBox, err := InspectProxyPayloadForIOS([]byte(unknownLink), "nodeBundle")
	if err != nil {
		t.Fatalf("inspect unknown child: %v", err)
	}
	report := decodeProxyImportReport(t, reportBox)
	if len(report.Proxies) != 1 || len(report.Skipped) != 0 {
		t.Fatalf("a body key this build does not map must not cost the node: %#v", report)
	}
	if len(report.NotHonoured) != 1 ||
		report.NotHonoured[0].Message != "hako: proxy field vmess.base64-json.unknownTLSChild: not mapped by this importer build" ||
		report.NotHonoured[0].Proxy != "vmess-json-deep" || report.NotHonoured[0].Code != "fieldNotHonoured" {
		t.Fatalf("the key must be named as not honoured, under the node's name: %#v", report.NotHonoured)
	}
	// The node that arrived is the node the known keys describe; the unknown
	// key changed nothing on it.
	for path, expected := range want {
		got, exists := nestedProxyValue(report.Proxies[0], path)
		if !exists || !reflect.DeepEqual(got, expected) {
			t.Errorf("%s = %#v (exists %t), want %#v; proxy = %#v", path, got, exists, expected, report.Proxies[0])
		}
	}
}

func TestEveryCanonicalImportProtocolPreservesItsDeepConnectionFields(t *testing.T) {
	const certificatePin = "65b3acd7db555768304a16abb6f4366c1a0c0bb5cec81429617f0150d7d66726"
	privateKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	publicKeyBytes := make([]byte, 32)
	publicKeyBytes[0] = 1
	publicKey := base64.StdEncoding.EncodeToString(publicKeyBytes)

	masqueKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	masquePrivate, err := x509.MarshalECPrivateKey(masqueKey)
	if err != nil {
		t.Fatal(err)
	}
	masquePublic, err := x509.MarshalPKIXPublicKey(&masqueKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	ssPassword := base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:secret"))
	ssrPassword := base64.RawURLEncoding.EncodeToString([]byte("secret"))
	ssrPayload := "example.invalid:443:origin:aes-256-cfb:plain:" + ssrPassword +
		"/?obfsparam=" + base64.RawURLEncoding.EncodeToString([]byte("cdn.example.invalid")) +
		"&protoparam=" + base64.RawURLEncoding.EncodeToString([]byte("protocol-value")) +
		"&remarks=" + base64.RawURLEncoding.EncodeToString([]byte("ssr-deep")) +
		"&group=" + base64.RawURLEncoding.EncodeToString([]byte("metadata-only"))

	trustTunnelPayload := appendTLV(nil, 0x01, []byte("vpn.example.invalid"))
	trustTunnelPayload = appendTLV(trustTunnelPayload, 0x02, []byte("198.51.100.7:443"))
	trustTunnelPayload = appendTLV(trustTunnelPayload, 0x03, []byte("sni.example.invalid"))
	trustTunnelPayload = appendTLV(trustTunnelPayload, 0x05, []byte("user"))
	trustTunnelPayload = appendTLV(trustTunnelPayload, 0x06, []byte("secret"))
	trustTunnelPayload = appendTLV(trustTunnelPayload, 0x07, []byte{1})
	trustTunnelPayload = appendTLV(trustTunnelPayload, 0x09, []byte{2})
	trustTunnelPayload = appendTLV(trustTunnelPayload, 0x0c, []byte("trusttunnel-deep"))

	tests := []struct {
		canonical string
		link      string
		want      map[string]any
	}{
		{
			canonical: "vmess",
			link: "vmess://YXV0bzpiODMxMzgxZC02MzI0LTRkNTMtYWQ0Zi04Y2RhNDhiMzA4MTFAZXhhbXBsZS5pbnZhbGlkOjQ0Mw" +
				"?remarks=vmess-deep&tls=1&peer=sni.example.invalid&allowInsecure=1&alpn=h2,http%2F1.1" +
				"&fp=chrome&pcs=sha256%2Fpin&obfs=websocket&obfsParam=cdn.example.invalid&path=%2Fray&tfo=1",
			want: map[string]any{
				"type": "vmess", "tls": true, "servername": "sni.example.invalid",
				"skip-cert-verify": true, "alpn": []any{"h2", "http/1.1"},
				"client-fingerprint": "chrome", "fingerprint": "sha256/pin", "network": "ws", "tfo": true,
				"ws-opts.path": "/ray", "ws-opts.headers.Host": "cdn.example.invalid",
			},
		},
		{
			canonical: "http",
			link:      "https://user:secret@example.invalid:443?peer=sni.example.invalid&allowInsecure=1&fingerprint=" + certificatePin + "&tfo=1#http-deep",
			want: map[string]any{
				"type": "http", "tls": true, "sni": "sni.example.invalid", "skip-cert-verify": true,
				"fingerprint": certificatePin, "tfo": true,
			},
		},
		{
			canonical: "socks5",
			link:      "socks5://user:secret@example.invalid:1080?tls=1&allowInsecure=1&fingerprint=" + certificatePin + "&udp=1&tfo=1#socks-deep",
			want: map[string]any{
				"type": "socks5", "tls": true, "skip-cert-verify": true,
				"fingerprint": certificatePin, "udp": true, "tfo": true,
			},
		},
		{
			canonical: "ssr",
			link:      "ssr://" + base64.RawURLEncoding.EncodeToString([]byte(ssrPayload)),
			want: map[string]any{
				"type": "ssr", "obfs-param": "cdn.example.invalid", "protocol-param": "protocol-value",
			},
		},
		{
			canonical: "trojan",
			link: "trojan://secret@example.invalid:443?peer=sni.example.invalid&allow_insecure=1&alpn=h2,http%2F1.1" +
				"&fp=chrome&pcs=sha256%2Fpin&security=reality&pbk=ppQ9FwLrLIa0AOrp1WvcyiaQ37vg2WSy_CD4bIdiTUw" +
				"&sid=6ba85179f3a2b4c5&plugin=obfs-local;obfs%3Dwebsocket;obfs-host%3Dcdn.example.invalid;obfs-uri%3D/socket&tfo=1#trojan-deep",
			want: map[string]any{
				"type": "trojan", "sni": "sni.example.invalid", "skip-cert-verify": true,
				"alpn": []any{"h2", "http/1.1"}, "client-fingerprint": "chrome", "fingerprint": "sha256/pin",
				"reality-opts.public-key": "ppQ9FwLrLIa0AOrp1WvcyiaQ37vg2WSy_CD4bIdiTUw",
				"reality-opts.short-id":   "6ba85179f3a2b4c5", "network": "ws",
				"ws-opts.path": "/socket", "ws-opts.headers.Host": "cdn.example.invalid", "tfo": true,
			},
		},
		{
			canonical: "ss",
			link: "ss://" + ssPassword + "@example.invalid:8388?udp-over-tcp=true" +
				"&plugin=obfs-local%3Bobfs%3Dtls%3Bobfs-host%3Dcdn.example.invalid&tfo=1#ss-deep",
			want: map[string]any{
				"type": "ss", "udp-over-tcp": true, "plugin": "obfs",
				"plugin-opts.mode": "tls", "plugin-opts.host": "cdn.example.invalid", "tfo": true,
			},
		},
		{
			canonical: "snell",
			link:      "snell://secret@example.invalid:443?version=4&udp=1&reuse=1&obfs=tls&obfsParam=cdn.example.invalid&tfo=1#snell-deep",
			want: map[string]any{
				"type": "snell", "version": float64(4), "udp": true, "reuse": true,
				"obfs-opts.mode": "tls", "obfs-opts.host": "cdn.example.invalid", "tfo": true,
			},
		},
		{
			canonical: "vless",
			link: "vless://a1b2c3d4-eacc-4433-981b-7e5f9a8b0000@example.invalid:443?encryption=none&security=reality" +
				"&type=tcp&sni=sni.example.invalid&fp=chrome&pbk=ppQ9FwLrLIa0AOrp1WvcyiaQ37vg2WSy_CD4bIdiTUw" +
				"&sid=6ba85179f3a2b4c5&flow=xtls-rprx-vision&alpn=h2,http%2F1.1&allowInsecure=1&tfo=1#vless-deep",
			want: map[string]any{
				"type": "vless", "tls": true, "servername": "sni.example.invalid", "flow": "xtls-rprx-vision",
				"alpn": []any{"h2", "http/1.1"}, "client-fingerprint": "chrome", "skip-cert-verify": true,
				"reality-opts.public-key": "ppQ9FwLrLIa0AOrp1WvcyiaQ37vg2WSy_CD4bIdiTUw",
				"reality-opts.short-id":   "6ba85179f3a2b4c5", "tfo": true,
			},
		},
		{
			canonical: "hysteria",
			link:      "hysteria://secret@example.invalid:443?peer=sni.example.invalid&allowInsecure=1&upmbps=10&downmbps=20&obfs=xplus&alpn=h3&pinSHA256=" + certificatePin + "&tfo=1#hysteria-deep",
			want: map[string]any{
				"type": "hysteria", "sni": "sni.example.invalid", "skip-cert-verify": true,
				"up": "10", "down": "20", "obfs": "xplus", "alpn": []any{"h3"},
				"fingerprint": certificatePin, "tfo": true,
			},
		},
		{
			canonical: "hysteria2",
			link:      "hysteria2://secret@example.invalid:443?peer=sni.example.invalid&allowInsecure=1&upmbps=10&downmbps=20&obfs=salamander&obfsParam=obfs-secret&alpn=h3&pinSHA256=" + certificatePin + "&tfo=1#hy2-deep",
			want: map[string]any{
				"type": "hysteria2", "sni": "sni.example.invalid", "skip-cert-verify": true,
				"up": "10", "down": "20", "obfs": "salamander", "obfs-password": "obfs-secret",
				"alpn": []any{"h3"}, "fingerprint": certificatePin, "tfo": true,
			},
		},
		{
			canonical: "tuic",
			link: "tuic://00000000-0000-0000-0000-000000000001:secret@example.invalid:443?peer=sni.example.invalid" +
				"&allow_insecure=1&proto=bbr&udp=native&alpn=h3&pinSHA256=" + certificatePin + "&disable_sni=0&tfo=1#tuic-deep",
			want: map[string]any{
				"type": "tuic", "sni": "sni.example.invalid", "skip-cert-verify": true,
				"congestion-controller": "bbr", "udp-relay-mode": "native", "alpn": []any{"h3"},
				"fingerprint": certificatePin, "tfo": true,
			},
		},
		{
			canonical: "wireguard",
			link: "wireguard://example.invalid:51820?publicKey=" + urlQueryEscape(publicKey) +
				"&privateKey=" + urlQueryEscape(privateKey) + "&ip=10.0.0.2%2F32,2001%3Adb8%3A%3A2%2F128" +
				"&presharedKey=" + urlQueryEscape(privateKey) + "&mtu=1280&keepalive=25&dns=1.1.1.1,2606%3A4700%3A4700%3A%3A1111&reserved=1,2,3&tfo=1#wireguard-deep",
			want: map[string]any{
				"type": "wireguard", "ip": "10.0.0.2/32", "ipv6": "2001:db8::2/128",
				"pre-shared-key": privateKey, "mtu": float64(1280), "persistent-keepalive": float64(25),
				"dns": []any{"1.1.1.1", "2606:4700:4700::1111"}, "reserved": "AQID", "tfo": true,
			},
		},
		{
			canonical: "masque",
			link: "masque://example.invalid:443?privateKey=" + urlQueryEscape(base64.StdEncoding.EncodeToString(masquePrivate)) +
				"&publicKey=" + urlQueryEscape(base64.StdEncoding.EncodeToString(masquePublic)) +
				"&ip=10.0.0.2%2F32,2001%3Adb8%3A%3A2%2F128&peer=sni.example.invalid&allowInsecure=1" +
				"&uri=%2F.well-known%2Fmasque&mtu=1280&proto=h3-l4proxy&tfo=1#masque-deep",
			want: map[string]any{
				"type": "masque", "ip": "10.0.0.2/32", "ipv6": "2001:db8::2/128",
				"sni": "sni.example.invalid", "skip-cert-verify": true, "uri": "/.well-known/masque",
				"mtu": float64(1280), "network": "h3-l4proxy", "tfo": true,
			},
		},
		{
			canonical: "ssh",
			link:      "ssh://user@example.invalid:22?password=secret&tfo=1#ssh-deep",
			want: map[string]any{
				"type": "ssh", "username": "user", "password": "secret", "tfo": true,
			},
		},
		{
			canonical: "anytls",
			link:      "anytls://secret@example.invalid:443?peer=sni.example.invalid&allowInsecure=1&alpn=h2,http%2F1.1&hpkp=sha256%2Fpin&fp=chrome&tfo=1#anytls-deep",
			want: map[string]any{
				"type": "anytls", "sni": "sni.example.invalid", "skip-cert-verify": true,
				"alpn": []any{"h2", "http/1.1"}, "fingerprint": "sha256/pin", "client-fingerprint": "chrome", "tfo": true,
			},
		},
		{
			canonical: "trusttunnel",
			link:      "tt://?" + base64.RawURLEncoding.EncodeToString(trustTunnelPayload),
			want: map[string]any{
				"type": "trusttunnel", "sni": "sni.example.invalid", "skip-cert-verify": true,
				"quic": true, "alpn": []any{"h3"},
			},
		},
		{
			canonical: "mieru",
			link: "mierus://user:secret@example.invalid:443?proto=TCP&profile=mieru-deep" +
				"&multiplexing=MULTIPLEXING_HIGH&handshake-mode=HANDSHAKE_NO_WAIT&traffic-pattern=CCoQARoECAEQCiIYCAMQASoIMDAwMTAyMDMqCDA0MDUwNjA3&tfo=1#mieru-deep",
			want: map[string]any{
				"type": "mieru", "transport": "TCP", "multiplexing": "MULTIPLEXING_HIGH",
				"handshake-mode": "HANDSHAKE_NO_WAIT", "traffic-pattern": "CCoQARoECAEQCiIYCAMQASoIMDAwMTAyMDMqCDA0MDUwNjA3", "tfo": true,
			},
		},
	}

	if len(tests) != 17 {
		t.Fatalf("deep protocol fixture count = %d, want 17", len(tests))
	}
	seen := make(map[string]bool, len(tests))
	for _, test := range tests {
		t.Run(test.canonical, func(t *testing.T) {
			if seen[test.canonical] {
				t.Fatalf("duplicate canonical protocol fixture %q", test.canonical)
			}
			seen[test.canonical] = true
			box, inspectErr := InspectProxyPayloadForIOS([]byte(test.link), "singleNode")
			if inspectErr != nil {
				diagnostic, _ := InspectProxyPayloadForIOS([]byte(test.link), "nodeBundle")
				if diagnostic != nil {
					t.Fatalf("inspect: %v; report: %s", inspectErr, diagnostic.Value)
				}
				t.Fatalf("inspect: %v", inspectErr)
			}
			proxy := decodeProxyImportReport(t, box).Proxies[0]
			for path, want := range test.want {
				got, exists := nestedProxyValue(proxy, path)
				if !exists || !reflect.DeepEqual(got, want) {
					t.Errorf("%s = %#v (exists %t), want %#v; proxy = %#v", path, got, exists, want, proxy)
				}
			}
		})
	}
	wantCanonical := []string{
		"vmess", "http", "socks5", "ssr", "trojan", "ss", "snell", "vless", "hysteria",
		"hysteria2", "tuic", "wireguard", "masque", "ssh", "anytls", "trusttunnel", "mieru",
	}
	for _, canonical := range wantCanonical {
		if !seen[canonical] {
			t.Errorf("canonical protocol %q has no deep import fixture", canonical)
		}
	}
}

// Every canonical protocol names a field it could not consume, and imports the
// node anyway.
//
// This asserted the refusal until 2026-08-28, across all seventeen protocols,
// which is why the defect it encoded was seventeen protocols wide: an exporter
// inventing one key cost the node on every one of them. The reader's ruling is
// that there is no such outcome -- parse what parses, and say what was left
// behind.
//
// Naming it is still required, and is the half that must not be lost. A field
// dropped in silence produces a node that looks right and behaves differently,
// and the person has nothing to connect the behaviour back to.
func TestEveryCanonicalImportProtocolNamesAnUnconsumedSemanticField(t *testing.T) {
	privateKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	publicKeyBytes := make([]byte, 32)
	publicKeyBytes[0] = 1
	publicKey := base64.StdEncoding.EncodeToString(publicKeyBytes)
	ssPassword := base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:secret"))
	const masqueValidPublic = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEr+S+1lurxAxUbuPi4RhUv/aZ5CVG/Br79BRi0b+QX+7oBc5Yx2eQ7OMYFGQ6+lqPLWkEr1pl1nZg+RoEzg1Jqg=="
	const masqueValidPrivate = "MHcCAQEEIIDzwMdDFdFe3jj4vanTuI2sdBFaUjjPnV/68XaVWfwfoAoGCCqGSM49AwEHoUQDQgAEr+S+1lurxAxUbuPi4RhUv/aZ5CVG/Br79BRi0b+QX+7oBc5Yx2eQ7OMYFGQ6+lqPLWkEr1pl1nZg+RoEzg1Jqg=="
	ssrPassword := base64.RawURLEncoding.EncodeToString([]byte("secret"))
	ssrPayload := "example.invalid:443:origin:aes-256-cfb:plain:" + ssrPassword +
		"/?remarks=" + base64.RawURLEncoding.EncodeToString([]byte("ssr")) + "&hako_unknown_semantic=1"

	fixtures := map[string]string{
		"vmess":     "vmess://YXV0bzpiODMxMzgxZC02MzI0LTRkNTMtYWQ0Zi04Y2RhNDhiMzA4MTFAZXhhbXBsZS5pbnZhbGlkOjQ0Mw?remarks=vmess&hako_unknown_semantic=1",
		"http":      "http://user:secret@example.invalid:8080?hako_unknown_semantic=1#http",
		"socks5":    "socks5://user:secret@example.invalid:1080?hako_unknown_semantic=1#socks5",
		"ssr":       "ssr://" + base64.RawURLEncoding.EncodeToString([]byte(ssrPayload)),
		"trojan":    "trojan://secret@example.invalid:443?hako_unknown_semantic=1#trojan",
		"ss":        "ss://" + ssPassword + "@example.invalid:8388?hako_unknown_semantic=1#ss",
		"snell":     "snell://secret@example.invalid:443?version=4&hako_unknown_semantic=1#snell",
		"vless":     "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.invalid:443?type=tcp&hako_unknown_semantic=1#vless",
		"hysteria":  "hysteria://secret@example.invalid:443?upmbps=10&downmbps=20&hako_unknown_semantic=1#hysteria",
		"hysteria2": "hysteria2://secret@example.invalid:443?hako_unknown_semantic=1#hysteria2",
		"tuic":      "tuic://00000000-0000-0000-0000-000000000001:secret@example.invalid:443?hako_unknown_semantic=1#tuic",
		"wireguard": "wireguard://example.invalid:51820?publicKey=" + urlQueryEscape(publicKey) +
			"&privateKey=" + urlQueryEscape(privateKey) + "&ip=10.0.0.2%2F32&hako_unknown_semantic=1#wireguard",
		// The keys are real ones. They were `unused` until 2026-08-28 and that
		// went unnoticed for as long as the unknown-field refusal fired first:
		// the record never reached the kernel, so nothing ever decoded them.
		"masque": "masque://example.invalid:443?privateKey=" + urlQueryEscape(masqueValidPrivate) +
			"&publicKey=" + urlQueryEscape(masqueValidPublic) + "&ip=10.0.0.2%2F32" +
			"&hako_unknown_semantic=1#masque",
		"ssh":         "ssh://user:secret@example.invalid:22?hako_unknown_semantic=1#ssh",
		"anytls":      "anytls://secret@example.invalid:443?hako_unknown_semantic=1#anytls",
		"trusttunnel": "tt://user:secret@example.invalid:443?hako_unknown_semantic=1#tt",
		"mieru":       "mierus://user:secret@example.invalid:443?proto=TCP&profile=profile&hako_unknown_semantic=1#mieru",
	}
	if len(fixtures) != 17 {
		t.Fatalf("unknown-field fixture count = %d, want 17", len(fixtures))
	}
	for canonical, fixture := range fixtures {
		t.Run(canonical, func(t *testing.T) {
			box, err := InspectProxyPayloadForIOS([]byte(fixture), "nodeBundle")
			if err != nil {
				t.Fatalf("inspect: %v", err)
			}
			report := decodeProxyImportReport(t, box)
			if len(report.Proxies) != 1 || len(report.Skipped) != 0 {
				t.Fatalf("an unconsumed field cost the node: %#v", report)
			}
			var named bool
			for _, notice := range report.NotHonoured {
				if strings.Contains(notice.Message, "hako_unknown_semantic") {
					named = true
				}
			}
			if !named {
				t.Fatalf("the field was dropped without saying so: %#v", report.NotHonoured)
			}
		})
	}
}

func TestEveryCanonicalImportProtocolRejectsMalformedRequiredFields(t *testing.T) {
	fixtures := map[string]string{
		"vmess":       "vmess://bm90LWpzb24",
		"http":        "http://user:secret@example.invalid#http",
		"socks5":      "socks5://user:secret@example.invalid#socks5",
		"ssr":         "ssr://not-base64",
		"trojan":      "trojan://secret@:443#trojan",
		"ss":          "ss://not-base64@example.invalid:8388#ss",
		"snell":       "snell://@example.invalid:443#snell",
		"vless":       "vless://@example.invalid:443?type=tcp#vless",
		"hysteria":    "hysteria://secret@example.invalid:443#hysteria",
		"hysteria2":   "hysteria2://secret@:443#hysteria2",
		"tuic":        "tuic://example.invalid:443#tuic",
		"wireguard":   "wg://example.invalid:51820?ip=10.0.0.2/32#wireguard",
		"masque":      "masque://example.invalid:443?ip=10.0.0.2/32#masque",
		"ssh":         "ssh://example.invalid:22#ssh",
		"anytls":      "anytls://example.invalid:443#anytls",
		"trusttunnel": "tt://?not-base64",
		"mieru":       "mierus://user:secret@example.invalid?profile=mieru",
	}
	if len(fixtures) != 17 {
		t.Fatalf("malformed fixture count = %d, want 17", len(fixtures))
	}
	for canonical, fixture := range fixtures {
		t.Run(canonical, func(t *testing.T) {
			box, err := InspectProxyPayloadForIOS([]byte(fixture), "nodeBundle")
			if err != nil {
				t.Fatalf("inspect: %v", err)
			}
			report := decodeProxyImportReport(t, box)
			if len(report.Proxies) != 0 || len(report.Skipped) != 1 {
				t.Fatalf("report = %#v", report)
			}
			if report.Skipped[0].Code != "malformedRecord" && report.Skipped[0].Code != "coreRejected" {
				t.Fatalf("issue = %#v", report.Skipped[0])
			}
		})
	}
}

func TestNestedTLSContainersPreserveRealityAndNameUnknownChildren(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		want    map[string]any
	}{
		{
			name: "sing-box reality and utls",
			payload: `{"outbounds":[{"type":"vless","tag":"Sing TLS","server":"sing.example.invalid","server_port":443,` +
				`"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","tls":{"enabled":true,"server_name":"sni.example.invalid",` +
				`"insecure":true,"alpn":["h2","http/1.1"],"utls":{"enabled":true,"fingerprint":"chrome"},` +
				`"reality":{"enabled":true,"public_key":"ppQ9FwLrLIa0AOrp1WvcyiaQ37vg2WSy_CD4bIdiTUw","short_id":"6ba85179f3a2b4c5"}},` +
				`"transport":{"type":"ws","path":"/ray","headers":{"Host":"cdn.example.invalid"},"max_early_data":2048,"early_data_header_name":"Sec-WebSocket-Protocol"}}]}`,
			want: map[string]any{
				"tls": true, "servername": "sni.example.invalid", "skip-cert-verify": true,
				"alpn": []any{"h2", "http/1.1"}, "client-fingerprint": "chrome",
				"reality-opts.public-key": "ppQ9FwLrLIa0AOrp1WvcyiaQ37vg2WSy_CD4bIdiTUw",
				"reality-opts.short-id":   "6ba85179f3a2b4c5", "network": "ws", "ws-opts.path": "/ray",
				"ws-opts.headers.Host": "cdn.example.invalid", "ws-opts.max-early-data": float64(2048),
				"ws-opts.early-data-header-name": "Sec-WebSocket-Protocol",
			},
		},
		{
			name: "v2ray reality and websocket",
			payload: `{"outbounds":[{"tag":"V2Ray TLS","protocol":"vless","settings":{"vnext":[{"address":"v2ray.example.invalid",` +
				`"port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","flow":"xtls-rprx-vision"}]}]},` +
				`"streamSettings":{"network":"ws","security":"reality","realitySettings":{"serverName":"sni.example.invalid",` +
				`"fingerprint":"chrome","publicKey":"ppQ9FwLrLIa0AOrp1WvcyiaQ37vg2WSy_CD4bIdiTUw","shortId":"6ba85179f3a2b4c5"},` +
				`"wsSettings":{"path":"/ray","headers":{"Host":"cdn.example.invalid"},"maxEarlyData":2048,"earlyDataHeaderName":"Sec-WebSocket-Protocol"}}}]}`,
			want: map[string]any{
				"tls": true, "servername": "sni.example.invalid", "client-fingerprint": "chrome",
				"reality-opts.public-key": "ppQ9FwLrLIa0AOrp1WvcyiaQ37vg2WSy_CD4bIdiTUw",
				"reality-opts.short-id":   "6ba85179f3a2b4c5", "network": "ws", "ws-opts.path": "/ray",
				"ws-opts.headers.Host": "cdn.example.invalid", "ws-opts.max-early-data": float64(2048),
				"ws-opts.early-data-header-name": "Sec-WebSocket-Protocol",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			box, err := InspectProxyPayloadForIOS([]byte(test.payload), "subscriptionBody")
			if err != nil {
				t.Fatalf("inspect: %v", err)
			}
			proxy := decodeProxyImportReport(t, box).Proxies[0]
			for path, want := range test.want {
				got, exists := nestedProxyValue(proxy, path)
				if !exists || !reflect.DeepEqual(got, want) {
					t.Errorf("%s = %#v (exists %t), want %#v; proxy = %#v", path, got, exists, want, proxy)
				}
			}
		})
	}

	// A TLS child this build does not map. Until 2026-09-02 these two were in
	// the list below and refused the outbound, on the argument that a TLS
	// child we cannot read describes security we cannot provide. The reader's
	// ruling that day put them with the query keys instead: the node arrives
	// with the TLS it did ask for, and the key it also asked for is named as
	// not honoured -- said, not silently dropped, and not a reason to lose a
	// node whose every other field this build reads.
	unknownChildren := []struct {
		payload string
		notice  string
	}{
		{
			payload: `{"outbounds":[{"type":"vless","tag":"Sing","server":"sing.example.invalid","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","tls":{"enabled":true,"unknown_tls_child":true}}]}`,
			notice:  "hako: proxy field sing-box.outbound.tls.unknown_tls_child: not mapped by this importer build",
		},
		{
			payload: `{"outbounds":[{"tag":"V2Ray","protocol":"vless","settings":{"vnext":[{"address":"v2ray.example.invalid","port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"unknownTLSChild":true}}}]}`,
			notice:  "hako: proxy field v2ray.outbound.streamSettings.tlsSettings.unknownTLSChild: not mapped by this importer build",
		},
	}
	for index, test := range unknownChildren {
		t.Run("name unknown child "+strconv.Itoa(index), func(t *testing.T) {
			box, err := InspectProxyPayloadForIOS([]byte(test.payload), "subscriptionBody")
			if err != nil {
				t.Fatalf("inspect: %v", err)
			}
			report := decodeProxyImportReport(t, box)
			if len(report.Proxies) != 1 || len(report.Skipped) != 0 {
				t.Fatalf("an outbound with a TLS child this build does not map must still become a node: %#v", report)
			}
			if got := report.Proxies[0]["tls"]; got != true {
				t.Fatalf("the TLS the outbound did ask for must survive: %#v", report.Proxies[0])
			}
			if len(report.NotHonoured) != 1 || report.NotHonoured[0].Message != test.notice ||
				report.NotHonoured[0].Proxy != report.Proxies[0]["name"] {
				t.Fatalf("the child must be named, under the node's name: %#v", report.NotHonoured)
			}
		})
	}

	// A child that is not the shape the dialect defines, or that names a
	// layer the outbound does not have. There is no reading of these that
	// builds the node the file describes.
	unreadableChildren := []string{
		`{"outbounds":[{"type":"vless","tag":"Sing","server":"sing.example.invalid","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","tls":true}]}`,
		`{"outbounds":[{"type":"vless","tag":"Sing","server":"sing.example.invalid","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","tls":{"enabled":true,"utls":{"enabled":false,"fingerprint":"chrome"}}}]}`,
		`{"outbounds":[{"type":"vless","tag":"Sing","server":"sing.example.invalid","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","transport":{"type":"ws","path":"/ray","headers":"Host: cdn.example.invalid"}}]}`,
		`{"outbounds":[{"tag":"V2Ray","protocol":"vless","settings":{"vnext":[{"address":"v2ray.example.invalid","port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]},"streamSettings":true}]}`,
		`{"outbounds":[{"tag":"V2Ray SS","protocol":"shadowsocks","settings":{"servers":[{"address":"ss.example.invalid","port":8388,"method":"aes-128-gcm","password":"secret"}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"publicKey":"ppQ9FwLrLIa0AOrp1WvcyiaQ37vg2WSy_CD4bIdiTUw"}}}]}`,
	}
	// What each of these must never do is become a node. `"tls": true` where an
	// object goes, a headers string, uTLS children under a disabled uTLS, Reality
	// on a shadowsocks outbound: importing the outbound without them hands the
	// person a node whose protection differs from the document they were given
	// -- quietly, and in the direction that costs them.
	//
	// The outcome changed shape on 2026-08-28 and the invariant did not. These
	// used to fail the whole payload; a container-format record that cannot be
	// read is now skipped with its reason, so the assertion is that the record
	// produced no node and said why. Checking only for an error would have
	// started passing against an importer that dropped the child and imported
	// the node, as long as something else in the payload failed.
	for index, payload := range unreadableChildren {
		t.Run("reject unreadable child "+strconv.Itoa(index), func(t *testing.T) {
			box, err := InspectProxyPayloadForIOS([]byte(payload), "subscriptionBody")
			if err != nil {
				if !strings.Contains(err.Error(), "unknown") && !strings.Contains(err.Error(), "unsupported") {
					t.Fatalf("error = %v", err)
				}
				return
			}
			report := decodeProxyImportReport(t, box)
			if len(report.Proxies) != 0 {
				t.Fatalf("an outbound with an unreadable child became a node: %#v", report.Proxies)
			}
			if len(report.Skipped) != 1 {
				t.Fatalf("expected one skip with a reason: %#v", report)
			}
			if message := report.Skipped[0].Message; !strings.Contains(message, "unknown") &&
				!strings.Contains(message, "unsupported") {
				t.Fatalf("the skip does not say the child was unreadable: %q", message)
			}
		})
	}
}

func TestEveryRecognizedUnsupportedSchemeReturnsItsRegistryReason(t *testing.T) {
	for _, capability := range proxyImportCapabilities {
		if capability.Status == proxyImportSupported {
			continue
		}
		t.Run(capability.Scheme, func(t *testing.T) {
			box, err := InspectProxyPayloadForIOS(
				[]byte(capability.Scheme+"://fixture@example.invalid:443"),
				"nodeBundle",
			)
			if err != nil {
				t.Fatalf("inspect: %v", err)
			}
			report := decodeProxyImportReport(t, box)
			if len(report.Skipped) != 1 {
				t.Fatalf("report = %#v", report)
			}
			wantCode := capability.Status
			if wantCode == proxyImportWrapper {
				wantCode = "subscriptionWrapper"
			}
			if got := report.Skipped[0].Code; got != wantCode {
				t.Fatalf("code = %q, want %q", got, wantCode)
			}
		})
	}
}

func TestInspectProxyPayloadForIOSReportsEveryRecordInsteadOfDroppingIt(t *testing.T) {
	payload := []byte("hysteria2://secret@example.invalid:443#accepted\n" +
		"lua://script@example.invalid:443#unsupported\n" +
		"unknown-proxy://secret@example.invalid:443#unknown\n" +
		"vmess://bm90LWpzb24#malformed")
	box, err := InspectProxyPayloadForIOS(payload, "nodeBundle")
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	report := decodeProxyImportReport(t, box)
	if report.Format != "share-links" || report.Context != "nodeBundle" {
		t.Fatalf("identity = %q/%q", report.Format, report.Context)
	}
	if len(report.Proxies) != 1 || report.Proxies[0]["name"] != "accepted" {
		t.Fatalf("proxies = %#v", report.Proxies)
	}
	// Three records did not become nodes, for three different reasons, and they
	// arrive in one array in the order they appeared. The reason is carried by
	// the code; it used to be carried by which of two arrays the entry was in,
	// which is what the client had to undo before it could show them in order.
	if len(report.Skipped) != 3 {
		t.Fatalf("skipped = %#v", report.Skipped)
	}
	for index, want := range []struct{ scheme, code string }{
		{"lua", "coreUnsupported"},
		{"unknown-proxy", "unknownScheme"},
		{"vmess", "malformedRecord"},
	} {
		if report.Skipped[index].Scheme != want.scheme || report.Skipped[index].Code != want.code {
			t.Fatalf("skipped[%d] = %#v, want %s/%s", index, report.Skipped[index], want.scheme, want.code)
		}
		if index > 0 && report.Skipped[index].Index <= report.Skipped[index-1].Index {
			t.Fatalf("skipped is not in the order the records appeared: %#v", report.Skipped)
		}
	}
}

func TestInspectProxyPayloadForIOSExtractsLinksFromHumanTextWithoutSwallowingProse(t *testing.T) {
	// The bracket is paired, because that is what makes it prose. An unpaired
	// closing bracket is what an airport writes at the end of a node's name --
	// `(hy2)`, `(IEPL)` -- and stripping those renamed the person's nodes
	// without telling them. The trim now asks whether an opener is waiting on
	// the same line before the link; the companion case below is the name that
	// must survive.
	payload := []byte("请导入（hysteria2://secret@example.invalid:443#accepted）。\n" +
		"这是一行说明，不是节点。\n" +
		"hysteria2://second@example.invalid:443#second | " +
		"lua://script@example.invalid:443#unsupported，")
	box, err := InspectProxyPayloadForIOS(payload, "nodeBundle")
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	report := decodeProxyImportReport(t, box)
	if len(report.Proxies) != 2 {
		t.Fatalf("proxies = %#v", report.Proxies)
	}
	if got := report.Proxies[0]["name"]; got != "accepted" {
		t.Fatalf("first name = %#v, want accepted", got)
	}
	// The other direction, from a real airport link the macOS lane pasted: the
	// brackets belong to the name and no prose opened them.
	kept, err := InspectProxyPayloadForIOS(
		[]byte("hysteria2://secret@example.invalid:443#\U0001F1EE\U0001F1F314印度-移动/南方联通(hy2)"), "singleNode")
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	keptReport := decodeProxyImportReport(t, kept)
	if len(keptReport.Proxies) != 1 {
		t.Fatalf("report = %#v", keptReport)
	}
	if got := keptReport.Proxies[0]["name"]; got != "\U0001F1EE\U0001F1F314印度-移动/南方联通(hy2)" {
		t.Fatalf("the node was renamed: %#v", got)
	}
	if got := report.Proxies[1]["name"]; got != "second" {
		t.Fatalf("second name = %#v, want second", got)
	}
	if len(report.Skipped) != 1 || report.Skipped[0].Scheme != "lua" {
		t.Fatalf("recognized unsupported = %#v", report.Skipped)
	}
}

func TestInspectProxyPayloadForIOSDecodesABase64BundleAndNormalizesAliases(t *testing.T) {
	// base64("hy://auth@example.invalid:443?peer=sni.example.invalid&upmbps=10&downmbps=20#one")
	payload := []byte("aHk6Ly9hdXRoQGV4YW1wbGUuaW52YWxpZDo0NDM/cGVlcj1zbmkuZXhhbXBsZS5pbnZhbGlkJnVwbWJwcz0xMCZkb3dubWJwcz0yMCNvbmU=")
	box, err := InspectProxyPayloadForIOS(payload, "subscriptionBody")
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	report := decodeProxyImportReport(t, box)
	if report.Format != "base64-share-links" || len(report.Proxies) != 1 {
		t.Fatalf("report = %#v", report)
	}
	proxy := report.Proxies[0]
	assertProxyFields(t, proxy, map[string]any{
		"type": "hysteria", "server": "example.invalid", "port": "443",
		"auth_str": "auth", "sni": "sni.example.invalid", "up": "10", "down": "20",
	})
}

func TestInspectProxyPayloadForIOSSingleNodeRejectsMoreThanOneNode(t *testing.T) {
	payload := []byte("hysteria2://one@example.invalid:443#one\n" +
		"hysteria2://two@example.invalid:443#two")
	if _, err := InspectProxyPayloadForIOS(payload, "singleNode"); err == nil {
		t.Fatal("want a cardinality error")
	}
}

func TestInspectProxyPayloadForIOSConfigurationDoesNotScavengeEmbeddedLinks(t *testing.T) {
	payload := []byte("notes: see hysteria2://secret@example.invalid:443#not-a-config")
	if _, err := InspectProxyPayloadForIOS(payload, "configuration"); err == nil {
		t.Fatal("configuration context must require a recognized configuration container")
	}
}

func TestInspectProxyPayloadForIOSMapsShadowrocketDialectsWithoutLosingConnectionFields(t *testing.T) {
	tests := []struct {
		name string
		link string
		want map[string]any
	}{
		{
			name: "hysteria2 aliases",
			link: "hysteria2://secret@example.invalid:443?peer=sni.example.invalid&allowInsecure=1&upmbps=10&downmbps=20#hy2",
			want: map[string]any{
				"type": "hysteria2", "server": "example.invalid", "port": "443",
				"password": "secret", "sni": "sni.example.invalid",
				"skip-cert-verify": true, "up": "10", "down": "20",
			},
		},
		{
			name: "tuic aliases",
			link: "tuic://00000000-0000-0000-0000-000000000001:secret@example.invalid:443?peer=sni.example.invalid&allow_insecure=1&proto=bbr&udp=native#tuic",
			want: map[string]any{
				"type": "tuic", "server": "example.invalid", "port": "443",
				"uuid": "00000000-0000-0000-0000-000000000001", "password": "secret",
				"sni": "sni.example.invalid", "skip-cert-verify": true,
				"congestion-controller": "bbr", "udp-relay-mode": "native",
			},
		},
		{
			name: "trojan aliases",
			link: "trojan://secret@example.invalid:443?peer=sni.example.invalid&allow_insecure=1&proto=ws&path=%2Fsocket#trojan",
			want: map[string]any{
				"type": "trojan", "server": "example.invalid", "port": "443",
				"password": "secret", "sni": "sni.example.invalid",
				"skip-cert-verify": true, "network": "ws",
			},
		},
		{
			name: "anytls aliases",
			link: "anytls://secret@example.invalid:443?peer=sni.example.invalid&allowInsecure=1#anytls",
			want: map[string]any{
				"type": "anytls", "server": "example.invalid", "port": "443",
				"password": "secret", "sni": "sni.example.invalid", "skip-cert-verify": true,
			},
		},
		{
			name: "plain http userinfo",
			link: "https://user:secret@example.invalid:443#https",
			want: map[string]any{
				"type": "http", "server": "example.invalid", "port": "443",
				"username": "user", "password": "secret", "tls": true,
			},
		},
		{
			name: "encoded https authority",
			// base64("user:secret@example.invalid:443")
			link: "https://dXNlcjpzZWNyZXRAZXhhbXBsZS5pbnZhbGlkOjQ0Mw#encoded-https",
			want: map[string]any{
				"type": "http", "server": "example.invalid", "port": "443",
				"username": "user", "password": "secret", "tls": true,
			},
		},
		{
			name: "plain socks userinfo",
			link: "socks5://user:secret@example.invalid:1080#socks",
			want: map[string]any{
				"type": "socks5", "server": "example.invalid", "port": "1080",
				"username": "user", "password": "secret",
			},
		},
		{
			name: "mieru aliases",
			link: "mierus://user:secret@example.invalid:443?proto=TCP&profile=profile#mieru",
			want: map[string]any{
				"type": "mieru", "server": "example.invalid", "port": float64(443),
				"username": "user", "password": "secret", "transport": "TCP",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			box, err := InspectProxyPayloadForIOS([]byte(test.link), "singleNode")
			if err != nil {
				t.Fatalf("inspect: %v", err)
			}
			proxy := decodeProxyImportReport(t, box).Proxies[0]
			for key, want := range test.want {
				if got := proxy[key]; !reflect.DeepEqual(got, want) {
					t.Errorf("%s = %#v, want %#v; proxy = %#v", key, got, want, proxy)
				}
			}
		})
	}
}

func TestInspectProxyPayloadForIOSReparsesLegacyVMessAuthority(t *testing.T) {
	link := "vmess://YXV0bzpiODMxMzgxZC02MzI0LTRkNTMtYWQ0Zi04Y2RhNDhiMzA4MTFAZXhhbXBsZS5pbnZhbGlkOjQ0Mw" +
		"?remarks=Legacy&peer=sni.example.invalid&tls=1&obfs=websocket&path=%2Fray&obfsParam=cdn.example.invalid"
	box, err := InspectProxyPayloadForIOS([]byte(link), "singleNode")
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	proxy := decodeProxyImportReport(t, box).Proxies[0]
	want := map[string]any{
		"name": "Legacy", "type": "vmess", "server": "example.invalid", "port": float64(443),
		"uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "cipher": "auto",
		"tls": true, "servername": "sni.example.invalid", "network": "ws",
	}
	for key, value := range want {
		if !reflect.DeepEqual(proxy[key], value) {
			t.Errorf("%s = %#v, want %#v; proxy = %#v", key, proxy[key], value, proxy)
		}
	}
}

func TestInspectProxyPayloadForIOSReparsesLegacyVlessIPv6Authority(t *testing.T) {
	// base64("none:b831381d-6324-4d53-ad4f-8cda48b30811@[2001:db8::1]:443")
	link := "vless://bm9uZTpiODMxMzgxZC02MzI0LTRkNTMtYWQ0Zi04Y2RhNDhiMzA4MTFAWzIwMDE6ZGI4OjoxXTo0NDM" +
		"?type=tcp#IPv6"
	box, err := InspectProxyPayloadForIOS([]byte(link), "singleNode")
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	proxy := decodeProxyImportReport(t, box).Proxies[0]
	if proxy["server"] != "2001:db8::1" || proxy["port"] != "443" ||
		proxy["uuid"] != "b831381d-6324-4d53-ad4f-8cda48b30811" {
		t.Fatalf("proxy = %#v", proxy)
	}
}

func TestInspectProxyPayloadForIOSConstructsShadowrocketSchemesThatCoreOwns(t *testing.T) {
	privateKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	publicKeyBytes := make([]byte, 32)
	publicKeyBytes[0] = 1
	publicKey := base64.StdEncoding.EncodeToString(publicKeyBytes)

	tests := []struct {
		name string
		link string
		want map[string]any
	}{
		{
			name: "snell",
			link: "snell://secret@example.invalid:443?version=4&udp=1&obfs=tls&obfsParam=sni.example.invalid#snell",
			want: map[string]any{
				"type": "snell", "server": "example.invalid", "port": float64(443),
				"psk": "secret", "version": float64(4), "udp": true,
			},
		},
		{
			name: "ssh",
			link: "ssh://user:secret@example.invalid:22#ssh",
			want: map[string]any{
				"type": "ssh", "server": "example.invalid", "port": float64(22),
				"username": "user", "password": "secret",
			},
		},
		{
			name: "wireguard alias",
			link: "wg://example.invalid:51820?publicKey=" + urlQueryEscape(publicKey) +
				"&privateKey=" + urlQueryEscape(privateKey) + "&ip=10.0.0.2%2F32&udp=1#wireguard",
			want: map[string]any{
				"type": "wireguard", "server": "example.invalid", "port": float64(51820),
				"public-key": publicKey, "private-key": privateKey, "ip": "10.0.0.2/32",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			box, err := InspectProxyPayloadForIOS([]byte(test.link), "singleNode")
			if err != nil {
				t.Fatalf("inspect: %v", err)
			}
			proxy := decodeProxyImportReport(t, box).Proxies[0]
			for key, want := range test.want {
				if got := proxy[key]; !reflect.DeepEqual(got, want) {
					t.Errorf("%s = %#v, want %#v; proxy = %#v", key, got, want, proxy)
				}
			}
		})
	}
}

func TestInspectProxyPayloadForIOSConstructsMasqueWithCoreKeys(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	link := "masque://example.invalid:443?privateKey=" + urlQueryEscape(base64.StdEncoding.EncodeToString(privateDER)) +
		"&publicKey=" + urlQueryEscape(base64.StdEncoding.EncodeToString(publicDER)) +
		"&ip=10.0.0.2%2F32&peer=sni.example.invalid&allowInsecure=1&proto=h3#masque"
	box, err := InspectProxyPayloadForIOS([]byte(link), "singleNode")
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	proxy := decodeProxyImportReport(t, box).Proxies[0]
	if proxy["type"] != "masque" || proxy["sni"] != "sni.example.invalid" || proxy["skip-cert-verify"] != true {
		t.Fatalf("proxy = %#v", proxy)
	}
}

func TestInspectProxyPayloadForIOSDecodesOfficialTrustTunnelTLV(t *testing.T) {
	payload := appendTLV(nil, 0x01, []byte("vpn.example.invalid"))
	payload = appendTLV(payload, 0x02, []byte("198.51.100.7:443"))
	payload = appendTLV(payload, 0x03, []byte("sni.example.invalid"))
	payload = appendTLV(payload, 0x05, []byte("user"))
	payload = appendTLV(payload, 0x06, []byte("secret"))
	payload = appendTLV(payload, 0x07, []byte{1})
	payload = appendTLV(payload, 0x09, []byte{2})
	payload = appendTLV(payload, 0x0c, []byte("Trust Tunnel"))
	link := "tt://?" + base64.RawURLEncoding.EncodeToString(payload)

	box, err := InspectProxyPayloadForIOS([]byte(link), "singleNode")
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	proxy := decodeProxyImportReport(t, box).Proxies[0]
	want := map[string]any{
		"name": "Trust Tunnel", "type": "trusttunnel", "server": "198.51.100.7",
		"port": float64(443), "username": "user", "password": "secret",
		"sni": "sni.example.invalid", "skip-cert-verify": true, "quic": true,
	}
	for key, value := range want {
		if !reflect.DeepEqual(proxy[key], value) {
			t.Errorf("%s = %#v, want %#v; proxy = %#v", key, proxy[key], value, proxy)
		}
	}
}

func TestInspectProxyPayloadForIOSReportsUnrepresentableTrustTunnelFields(t *testing.T) {
	basePayload := appendTLV(nil, 0x01, []byte("vpn.example.invalid"))
	basePayload = appendTLV(basePayload, 0x02, []byte("198.51.100.7:443"))
	basePayload = appendTLV(basePayload, 0x05, []byte("user"))
	basePayload = appendTLV(basePayload, 0x06, []byte("secret"))
	tests := []struct {
		name  string
		field byte
		value []byte
	}{
		{name: "second address", field: 0x02, value: []byte("198.51.100.8:443")},
		{name: "pinned certificate", field: 0x08, value: []byte{1, 2, 3}},
		{name: "unknown upstream protocol", field: 0x09, value: []byte{3}},
		{name: "anti dpi", field: 0x0a, value: []byte{1}},
		{name: "client random prefix", field: 0x0b, value: []byte("abcd/ffff")},
		{name: "dns upstreams", field: 0x0d, value: []byte{7, '1', '.', '1', '.', '1', '.', '1'}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := appendTLV(append([]byte(nil), basePayload...), test.field, test.value)
			link := "tt://?" + base64.RawURLEncoding.EncodeToString(payload)
			box, err := InspectProxyPayloadForIOS([]byte(link), "nodeBundle")
			if err != nil {
				t.Fatalf("inspect: %v", err)
			}
			report := decodeProxyImportReport(t, box)
			if len(report.Skipped) != 1 ||
				report.Skipped[0].Code != "recognizedUnsupportedField" {
				t.Fatalf("report = %#v", report)
			}
		})
	}
}

func TestInspectProxyPayloadForIOSRejectsMultipleWireGuardPeers(t *testing.T) {
	privateKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	publicKeyBytes := make([]byte, 32)
	publicKeyBytes[0] = 1
	publicKey := base64.StdEncoding.EncodeToString(publicKeyBytes)
	payload := "[Interface]\nPrivateKey = " + privateKey + "\nAddress = 10.0.0.2/32\n" +
		"[Peer]\nPublicKey = " + publicKey + "\nEndpoint = one.example.invalid:51820\n" +
		"[Peer]\nPublicKey = " + publicKey + "\nEndpoint = two.example.invalid:51820\n"
	if _, err := InspectProxyPayloadForIOS([]byte(payload), "subscriptionBody"); err == nil ||
		!strings.Contains(err.Error(), "exactly one Peer") {
		t.Fatalf("error = %v", err)
	}
}

func TestInspectProxyPayloadForIOSDetectsSubscriptionContainers(t *testing.T) {
	privateKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	publicKeyBytes := make([]byte, 32)
	publicKeyBytes[0] = 1
	publicKey := base64.StdEncoding.EncodeToString(publicKeyBytes)
	ssdJSON := `{"airport":"Example","port":8388,"encryption":"aes-128-gcm","password":"secret","servers":[{"server":"ssd.example.invalid","remarks":"SSD"}]}`

	tests := []struct {
		name       string
		payload    string
		wantFormat string
		want       map[string]any
	}{
		{
			name:       "mihomo yaml",
			payload:    "proxies:\n  - name: YAML\n    type: hysteria2\n    server: yaml.example.invalid\n    port: 443\n    password: secret\n",
			wantFormat: "mihomo-yaml",
			want:       map[string]any{"type": "hysteria2", "server": "yaml.example.invalid", "port": float64(443), "password": "secret"},
		},
		{
			name:       "surge proxy section",
			payload:    "[Proxy]\nSurge = trojan, surge.example.invalid, 443, password=secret, sni=sni.example.invalid, skip-cert-verify=true\n",
			wantFormat: "surge",
			want:       map[string]any{"type": "trojan", "server": "surge.example.invalid", "port": float64(443), "password": "secret", "sni": "sni.example.invalid", "skip-cert-verify": true},
		},
		{
			name:       "sip008 json",
			payload:    `{"servers":[{"server":"sip.example.invalid","server_port":8388,"method":"aes-128-gcm","password":"secret","remarks":"SIP008"}]}`,
			wantFormat: "sip008-json",
			want:       map[string]any{"type": "ss", "server": "sip.example.invalid", "port": float64(8388), "cipher": "aes-128-gcm", "password": "secret"},
		},
		{
			name: "shadowrocket json with nested tls semantics",
			payload: `{"type":"Shadowrocket","servers":[{"type":"vless","host":"shadowrocket.example.invalid","port":443,` +
				`"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","flow":"xtls-rprx-vision","security":"reality",` +
				`"sni":"sni.example.invalid","allowInsecure":true,"alpn":"h2,http/1.1","fp":"chrome",` +
				`"hpkp":"65b3acd7db555768304a16abb6f4366c1a0c0bb5cec81429617f0150d7d66726",` +
				`"pbk":"ppQ9FwLrLIa0AOrp1WvcyiaQ37vg2WSy_CD4bIdiTUw","sid":"6ba85179f3a2b4c5","tfo":true,"remarks":"Shadowrocket"}]}`,
			wantFormat: "shadowrocket-json",
			want: map[string]any{
				"type": "vless", "server": "shadowrocket.example.invalid", "port": float64(443),
				"uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "flow": "xtls-rprx-vision", "tls": true,
				"servername": "sni.example.invalid", "skip-cert-verify": true, "alpn": []any{"h2", "http/1.1"},
				"client-fingerprint": "chrome", "fingerprint": "65b3acd7db555768304a16abb6f4366c1a0c0bb5cec81429617f0150d7d66726",
				"reality-opts.public-key": "ppQ9FwLrLIa0AOrp1WvcyiaQ37vg2WSy_CD4bIdiTUw",
				"reality-opts.short-id":   "6ba85179f3a2b4c5", "tfo": true,
			},
		},
		{
			name:       "sing-box json",
			payload:    `{"outbounds":[{"type":"vless","tag":"Sing","server":"sing.example.invalid","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","tls":{"enabled":true,"server_name":"sni.example.invalid","insecure":true},"transport":{"type":"ws","path":"/ray","headers":{"Host":"cdn.example.invalid"}}}]}`,
			wantFormat: "sing-box-json",
			want:       map[string]any{"type": "vless", "server": "sing.example.invalid", "port": float64(443), "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "tls": true, "servername": "sni.example.invalid", "skip-cert-verify": true, "network": "ws", "ws-opts.path": "/ray", "ws-opts.headers.Host": "cdn.example.invalid"},
		},
		{
			name:       "v2ray json",
			payload:    `{"outbounds":[{"tag":"V2Ray","protocol":"vmess","settings":{"vnext":[{"address":"v2ray.example.invalid","port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","alterId":0,"security":"auto"}]}]},"streamSettings":{"network":"ws","security":"tls","tlsSettings":{"serverName":"sni.example.invalid","allowInsecure":true},"wsSettings":{"path":"/ray","headers":{"Host":"cdn.example.invalid"}}}}]}`,
			wantFormat: "v2ray-json",
			want:       map[string]any{"type": "vmess", "server": "v2ray.example.invalid", "port": float64(443), "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "alterId": float64(0), "cipher": "auto", "tls": true, "servername": "sni.example.invalid", "skip-cert-verify": true, "network": "ws", "ws-opts.path": "/ray", "ws-opts.headers.Host": "cdn.example.invalid"},
		},
		{
			name:       "ssd",
			payload:    "ssd://" + base64.RawURLEncoding.EncodeToString([]byte(ssdJSON)),
			wantFormat: "ssd",
			want:       map[string]any{"type": "ss", "server": "ssd.example.invalid", "port": float64(8388), "cipher": "aes-128-gcm", "password": "secret"},
		},
		{
			name:       "wireguard ini",
			payload:    "[Interface]\nPrivateKey = " + privateKey + "\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = " + publicKey + "\nEndpoint = wg.example.invalid:51820\nAllowedIPs = 0.0.0.0/0\n",
			wantFormat: "wireguard-ini",
			want:       map[string]any{"type": "wireguard", "server": "wg.example.invalid", "port": float64(51820), "private-key": privateKey, "public-key": publicKey, "ip": "10.0.0.2/32", "udp": true},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			box, err := InspectProxyPayloadForIOS([]byte(test.payload), "subscriptionBody")
			if err != nil {
				t.Fatalf("inspect: %v", err)
			}
			report := decodeProxyImportReport(t, box)
			if report.Format != test.wantFormat || len(report.Proxies) != 1 {
				t.Fatalf("report = %#v", report)
			}
			assertProxyFields(t, report.Proxies[0], test.want)
		})
	}
}

func TestInspectProxyPayloadForIOSMergesNestedJSONSubscriptionContainers(t *testing.T) {
	payload := `[
        {"outbounds":[{"type":"vless","tag":"Sing","server":"sing.example.invalid","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811"}]},
        {"servers":[{"server":"sip.example.invalid","server_port":8388,"method":"aes-128-gcm","password":"secret","remarks":"SIP008"}]}
    ]`
	box, err := InspectProxyPayloadForIOS([]byte(payload), "subscriptionBody")
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	report := decodeProxyImportReport(t, box)
	if report.Format != "mixed-proxy-json" || len(report.Proxies) != 2 {
		t.Fatalf("report = %#v", report)
	}
	if report.Proxies[0]["server"] != "sing.example.invalid" ||
		report.Proxies[1]["server"] != "sip.example.invalid" {
		t.Fatalf("proxies = %#v", report.Proxies)
	}
}

func TestSubscriptionContainerDetectorsFailClosedOnMalformedAuthoritativeSignatures(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		want    string
	}{
		{name: "mihomo yaml", payload: "proxies:\n  broken: true\n", want: "parse mihomo-yaml"},

		{name: "json", payload: `{"outbounds":`, want: "parse"},
		{name: "ssd", payload: "ssd://not-base64", want: "parse ssd"},
		{
			name: "json does not fall through to an embedded link",
			payload: `{"outbounds":` + "\n" +
				"vmess://YXV0bzpiODMxMzgxZC02MzI0LTRkNTMtYWQ0Zi04Y2RhNDhiMzA4MTFAZXhhbXBsZS5pbnZhbGlkOjQ0Mw",
			want: "parse",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := InspectProxyPayloadForIOS([]byte(test.payload), "subscriptionBody"); err == nil ||
				!strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}

	// The surge row moved out of the list above on 2026-08-28 and is asserted
	// here instead, because what it was guarding and what it was checking came
	// apart. This test exists so that a payload which announces one format and
	// then fails to parse as it does not quietly get handed to a different
	// detector -- the json rows are the point, where falling through would scan
	// a document nobody understood for embedded links and import whatever it
	// found.
	//
	// `[Proxy]` followed by an unreadable line is not that. The document is
	// surge, it is read as surge, and one line of it cannot be read. It now
	// comes back as a report saying so, which is the outcome the reader asked
	// for; falling through is still refused, and that is what is checked.
	t.Run("a surge document with an unreadable line stays a surge document", func(t *testing.T) {
		box, err := InspectProxyPayloadForIOS([]byte("[Proxy]\nbroken\n"), "subscriptionBody")
		if err != nil {
			t.Fatalf("a single unreadable line cost the document: %v", err)
		}
		report := decodeProxyImportReport(t, box)
		if report.Format != "surge" {
			t.Fatalf("format = %q, want surge -- a malformed surge line must not be handed to another detector", report.Format)
		}
		if len(report.Proxies) != 0 || len(report.Skipped) != 1 {
			t.Fatalf("report = %#v", report)
		}
	})
}

func TestTranslatedSubscriptionContainersRejectUnknownSemanticChildren(t *testing.T) {
	privateKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	publicKeyBytes := make([]byte, 32)
	publicKeyBytes[0] = 1
	publicKey := base64.StdEncoding.EncodeToString(publicKeyBytes)
	tests := []struct {
		name    string
		payload string
	}{
		{
			name: "surge option",
			payload: "[Proxy]\nSurge = trojan, surge.example.invalid, 443, password=secret, " +
				"hako-unknown-semantic=true\n",
		},
		{
			name:    "surge bare option",
			payload: "[Proxy]\nSurge = trojan, surge.example.invalid, 443, password=secret, hako-unknown-semantic\n",
		},
		// The sip008 and SSD server rows left this table on 2026-09-02: a JSON
		// server child nobody maps is named under the node now, and the node
		// arrives. They live in
		// TestTranslatedJSONServerContainersNameUnknownSemanticChildren.
		{
			name: "wireguard interface child",
			payload: "[Interface]\nPrivateKey = " + privateKey + "\nAddress = 10.0.0.2/32\n" +
				"HakoUnknownSemantic = true\n[Peer]\nPublicKey = " + publicKey +
				"\nEndpoint = wg.example.invalid:51820\nAllowedIPs = 0.0.0.0/0\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// The field must be named, and the record must not become a node.
			// Where that answer is delivered changed on 2026-08-28: a
			// container-format record that cannot be read is skipped with its
			// reason rather than failing the document, so the surge rows arrive
			// as a report and the rest still arrive as an error. Both are
			// checked against the same two things.
			box, err := InspectProxyPayloadForIOS([]byte(test.payload), "subscriptionBody")
			if err != nil {
				if !strings.Contains(strings.ToLower(err.Error()), "hako") {
					t.Fatalf("error = %v, want the unknown field named", err)
				}
				return
			}
			report := decodeProxyImportReport(t, box)
			if len(report.Proxies) != 0 {
				t.Fatalf("a record with an unknown semantic child became a node: %#v", report.Proxies)
			}
			if len(report.Skipped) != 1 || !strings.Contains(strings.ToLower(report.Skipped[0].Message), "hako") {
				t.Fatalf("the skip does not name the unknown field: %#v", report.Skipped)
			}
		})
	}
}

// TestTranslatedJSONServerContainersNameUnknownSemanticChildren is the other
// half of the table above, after 2026-09-02: for the JSON server dialects an
// unknown child is named, under the node, and the node arrives -- the same
// answer an unmapped query key has had since 2026-08-28.
func TestTranslatedJSONServerContainersNameUnknownSemanticChildren(t *testing.T) {
	ssd := `{"airport":"Example","port":8388,"encryption":"aes-128-gcm","password":"secret",` +
		`"servers":[{"server":"ssd.example.invalid","remarks":"SSD","hako_unknown_semantic":true}]}`
	tests := []struct {
		name    string
		payload string
		node    string
	}{
		{
			name: "sip008 server child",
			payload: `{"servers":[{"server":"sip.example.invalid","server_port":8388,` +
				`"method":"aes-128-gcm","password":"secret","hako_unknown_semantic":true}]}`,
			node: "sip.example.invalid",
		},
		{name: "ssd server child", payload: "ssd://" + base64.RawURLEncoding.EncodeToString([]byte(ssd)), node: "SSD"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			box, err := InspectProxyPayloadForIOS([]byte(test.payload), "subscriptionBody")
			if err != nil {
				t.Fatalf("a child nobody maps cost the document: %v", err)
			}
			report := decodeProxyImportReport(t, box)
			if len(report.Proxies) != 1 || len(report.Skipped) != 0 {
				t.Fatalf("the node did not arrive: proxies=%#v skipped=%#v", report.Proxies, report.Skipped)
			}
			if name, _ := report.Proxies[0]["name"].(string); name != test.node {
				t.Fatalf("node name = %q, want %q", name, test.node)
			}
			if len(report.NotHonoured) != 1 {
				t.Fatalf("expected the one unknown child named, got %#v", report.NotHonoured)
			}
			notice := report.NotHonoured[0]
			if notice.Message != "hako: proxy field json.server.hako_unknown_semantic: not mapped by this importer build" ||
				notice.Proxy != test.node || notice.Code != "fieldNotHonoured" {
				t.Fatalf("notice = %#v", notice)
			}
		})
	}
}

func TestProxyImportRejectsEmptyOversizedAndUnknownPayloads(t *testing.T) {
	// A refusal says which of the two happened, and the oversize one carries the
	// numbers: "invalid" told the reader nothing they could act on.
	for name, testCase := range map[string]struct {
		payload []byte
		want    string
	}{
		"empty":     {nil, "proxy payload is empty"},
		"oversized": {make([]byte, maximumProviderResourceBytes+1), "over the 16777216-byte limit"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := InspectProxyPayloadForIOS(testCase.payload, "subscriptionBody"); err == nil ||
				!strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	if _, err := InspectProxyPayloadForIOS([]byte("this is neither base64 nor a proxy payload"), "subscriptionBody"); err == nil ||
		!strings.Contains(err.Error(), "proxy payload format is unknown") {
		t.Fatalf("unknown-format error = %v", err)
	}
}

func appendTLV(data []byte, tag byte, value []byte) []byte {
	if len(value) > 63 {
		panic("test TLV helper only supports one-byte lengths")
	}
	data = append(data, tag, byte(len(value)))
	return append(data, value...)
}

func urlQueryEscape(value string) string {
	replacer := strings.NewReplacer("+", "%2B", "/", "%2F", "=", "%3D")
	return replacer.Replace(value)
}

// The three cases this gate used to hold, from the other side: each now brings
// the node back with the field named. Removing them from the list above without
// asserting the new outcome would have left the change untested.
func TestFieldsWithNowhereToGoStillBringTheNode(t *testing.T) {
	const masquePublic = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEr%2BS%2B1lurxAxUbuPi4RhUv%2FaZ5CVG%2FBr79BRi0b%2BQX%2B7oBc5Yx2eQ7OMYFGQ6%2BlqPLWkEr1pl1nZg%2BRoEzg1Jqg%3D%3D"
	const masquePrivate = "MHcCAQEEIIDzwMdDFdFe3jj4vanTuI2sdBFaUjjPnV%2F68XaVWfwfoAoGCCqGSM49AwEHoUQDQgAEr%2BS%2B1lurxAxUbuPi4RhUv%2FaZ5CVG%2FBr79BRi0b%2BQX%2B7oBc5Yx2eQ7OMYFGQ6%2BlqPLWkEr1pl1nZg%2BRoEzg1Jqg%3D%3D"
	for _, test := range []struct{ name, link, field string }{
		{
			name: "WireGuard TLS server name",
			link: "wg://example.invalid:51820?publicKey=AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D" +
				"&privateKey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D&ip=10.0.0.2/32&sni=sni.example.invalid#wg",
			field: "sni",
		},
		{name: "AnyTLS keepalive", link: "anytls://secret@example.invalid:443?keepalive=25#anytls", field: "keepalive"},
		{
			name:  "SSH keepalive and key path",
			link:  "ssh://user:secret@example.invalid:22?keepalive=25&path=/ray#ssh-options",
			field: "keepalive",
		},
		{
			name: "MASQUE WireGuard-shaped preshared key",
			link: "masque://example.invalid:443?publicKey=" + masquePublic + "&privateKey=" + masquePrivate +
				"&ip=10.0.0.2/32&presharedKey=secret#masque",
			field: "presharedKey",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			box, err := InspectProxyPayloadForIOS([]byte(test.link), "nodeBundle")
			if err != nil {
				t.Fatalf("inspect: %v", err)
			}
			report := decodeProxyImportReport(t, box)
			if len(report.Proxies) != 1 {
				t.Fatalf("the node did not arrive: %#v", report)
			}
			if len(report.Skipped) != 0 {
				t.Fatalf("the node arrived and was also called unsupported: %#v", report.Skipped)
			}
			var named bool
			for _, notice := range report.NotHonoured {
				if strings.Contains(notice.Message, test.field) {
					named = true
				}
			}
			if !named {
				t.Fatalf("the field was dropped without saying so: %#v", report.NotHonoured)
			}
		})
	}
}

// A context this build does not know costs a notice, not the payload.
//
// It used to cost the payload: `unknown proxy import context "x"` came back
// instead of a report, and everything that parsed cleanly went with it. The
// parameter asks the call site to declare something only the content knows, so
// a wrong declaration is a question of when, not whether.
//
// All three exits are exercised, because the notice is attached at each of them
// separately and two of them were missed on the first pass: a container, a
// base64-wrapped container, and a plain list of links. The known-context rows
// are the negative control -- if the notice appeared there, this test would be
// asserting nothing.
func TestAnUnknownImportContextCostsANoticeNotThePayload(t *testing.T) {
	const link = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwd2Q@198.51.100.1:1080#N"
	container := "proxies:\n  - {name: N, type: ss, server: 198.51.100.1, port: 1080, cipher: chacha20-ietf-poly1305, password: pw}\n"
	for _, shape := range []struct {
		name, payload string
		// `configuration` is only a legal context for a container; a list of
		// links under it is refused for being the wrong shape, which is a
		// separate and correct behaviour this test is not about.
		knownContext string
	}{
		{"a plain list of links", link, "nodeBundle"},
		{"a container", container, "configuration"},
		{"a base64-wrapped container", base64.StdEncoding.EncodeToString([]byte(container)), "configuration"},
	} {
		for _, context := range []struct {
			value      string
			wantNotice bool
		}{
			{shape.knownContext, false},
			{"not-a-context", true},
		} {
			t.Run(shape.name+" with "+context.value, func(t *testing.T) {
				box, err := InspectProxyPayloadForIOS([]byte(shape.payload), context.value)
				if err != nil {
					t.Fatalf("an import context cost the whole payload: %v", err)
				}
				report := decodeProxyImportReport(t, box)
				if len(report.Proxies) != 1 {
					t.Fatalf("the node did not arrive: %#v", report)
				}
				var got bool
				for _, notice := range report.NotHonoured {
					if strings.Contains(notice.Message, "import.context=") {
						got = true
					}
				}
				if got != context.wantNotice {
					t.Fatalf("context notice present=%v, want %v: %#v", got, context.wantNotice, report.NotHonoured)
				}
			})
		}
	}
}
