package hako

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestTheExportersUnsetPlaceholderIsNotReadAsAValue covers the habit behind two
// different symptoms: the exporter writes `none` into a field the user left
// alone instead of omitting the key. Read literally it refused a snell record
// outright (strconv.Atoi("none")) and, more quietly, handed mihomo "none" as a
// hysteria protocol and a tuic congestion controller -- accepted, and wrong.
//
// The last case is the guard rail: `encryption=none` on vless is a real value,
// and blanking it would be the same mistake pointing the other way.
func TestTheExportersUnsetPlaceholderIsNotReadAsAValue(t *testing.T) {
	read := func(t *testing.T, link string) map[string]any {
		t.Helper()
		box, err := InspectProxyPayloadForIOS([]byte(link), "singleNode")
		if err != nil {
			t.Fatalf("%s: %v", link, err)
		}
		var report proxyImportReport
		if err := json.Unmarshal([]byte(box.Value), &report); err != nil {
			t.Fatalf("report: %v", err)
		}
		if len(report.Proxies) != 1 {
			t.Fatalf("%s refused: %+v %+v", link, report.Skipped, report.Skipped)
		}
		return report.Proxies[0]
	}

	for _, unset := range []struct{ label, link, field string }{
		{"snell version", "snell://pw@example.invalid:443?version=none#s", "version"},
		{"hysteria protocol", "hysteria://example.invalid:443?auth=p&upmbps=10&downmbps=20&protocol=none#h", "protocol"},
		{"tuic congestion control", "tuic://11111111-2222-3333-4444-555555555555:p@example.invalid:443?congestion_control=none#t", "congestion-controller"},
	} {
		t.Run(unset.label, func(t *testing.T) {
			proxy := read(t, unset.link)
			value, present := proxy[unset.field]
			if present && strings.EqualFold(anyString(value), "none") {
				encoded, _ := json.Marshal(proxy)
				t.Fatalf("%s reached the kernel as the literal word: %s", unset.field, encoded)
			}
		})
	}

	t.Run("vless encryption none is a real value", func(t *testing.T) {
		proxy := read(t, "vless://11111111-2222-3333-4444-555555555555@example.invalid:443?encryption=none#v")
		if got := anyString(proxy["encryption"]); got != "none" {
			t.Fatalf("encryption = %q -- a legitimate value was blanked as a placeholder", got)
		}
	})
}

// TestTheExporterOmitsWhatItConsidersImplicit covers the other half of the same
// habit: rather than writing a placeholder, the exporter drops a key whose value
// it treats as the only possible one. mieru is the case -- the kernel refuses
// anything but TCP or UDP and the exporter carries the transport in only one
// direction -- and snell is the counter-case, where an empty credential must stay
// empty rather than be back-filled from the encoding around it.
func TestTheExporterOmitsWhatItConsidersImplicit(t *testing.T) {
	t.Run("mieru transport is recovered", func(t *testing.T) {
		box, err := InspectProxyPayloadForIOS([]byte("mierus://user:sample@e.invalid?port=443&profile=p"), "singleNode")
		if err != nil {
			t.Fatalf("refused: %v", err)
		}
		var report proxyImportReport
		if err := json.Unmarshal([]byte(box.Value), &report); err != nil {
			t.Fatalf("report: %v", err)
		}
		if len(report.Proxies) != 1 {
			t.Fatalf("refused: %+v %+v", report.Skipped, report.Skipped)
		}
		if got := anyString(report.Proxies[0]["transport"]); got != "TCP" {
			t.Fatalf("transport = %q, want TCP", got)
		}
	})

	t.Run("an empty snell key is reported, not invented", func(t *testing.T) {
		// The authority decodes to "chacha20-ietf-poly1305:" -- a cipher and no
		// key. Keeping the undecoded base64 imported a node whose PSK was the
		// encoding of its own cipher name.
		box, err := InspectProxyPayloadForIOS(
			[]byte("snell://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTo@198.51.100.10:443?version=4#n"), "singleNode")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var report proxyImportReport
		if err := json.Unmarshal([]byte(box.Value), &report); err != nil {
			t.Fatalf("report: %v", err)
		}
		if len(report.Proxies) != 0 {
			encoded, _ := json.Marshal(report.Proxies[0])
			t.Fatalf("imported a node with an invented PSK: %s", encoded)
		}
		if len(report.Skipped) != 1 || !strings.Contains(report.Skipped[0].Message, "PSK") {
			t.Fatalf("the refusal does not name the missing key: %+v", report.Skipped)
		}
	})
}

// TestTheExporterMovesCredentialsAndWeFollowThem is the mieru instance of the
// family the vless authority prefix belongs to: the exporter puts a base64
// `user:password` in the username position and leaves the password empty, and
// upstream reads both halves raw, so the whole encoded pair became the username.
// Paired with socks5h, which upstream's converter accepts and this registry did
// not list at all.
func TestTheExporterMovesCredentialsAndWeFollowThem(t *testing.T) {
	read := func(t *testing.T, link string) map[string]any {
		t.Helper()
		box, err := InspectProxyPayloadForIOS([]byte(link), "singleNode")
		if err != nil {
			t.Fatalf("%s: %v", link, err)
		}
		var report proxyImportReport
		if err := json.Unmarshal([]byte(box.Value), &report); err != nil {
			t.Fatalf("report: %v", err)
		}
		if len(report.Proxies) != 1 {
			t.Fatalf("%s refused: %+v %+v", link, report.Skipped, report.Skipped)
		}
		return report.Proxies[0]
	}

	t.Run("mieru userinfo is decoded", func(t *testing.T) {
		// dTpw is base64 for "u:p".
		proxy := read(t, "mierus://dTpw:@example.invalid?port=2999&profile=p")
		if got := anyString(proxy["username"]); got != "u" {
			t.Errorf("username = %q, want u -- the encoded pair was taken whole", got)
		}
		if got := anyString(proxy["password"]); got != "p" {
			t.Errorf("password = %q, want p", got)
		}
	})

	t.Run("socks5h is recognised", func(t *testing.T) {
		proxy := read(t, "socks5h://dXNlcjpwYXNz@example.invalid:1080#s5h")
		if got := anyString(proxy["type"]); got != "socks5" {
			t.Errorf("type = %q, want socks5", got)
		}
		if got := anyString(proxy["password"]); got != "pass" {
			t.Errorf("password = %q, want pass", got)
		}
	})
}
