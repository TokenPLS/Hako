package hako

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/TokenPLS/Hako/common/convert"
)

// `security=tls` is the spelling airports hand out, and it was refused.
//
// A user's real subscription link -- socks5://…@host:443?security=tls -- came
// back as "proxy field socks5.query.security is recognized but unsupported",
// which reads as "this build cannot do TLS over socks5". That is not true:
// mihomo's socks5 outbound has a tls field and this tree carries an interop
// test for it. The key was registered on trojan, vless, vmess and snell and
// simply missing from socks5 and http.
//
// Two halves, and the second is the one a ledger entry alone would not catch:
// the key must be ACCEPTED, and what it says must be HONOURED. Accepting it and
// dropping the value would import the node as plaintext and fail at dial time
// with nothing pointing back at the link -- worse than the refusal it replaced.
//
// Reported by the iOS lane 2026-08-28 from the user's own airport.
func TestSecuritySpellingEnablesTLSWhereTLSExists(t *testing.T) {
	for name, tc := range map[string]struct {
		link    string
		wantTLS bool
	}{
		"socks5 security=tls":  {"socks5://dXNlcjpwYXNz@example.com:443?security=tls#Node", true},
		"socks5 security=none": {"socks5://dXNlcjpwYXNz@example.com:443?security=none#Node", false},
		"socks5 tls=1":         {"socks5://dXNlcjpwYXNz@example.com:443?tls=1#Node", true},
		"http security=tls":    {"http://user:pass@example.com:443?security=tls#Node", true},
	} {
		t.Run(name, func(t *testing.T) {
			box, err := ConvertProxiesForIOS([]byte(tc.link))
			if err != nil {
				t.Fatalf("the link was refused: %v", err)
			}
			// The importer answers YAML, not JSON. The first version of this
			// test decoded it as JSON and reported "invalid character 'p'" for
			// all four cases -- a harness error wearing the shape of a product
			// one, and the fourth time today a predicate was aimed at the wrong
			// artifact.
			var out struct {
				Proxies []map[string]any `yaml:"proxies"`
			}
			if err := yaml.Unmarshal([]byte(box.Value), &out); err != nil {
				t.Fatalf("import output is not the expected shape: %v\n%s", err, box.Value)
			}
			if len(out.Proxies) != 1 {
				t.Fatalf("expected one proxy, got %d: %s", len(out.Proxies), box.Value)
			}
			tls, _ := out.Proxies[0]["tls"].(bool)
			if tls != tc.wantTLS {
				t.Errorf("tls=%v, want %v — accepting the key and dropping what it says imports the node "+
					"as plaintext and fails at dial time with nothing pointing back at the link:\n%s",
					tls, tc.wantTLS, box.Value)
			}
		})
	}
}

// The refusal message that sent the user here, kept as the thing that must not
// come back. It named a field the importer does support, on a protocol that
// supports it, which is the shape of a ledger that fell behind the code rather
// than a capability that is missing.
func TestTheSecurityKeyIsNoLongerReportedAsUnsupported(t *testing.T) {
	_, err := ConvertProxiesForIOS([]byte("socks5://dXNlcjpwYXNz@example.com:443?security=tls#Node"))
	if err == nil {
		return
	}
	if strings.Contains(err.Error(), "socks5.query.security") {
		t.Fatalf("the field is registered and honoured, and the importer still calls it unsupported: %v", err)
	}
	t.Fatalf("the link was refused for another reason: %v", err)
}

// The second link the user hit, an hour after the first, and the reason the
// ledger stopped being patched key by key.
//
// ss://…?udp=1 is on nearly every airport subscription and mihomo's ss outbound
// has the field. It came back "recognized but unsupported", same as socks5's
// security -- two real links, two missing registrations, one design: the ledger
// is a whitelist, so every spelling anybody adds to a share link is a refusal
// until somebody registers it.
//
// The registration is here because the value must be HONOURED. The tolerance
// that stops the refusal is a separate change (ConvertProxiesForIOS now passes
// tolerateUnmapped, as every other caller already did), and tolerance alone
// would import this node with udp off -- a failure that arrives later and does
// not point back at the link.
func TestTheAirportUDPSpellingIsHonouredOnShadowsocks(t *testing.T) {
	box, err := ConvertProxiesForIOS([]byte(
		"ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpmYWtlX25vZGVfcGFzc3dvcmQ@1.1.1.1:1080?udp=1#Node"))
	if err != nil {
		t.Fatalf("a link with udp=1 was refused: %v", err)
	}
	var out struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal([]byte(box.Value), &out); err != nil {
		t.Fatalf("import output is not the expected shape: %v", err)
	}
	if len(out.Proxies) != 1 {
		t.Fatalf("expected one proxy, got %d", len(out.Proxies))
	}
	if udp, _ := out.Proxies[0]["udp"].(bool); !udp {
		t.Errorf("udp=1 was accepted and dropped; the node imports with udp off:\n%s", box.Value)
	}
}

// The change that stops the NEXT unregistered key from reaching a person as a
// refusal. ConvertProxiesForIOS is the paste path -- its own documentation says
// it exists so the reader can correct a link before saving -- and it was the
// one caller passing tolerateUnmapped false while the core's own provider
// loader passed true. Stricter than ourselves, on the path a human stands on.
func TestAnUnregisteredQueryKeyReachesTheEditorInsteadOfBeingRefused(t *testing.T) {
	box, err := ConvertProxiesForIOS([]byte(
		"ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpmYWtlX25vZGVfcGFzc3dvcmQ@1.1.1.1:1080?hako-no-such-key=1#Node"))
	if err != nil {
		t.Fatalf("a link carrying one unknown query key was refused whole: %v\n\n"+
			"mihomo reads the keys it knows and ignores the rest, and so does every other client that "+
			"reads these links. A whitelist here makes every future spelling a refusal.", err)
	}
	if !strings.Contains(box.Value, "proxies:") {
		t.Fatalf("the link was accepted and produced nothing usable:\n%s", box.Value)
	}
}

// UDP is on by default for the protocols upstream turns it on for, and a query
// key must not be able to turn it off.
//
// `udp` was registered on ss to stop the refusal, and reading it as a switch
// was the obvious next step and would have been wrong: upstream sets
// ss["udp"] = true unconditionally (common/convert/converter.go:452) and never
// reads the query. A link carrying udp=0 would then import with udp off here
// and on upstream -- a divergence introduced while fixing one.
//
// So the test compares against upstream's own converter rather than against an
// expectation written here. Whatever mihomo does with a link, this tree does.
func TestUDPMatchesUpstreamWhateverTheLinkSays(t *testing.T) {
	for name, link := range map[string]string{
		"ss with no udp key": "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwd2Q@1.1.1.1:1080#N",
		"ss with udp=0":      "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwd2Q@1.1.1.1:1080?udp=0#N",
		"ss with udp=1":      "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwd2Q@1.1.1.1:1080?udp=1#N",
		"trojan with no key": "trojan://pw@example.com:443#N",
	} {
		t.Run(name, func(t *testing.T) {
			upstream, err := convert.ConvertsV2Ray([]byte(link))
			if err != nil || len(upstream) != 1 {
				t.Skipf("upstream does not convert this shape, so there is nothing to match: %v", err)
			}
			box, err := ConvertProxiesForIOS([]byte(link))
			if err != nil {
				t.Fatalf("this tree refuses a link upstream converts: %v", err)
			}
			var out struct {
				Proxies []map[string]any `yaml:"proxies"`
			}
			if err := yaml.Unmarshal([]byte(box.Value), &out); err != nil {
				t.Fatalf("import output is not the expected shape: %v", err)
			}
			if len(out.Proxies) != 1 {
				t.Fatalf("expected one proxy, got %d", len(out.Proxies))
			}
			theirs, _ := upstream[0]["udp"].(bool)
			ours, _ := out.Proxies[0]["udp"].(bool)
			if theirs != ours {
				t.Errorf("udp: upstream %v, this tree %v — a query key must not change what upstream "+
					"decides unconditionally", theirs, ours)
			}
		})
	}
}
