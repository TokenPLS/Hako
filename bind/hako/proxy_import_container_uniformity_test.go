package hako

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"gopkg.in/yaml.v3"
)

// canonicalProxyCorpusForContainerUniformity covers the field families a real
// subscription carries: plugin options, ws transport, reality plus a client
// fingerprint, hysteria2 port hopping, and the vmess alterId spelling. Values are
// synthetic.
const canonicalProxyCorpusForContainerUniformity = `[
  {"name":"a","type":"ss","server":"a.example","port":443,"cipher":"aes-128-gcm","password":"p1","udp":true,
   "plugin":"obfs","plugin-opts":{"mode":"tls","host":"a.example"}},
  {"name":"b","type":"trojan","server":"b.example","port":443,"password":"p2","sni":"b.example",
   "skip-cert-verify":true,"network":"ws","ws-opts":{"path":"/ray","headers":{"Host":"b.example"}}},
  {"name":"c","type":"vless","server":"c.example","port":443,"uuid":"11111111-2222-3333-4444-555555555555",
   "flow":"xtls-rprx-vision","tls":true,"client-fingerprint":"chrome",
   "reality-opts":{"public-key":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA","short-id":"abcd"}},
  {"name":"d","type":"hysteria2","server":"d.example","port":443,"password":"p3","ports":"443,5000-6000",
   "sni":"d.example"},
  {"name":"e","type":"vmess","server":"e.example","port":443,"uuid":"66666666-7777-8888-9999-000000000000",
   "alterId":0,"cipher":"auto","tfo":true},
  {"name":"f","type":"anytls","server":"f.example","port":443,"password":"p4","sni":"f.example"}
]`

// TestContainerSpellingDoesNotChangeTheImport pins the invariant the 652-node
// corpus broke: which container a caller wrapped a set of proxies in is a fact
// about the container, not about the proxies. All four spellings of "here are
// some mihomo proxies" must therefore import identically.
func TestContainerSpellingDoesNotChangeTheImport(t *testing.T) {
	var items []map[string]any
	if err := json.Unmarshal([]byte(canonicalProxyCorpusForContainerUniformity), &items); err != nil {
		t.Fatalf("corpus is not JSON: %v", err)
	}
	if len(items) == 0 {
		t.Fatal("corpus is empty, so this test would pass without comparing anything")
	}
	keyedJSON, err := json.Marshal(map[string]any{"proxies": items})
	if err != nil {
		t.Fatalf("wrap corpus as JSON: %v", err)
	}
	bareYAML, err := yaml.Marshal(items)
	if err != nil {
		t.Fatalf("write corpus as a YAML sequence: %v", err)
	}
	keyedYAML, err := yaml.Marshal(map[string]any{"proxies": items})
	if err != nil {
		t.Fatalf("write corpus as a YAML document: %v", err)
	}

	read := func(t *testing.T, payload []byte, label string) string {
		t.Helper()
		box, err := InspectProxyPayloadForIOS(payload, "nodeBundle")
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		var report proxyImportReport
		if err := json.Unmarshal([]byte(box.Value), &report); err != nil {
			t.Fatalf("%s report: %v", label, err)
		}
		if len(report.Skipped) > 0 {
			t.Fatalf("%s called mihomo's own fields unsupported: %v", label, report.Skipped)
		}
		if len(report.Proxies) != len(items) {
			t.Fatalf("%s imported %d of %d proxies (rejected: %v)",
				label, len(report.Proxies), len(items), report.Skipped)
		}
		encoded, err := json.Marshal(report.Proxies)
		if err != nil {
			t.Fatalf("%s: marshal proxies: %v", label, err)
		}
		return string(encoded)
	}

	wrap := func(payload []byte) []byte {
		return []byte(base64.StdEncoding.EncodeToString(payload))
	}
	containers := []struct {
		label   string
		payload []byte
	}{
		{"bare JSON array", []byte(canonicalProxyCorpusForContainerUniformity)},
		{`JSON {"proxies": [...]}`, keyedJSON},
		{"bare YAML sequence", bareYAML},
		{"YAML proxies: document", keyedYAML},
		// A subscription that base64s its whole body is the same subscription.
		{"base64(bare JSON array)", wrap([]byte(canonicalProxyCorpusForContainerUniformity))},
		{"base64(YAML proxies: document)", wrap(keyedYAML)},
	}
	reference := read(t, containers[0].payload, containers[0].label)
	for _, container := range containers[1:] {
		if got := read(t, container.payload, container.label); got != reference {
			t.Errorf("%s imported differently from %s\n  want %s\n   got %s",
				container.label, containers[0].label, reference, got)
		}
	}
}

// TestDialectObjectsInABareArrayStillReachTheMapping guards the other direction:
// the canonical route must not swallow documents written in a dialect, whose
// fields only survive because jsonServerMapping translates them.
func TestDialectObjectsInABareArrayStillReachTheMapping(t *testing.T) {
	const dialect = `[{"type":"ss","server":"g.example","server_port":8388,"method":"chacha20-ietf-poly1305",
	  "password":"p5","remarks":"dialect node"}]`
	box, err := InspectProxyPayloadForIOS([]byte(dialect), "nodeBundle")
	if err != nil {
		t.Fatalf("dialect object rejected: %v", err)
	}
	var report proxyImportReport
	if err := json.Unmarshal([]byte(box.Value), &report); err != nil {
		t.Fatalf("report: %v", err)
	}
	if len(report.Proxies) != 1 {
		t.Fatalf("expected one proxy, got %d (unsupported: %v)", len(report.Proxies), report.Skipped)
	}
	proxy := report.Proxies[0]
	for key, want := range map[string]any{
		"name":     "dialect node",
		"port":     8388,
		"cipher":   "chacha20-ietf-poly1305",
		"password": "p5",
	} {
		got := proxy[key]
		if anyString(got) != anyString(want) {
			t.Errorf("dialect key lost in translation: %s = %v, want %v", key, got, want)
		}
	}
}
