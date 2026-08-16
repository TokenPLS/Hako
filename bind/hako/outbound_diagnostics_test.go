package hako

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestOutboundEndpointKindsMatchSwiftIDsWithoutLeakingEndpoints(t *testing.T) {
	const content = `
proxies:
  - name: Host Node
    type: VLESS
    server: secret.example.test
    port: 443
    uuid: private-credential
  - name: IPv4 Node
    type: socks5
    server: 192.0.2.1
  - name: IPv6 Node
    type: hysteria2
    server: 2001:db8::1
`
	got := snapshotOutboundEndpointKinds(content)
	want := map[string]string{
		anonymizedNodeID("Host Node", "VLESS"):     "hostname",
		anonymizedNodeID("IPv4 Node", "socks5"):    "ipv4",
		anonymizedNodeID("IPv6 Node", "hysteria2"): "ipv6",
	}
	if len(got) != len(want) {
		t.Fatalf("endpoint kinds = %#v, want %#v", got, want)
	}
	for id, kind := range want {
		if got[id] != kind {
			t.Fatalf("endpoint kind %s = %q, want %q", id, got[id], kind)
		}
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"Host Node", "secret.example.test", "192.0.2.1", "private-credential"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("diagnostics leaked %q: %s", secret, encoded)
		}
	}
}
