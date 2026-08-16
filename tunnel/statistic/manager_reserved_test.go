package statistic

import "testing"

// bytes whose final egress is a reserved non-proxy outbound
// (direct/reject/reject-drop/pass/compatible) must not inflate the proxy-only
// counters used as release evidence. Previously only exact "DIRECT" was
// excluded, so REJECTed and other pseudo-outbound bytes counted as proxy.
func TestManagerExcludesReservedNonProxyOutbounds(t *testing.T) {
	for _, name := range []string{"DIRECT", "COMPATIBLE", "REJECT", "REJECT-DROP", "PASS"} {
		m := &Manager{}
		m.PushUploaded(name, 100)
		m.PushDownloaded(name, 200)
		if up, down := m.TotalTraffic(true); up != 0 || down != 0 {
			t.Fatalf("%s counted as proxy: proxy total = %d/%d, want 0/0", name, up, down)
		}
		if up, down := m.TotalTraffic(false); up != 100 || down != 200 {
			t.Fatalf("%s all-traffic = %d/%d, want 100/200", name, up, down)
		}
	}
}

func TestManagerCountsRealProxyOutbound(t *testing.T) {
	m := &Manager{}
	m.PushUploaded("my-ss-node", 100)
	m.PushDownloaded("my-ss-node", 200)
	if up, down := m.TotalTraffic(true); up != 100 || down != 200 {
		t.Fatalf("real proxy not counted: proxy total = %d/%d, want 100/200", up, down)
	}
}
