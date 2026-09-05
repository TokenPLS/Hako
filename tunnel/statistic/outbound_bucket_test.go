package statistic_test

import (
	"net"
	"testing"

	"github.com/TokenPLS/Hako/adapter/outbound"
	C "github.com/TokenPLS/Hako/constant"
	"github.com/TokenPLS/Hako/tunnel/statistic"
)

// The widget shows bytes and connections in three buckets -- proxy, direct, reject --
// by the outbound a connection finally left through. The bucket is decided once, when
// the tracker is built, from the same reserved-name table the proxy-only counters have
// used since, so the widget's proxy bytes are the release evidence's proxy
// bytes. The per-byte path then adds to a bucket picked by a switch, which is cheaper
// than the map lookup by name it replaces.

func trackedConn(t *testing.T, m *statistic.Manager, adapter C.ProxyAdapter) C.Conn {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })
	conn := outbound.NewConn(client, adapter)
	return statistic.NewTCPTracker(conn, m, &C.Metadata{}, nil, 0, 0, true)
}

func TestConnectionsAreCountedIntoTheirOutboundBucket(t *testing.T) {
	m := statistic.NewManagerForTest()
	proxy := trackedConn(t, m, outbound.NewRejectWithOption(outbound.RejectOption{Name: "my-node"}))
	direct := trackedConn(t, m, outbound.NewDirect())
	compatible := trackedConn(t, m, outbound.NewCompatible())
	reject := trackedConn(t, m, outbound.NewReject())
	rejectDrop := trackedConn(t, m, outbound.NewRejectDrop())

	totals := m.OutboundTotals()
	if totals.Opened != 5 || totals.Active != 5 || totals.Rejected != 2 {
		t.Fatalf("after five opens: opened=%d active=%d rejected=%d, want 5/5/2", totals.Opened, totals.Active, totals.Rejected)
	}
	_ = proxy.Close()
	_ = reject.Close()
	totals = m.OutboundTotals()
	if totals.Opened != 5 || totals.Active != 3 || totals.Rejected != 2 {
		t.Fatalf("after two closes: opened=%d active=%d rejected=%d, want 5/3/2", totals.Opened, totals.Active, totals.Rejected)
	}
	_ = direct.Close()
	_ = compatible.Close()
	_ = rejectDrop.Close()
	if totals = m.OutboundTotals(); totals.Active != 0 {
		t.Fatalf("active after all closes = %d, want 0", totals.Active)
	}
}

func TestBytesLandInTheBucketOfTheFinalOutbound(t *testing.T) {
	m := statistic.NewManagerForTest()
	for name, want := range map[string]string{
		"my-node": "proxy", "DIRECT": "direct", "COMPATIBLE": "direct", "PASS": "direct",
		"REJECT": "reject", "REJECT-DROP": "reject",
	} {
		before := m.OutboundTotals()
		m.PushUploaded(name, 10)
		m.PushDownloaded(name, 20)
		after := m.OutboundTotals()
		got := map[string][2]int64{
			"proxy":  {after.Proxy.Up - before.Proxy.Up, after.Proxy.Down - before.Proxy.Down},
			"direct": {after.Direct.Up - before.Direct.Up, after.Direct.Down - before.Direct.Down},
			"reject": {after.Reject.Up - before.Reject.Up, after.Reject.Down - before.Reject.Down},
		}
		for bucket, delta := range got {
			wantDelta := [2]int64{0, 0}
			if bucket == want {
				wantDelta = [2]int64{10, 20}
			}
			if delta != wantDelta {
				t.Fatalf("%s: bucket %s moved by %v, want %v", name, bucket, delta, wantDelta)
			}
		}
	}
	up, down := m.Total()
	if up != 60 || down != 120 {
		t.Fatalf("grand total = %d/%d, want 60/120 (every bucket also counts toward the total)", up, down)
	}
	if up, down := m.TotalTraffic(true); up != 10 || down != 20 {
		t.Fatalf("proxy-only total = %d/%d, want 10/20 (the widget's proxy bucket is the release evidence's)", up, down)
	}
}

// Bytes pushed through a tracker use the bucket decided at construction, not a lookup
// per push.
func TestTrackerBytesUseTheBucketDecidedAtConstruction(t *testing.T) {
	m := statistic.NewManagerForTest()
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	tracked := statistic.NewTCPTracker(outbound.NewConn(client, outbound.NewDirect()), m, &C.Metadata{}, nil, 0, 0, true)
	go func() {
		buffer := make([]byte, 4)
		_, _ = server.Read(buffer)
		_, _ = server.Write([]byte("pong"))
	}()
	if _, err := tracked.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 4)
	if _, err := tracked.Read(buffer); err != nil {
		t.Fatal(err)
	}
	totals := m.OutboundTotals()
	if totals.Direct.Up != 4 || totals.Direct.Down != 4 || totals.Proxy.Up != 0 || totals.Reject.Up != 0 {
		t.Fatalf("direct tracker bytes: direct=%d/%d proxy up=%d reject up=%d, want 4/4/0/0",
			totals.Direct.Up, totals.Direct.Down, totals.Proxy.Up, totals.Reject.Up)
	}
}
