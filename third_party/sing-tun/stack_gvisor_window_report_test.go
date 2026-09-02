//go:build with_gvisor

package tun

import (
	"testing"

	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
)

// The snapshot must read the range LIVE from the stack (wiring proof), not
// restate configuration, and report an empty distribution with no endpoints.
func TestGVisorWindowSnapshotReadsLiveRange(t *testing.T) {
	prior := GVisorTCPBufferBytes
	t.Cleanup(func() { GVisorTCPBufferBytes = prior })

	GVisorTCPBufferBytes = 0
	ep := channel.New(8, 1500, "")
	s, err := NewGVisorStack(ep)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	report := newGVisorWindowSnapshot(s)()
	if report.MinBytes != 4096 || report.DefaultBytes != 32*1024 || report.MaxBytes != 128*1024 {
		t.Fatalf("adaptive range not read back live: %+v", report)
	}
	if report.TCPConnections != 0 || report.ReceiveOccupancyMaxBytes != 0 || report.ConnectionsNearReceiveMax != 0 {
		t.Fatalf("empty stack must report empty distribution: %+v", report)
	}

	GVisorTCPBufferBytes = 96 * 1024
	pinned, err := NewGVisorStack(channel.New(8, 1500, ""))
	if err != nil {
		t.Fatal(err)
	}
	defer pinned.Close()
	report = newGVisorWindowSnapshot(pinned)()
	if report.MinBytes != 1 || report.DefaultBytes != 96*1024 || report.MaxBytes != 96*1024 {
		t.Fatalf("pinned range not read back live: %+v", report)
	}
}
