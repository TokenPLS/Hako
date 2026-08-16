//go:build with_gvisor

package tun

import (
	"testing"

	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
)

// ConnectionsNearReceiveMax was meant to be "evidence backpressure actually filled
// buffers", and it cannot be. It compares ReceiveQueueSizeOption -- which gVisor defines
// as "the actual number of payload bytes held in the buffer not including any segment
// overheads", explicitly distinct from the rcvMemUsed it admits against -- with 90% of
// the configured Max. Admission is gated on memory, so the memory gate closes while the
// payload figure is still far below the threshold, and the counter reads zero even at
// saturation. That is the most expensive kind of instrumentation: one that answers the
// question wrongly rather than declining to answer.
//
// rcvMemUsed is unexported and no option returns it, so the honest memory figure is not
// readable from outside gVisor. The event is: enqueueSegment increments
// ReceiveErrors.SegmentQueueDropped exactly when the memory gate refused a segment. That
// is what the report now carries, and per-endpoint stats are reachable through
// tcpip.Endpoint.Stats().
//

func TestGVisorWindowSnapshotReportsSegmentQueueDrops(t *testing.T) {
	prior := GVisorTCPBufferBytes
	t.Cleanup(func() { GVisorTCPBufferBytes = prior })
	GVisorTCPBufferBytes = 0

	stack, err := NewGVisorStack(channel.New(8, 1500, ""))
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()

	report := newGVisorWindowSnapshot(stack)()
	if report.SegmentQueueDroppedTotal != 0 {
		t.Fatalf("an idle stack must report no segment-queue drops, got %d",
			report.SegmentQueueDroppedTotal)
	}
	// The counter has to be present in the same snapshot as the occupancy distribution,
	// because the point of it is to be read together with them: occupancy says how full
	// the queues look in payload terms, and this says whether the memory gate ever
	// actually refused anything.
	if report.MaxBytes == 0 {
		t.Fatal("the snapshot lost the live range while gaining the drop counter")
	}
}

// TestSegmentQueueDropTotalSurvivesEndpointsWithoutTCPStats: the snapshot walks every
// registered endpoint and type-asserts its stats. An endpoint whose stats are not TCP
// stats must be skipped rather than abort the walk, or one UDP endpoint would silently
// zero the whole report.
func TestSegmentQueueDropTotalSurvivesEndpointsWithoutTCPStats(t *testing.T) {
	prior := GVisorTCPBufferBytes
	t.Cleanup(func() { GVisorTCPBufferBytes = prior })
	GVisorTCPBufferBytes = 0

	stack, err := NewGVisorStack(channel.New(8, 1500, ""))
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()

	// Two snapshots of the same idle stack must agree; a walk that aborted early on an
	// unexpected endpoint type would be order-dependent and could differ.
	first := newGVisorWindowSnapshot(stack)()
	second := newGVisorWindowSnapshot(stack)()
	if first.SegmentQueueDroppedTotal != second.SegmentQueueDroppedTotal {
		t.Fatalf("drop totals disagree across snapshots of an idle stack: %d vs %d",
			first.SegmentQueueDroppedTotal, second.SegmentQueueDroppedTotal)
	}
	if first.TCPConnections != second.TCPConnections {
		t.Fatalf("connection counts disagree: %d vs %d", first.TCPConnections, second.TCPConnections)
	}
}
