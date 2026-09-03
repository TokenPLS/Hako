//go:build with_low_memory

package tunnel

import (
	"net"
	"testing"
	"time"

	C "github.com/TokenPLS/Hako/constant"
	icontext "github.com/TokenPLS/Hako/context"
)

func TestLowMemoryTCPConnectionAdmissionIsBoundedAndRecoverable(t *testing.T) {
	activeTCPConnectionSlots.Store(0)
	rejectedTCPConnectionTotal.Store(0)
	t.Cleanup(func() {
		activeTCPConnectionSlots.Store(0)
		rejectedTCPConnectionTotal.Store(0)
	})

	for index := int64(0); index < 416; index++ {
		if !acquireTCPConnectionSlot() {
			t.Fatalf("connection %d was rejected before the admission limit", index+1)
		}
	}
	if acquireTCPConnectionSlot() {
		t.Fatal("connection above the admission limit was accepted")
	}

	snapshot := TCPConnectionAdmissionSnapshot()
	if snapshot.Limit != 416 || snapshot.Active != 416 || snapshot.Rejected != 1 {
		t.Fatalf("admission snapshot = %+v, want limit=416 active=416 rejected=1", snapshot)
	}

	previousStatus := status.Load()
	status.Store(Running)
	defer status.Store(previousStatus)
	inbound, client := net.Pipe()
	defer client.Close()
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	handleTCPConn(icontext.NewConnContext(inbound, &C.Metadata{Type: C.TUN}))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("over-limit inbound was not closed before routing")
	}
	if rejected := TCPConnectionAdmissionSnapshot().Rejected; rejected != 2 {
		t.Fatalf("rejected connection count = %d, want 2", rejected)
	}

	releaseTCPConnectionSlot()
	if !acquireTCPConnectionSlot() {
		t.Fatal("released connection slot was not reusable")
	}
	for index := int64(0); index < 416; index++ {
		releaseTCPConnectionSlot()
	}
	if active := TCPConnectionAdmissionSnapshot().Active; active != 0 {
		t.Fatalf("active connection slots = %d, want 0", active)
	}
}
