//go:build !with_low_memory

package tunnel

import "testing"

func TestStandardTCPConnectionAdmissionRemainsUnlimited(t *testing.T) {
	if !acquireTCPConnectionSlot() {
		t.Fatal("standard build rejected a TCP connection")
	}
	releaseTCPConnectionSlot()
	if snapshot := TCPConnectionAdmissionSnapshot(); snapshot != (TCPConnectionAdmission{}) {
		t.Fatalf("standard admission snapshot = %+v, want zero/unlimited", snapshot)
	}
}
