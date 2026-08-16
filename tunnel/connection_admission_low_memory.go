//go:build with_low_memory

package tunnel

import "sync/atomic"

// Leave sixteen slots above the signed 400-flow production workload for DNS,
// captive-portal and other control traffic that may share the TUN. Rejecting
// new work before sniffing/dialing is safer than allowing iOS critical memory
// pressure to close every established connection at once.
const lowMemoryTCPConnectionAdmissionLimit int64 = 416

var (
	activeTCPConnectionSlots   atomic.Int64
	rejectedTCPConnectionTotal atomic.Uint64
)

func acquireTCPConnectionSlot() bool {
	for {
		active := activeTCPConnectionSlots.Load()
		if active >= lowMemoryTCPConnectionAdmissionLimit {
			rejectedTCPConnectionTotal.Add(1)
			return false
		}
		if activeTCPConnectionSlots.CompareAndSwap(active, active+1) {
			return true
		}
	}
}

func releaseTCPConnectionSlot() {
	activeTCPConnectionSlots.Add(-1)
}

func TCPConnectionAdmissionSnapshot() TCPConnectionAdmission {
	return TCPConnectionAdmission{
		Limit:    lowMemoryTCPConnectionAdmissionLimit,
		Active:   activeTCPConnectionSlots.Load(),
		Rejected: rejectedTCPConnectionTotal.Load(),
	}
}
