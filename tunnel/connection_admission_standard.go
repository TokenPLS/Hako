//go:build !with_low_memory

package tunnel

func acquireTCPConnectionSlot() bool { return true }

func releaseTCPConnectionSlot() {}

func TCPConnectionAdmissionSnapshot() TCPConnectionAdmission {
	return TCPConnectionAdmission{}
}
