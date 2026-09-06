package tunnel

// TCPConnectionAdmission is the process-local low-memory admission state.
// Limit is zero in standard builds, which means unlimited.
type TCPConnectionAdmission struct {
	Limit    int64
	Active   int64
	Rejected uint64
}
