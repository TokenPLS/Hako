package tun

// GVisorTCPBufferBytes, when positive, pins the gVisor TCP send/receive buffer
// to a FIXED window (Default == Max == the value) for controlled benchmark runs
// — benchmark tooling sets it via the gomobile bind layer to A/B window
// sizes. When zero or negative (the default), the stack uses its adaptive range
// (4 KiB min / 32 KiB initial / 128 KiB max) and gVisor's receive-buffer
// moderation grows busy connections per measured demand; that range was chosen
// from on-device A/B numbers (see stack_gvisor.go).
//
// It lives in this un-tagged file (not stack_gvisor.go, which is //go:build
// with_gvisor) so the gomobile bind layer can set it from a build that does not
// itself compile the gVisor stack; stack_gvisor.go reads it at stack creation.
var GVisorTCPBufferBytes = 0

// GVisorPacketIOReport is a cumulative, payload-free snapshot of the Darwin
// PacketFlow descriptor path. The counters intentionally describe only packet
// movement and bounded queue occupancy; they never retain packet contents or
// endpoint metadata.
type GVisorPacketIOReport struct {
	IngressReadCalls       uint64
	IngressReadWouldBlock  uint64
	IngressReadPackets     uint64
	IngressReadBytes       uint64
	IngressReadErrors      uint64
	IngressDispatchPackets uint64
	IngressDispatchBytes   uint64
	ProcessorQueueDepth    uint64
	ProcessorQueuePeak     uint64
	EgressWriteCalls       uint64
	EgressWritePackets     uint64
	EgressWriteBytes       uint64
	EgressWriteErrors      uint64
}

// GVisorPacketIOSnapshot is installed by the active Darwin gVisor endpoint.
// Keeping the hook in an untagged file lets the gomobile binding expose the
// same diagnostic schema on every build target without importing a
// Darwin-only internal package.
var GVisorPacketIOSnapshot func() GVisorPacketIOReport

// GVisorTCPWindowReport is the live TCP window state of the running gVisor
// stack, so on-device evidence can prove which window a run really used — a
// staged-configuration marker cannot detect a wiring defect; this can.
type GVisorTCPWindowReport struct {
	// MinBytes/DefaultBytes/MaxBytes are the receive-buffer auto-tuning RANGE
	// read back live from the stack — the clamp moderation may not exceed, so
	// this proves the 128 KiB cap is really wired.
	MinBytes, DefaultBytes, MaxBytes int
	TCPConnections                   int
	// ReceiveOccupancy* is the queued receive PAYLOAD per TCP connection
	// (ReceiveQueueSizeOption = RcvBufUsed). It is not a memory figure, and this
	// comment used to say it was. gVisor defines RcvBufUsed as "the actual number of
	// payload bytes held in the buffer not including any segment overheads" and calls
	// it explicitly distinct from rcvMemUsed, which is what the stack actually admits
	// segments against. Every queued packet retains a whole pooled chunk regardless of
	// how little payload it carries, so at small payloads the two diverge by more than
	// an order of magnitude.
	//
	// It is still the right thing to read — SO_RCVBUF (GetReceiveBufferSize) reports a
	// 1 MiB nominal default that is never clamped and would overstate by ~8x — but it
	// answers "how much data is queued", not "how much memory is held". rcvMemUsed is
	// unexported and no option returns it, so the memory figure is not available from
	// outside gVisor.
	ReceiveOccupancyP50Bytes, ReceiveOccupancyP95Bytes, ReceiveOccupancyMaxBytes int
	// ConnectionsNearReceiveMax counts connections whose queued payload reached >=90%
	// of the range Max.
	//
	// Expect this to read 0, including under saturation, and do not treat a 0 as
	// evidence of anything. It compares a payload figure against a cap the stack
	// enforces on MEMORY: the memory gate closes while payload is still well short of
	// Max, so the threshold is not reachable in practice.
	//
	// SegmentQueueDroppedTotal is the field that carries this signal.
	ConnectionsNearReceiveMax int
	// SegmentQueueDroppedTotal is the summed per-endpoint count of segments dropped
	// because the receive queue was full — gVisor increments it in enqueueSegment
	// exactly when the memory gate refused a segment. Unlike the occupancy figures this
	// is the event itself rather than an inference from it, so a non-zero value is
	// direct evidence that backpressure reached the cap.
	SegmentQueueDroppedTotal uint64
}

// GVisorTCPWindowSnapshot is set by the full-gVisor stack's Start while it is
// live and cleared by its Close; Mixed never mounts it -- its gVisor half
// carries UDP only and its TCP rides the system half, so a TCP window report
// there would describe a path no TCP traffic takes. nil therefore means no
// gVisor TCP path, not "no gVisor stack" (Mixed runs one). It lives in this
// un-tagged file so the gomobile bind layer (built without with_gvisor) can
// surface the report in runtime diagnostics.
var GVisorTCPWindowSnapshot func() GVisorTCPWindowReport
