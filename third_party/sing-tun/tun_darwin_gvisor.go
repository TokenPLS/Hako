//go:build with_gvisor && darwin

package tun

import (
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/link/qdisc/fifo"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/sing-tun/internal/fdbased_darwin"
	"github.com/metacubex/sing-tun/internal/rawfile_darwin"

	"golang.org/x/sys/unix"
)

var _ GVisorTun = (*NativeTun)(nil)

func (t *NativeTun) WritePacket(pkt *stack.PacketBuffer) (int, error) {
	views := pkt.AsSlices()
	numIovecs := len(views)
	numIovecs++ // for packetHeaderVec4/6

	// Allocate small iovec arrays on the stack.
	var iovecsArr [8]unix.Iovec
	iovecs := iovecsArr[:0]
	if numIovecs > len(iovecsArr) {
		iovecs = make([]unix.Iovec, 0, numIovecs)
	}

	if pkt.NetworkProtocolNumber == header.IPv4ProtocolNumber {
		iovecs = append(iovecs, packetHeaderVec4)
	} else {
		iovecs = append(iovecs, packetHeaderVec6)
	}
	var dataLen int
	for _, packetSlice := range views {
		dataLen += len(packetSlice)
		iovec := unix.Iovec{
			Base: &packetSlice[0],
		}
		iovec.SetLen(len(packetSlice))
		iovecs = append(iovecs, iovec)
	}
	errno := rawfile.NonBlockingWriteIovec(t.tunFd, iovecs)
	if errno == 0 {
		return dataLen, nil
	} else {
		return 0, errno
	}
}

func (t *NativeTun) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	// Pin ProcessorsPerChannel to 1. With a single tun FD and batchSize=1
	// (RecvMsgX is off on the NE utun) the default (GOMAXPROCS/FDs) spins up
	// extra processor goroutines that buy no parallelism — never more than one
	// packet is queued — but forfeit the inline zero-wake delivery fast path,
	// taxing every ingress packet with an async goroutine wake.
	//
	// This is OUR tuning decision, not upstream's default -- an earlier version of this
	// comment claimed it matched sing-box's iOS default, and that is false. sing-box sets
	// GOMAXPROCS nowhere, so on iOS its ProcessorsPerChannel resolves to
	// max(1, GOMAXPROCS/len(FDs)) with GOMAXPROCS at NumCPU, about 6 on a modern iPhone.
	// Even under our own cap (effectiveMaxProcs defaults to 4 under a memory limit) leaving
	// this at 0 would give 4, so the pin is load-bearing rather than redundant.
	//
	// It is a measured trade, not a free win: at P=4 the same device gives about +25%
	// throughput for about +15 percentage points of CPU. P=1 is the chosen working point for
	// the Network Extension budget, not the faster one.
	fdbased.ResetPacketIOStats()
	ep, err := fdbased.New(&fdbased.Options{
		FDs:                  []int{t.tunFd},
		MTU:                  t.options.MTU,
		RXChecksumOffload:    true,
		ProcessorsPerChannel: 1,
		RecvMsgX:             t.options.EXP_RecvMsgX,
		SendMsgX:             t.options.EXP_SendMsgX,
	})
	if err != nil {
		return nil, stack.NICOptions{}, err
	}
	GVisorPacketIOSnapshot = func() GVisorPacketIOReport {
		snapshot := fdbased.PacketIOStatsSnapshot()
		return GVisorPacketIOReport{
			IngressReadCalls:       snapshot.IngressReadCalls,
			IngressReadWouldBlock:  snapshot.IngressReadWouldBlock,
			IngressReadPackets:     snapshot.IngressReadPackets,
			IngressReadBytes:       snapshot.IngressReadBytes,
			IngressReadErrors:      snapshot.IngressReadErrors,
			IngressDispatchPackets: snapshot.IngressDispatchPackets,
			IngressDispatchBytes:   snapshot.IngressDispatchBytes,
			ProcessorQueueDepth:    snapshot.ProcessorQueueDepth,
			ProcessorQueuePeak:     snapshot.ProcessorQueuePeak,
			EgressWriteCalls:       snapshot.EgressWriteCalls,
			EgressWritePackets:     snapshot.EgressWritePackets,
			EgressWriteBytes:       snapshot.EgressWriteBytes,
			EgressWriteErrors:      snapshot.EgressWriteErrors,
		}
	}
	return ep, stack.NICOptions{
		QDisc: fifo.New(ep, 1, 1000),
	}, nil
}
