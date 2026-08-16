package fdbased

import (
	"sync/atomic"

	"github.com/metacubex/sing-tun/internal/rawfile_darwin"
)

// PacketIOStats is a cumulative, payload-free snapshot for one active fd-based
// endpoint. Hako permits only one active Core, so resetting it when a new
// endpoint is constructed gives each service generation a clean baseline.
type PacketIOStats struct {
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

var packetIOCounters struct {
	ingressReadPackets     atomic.Uint64
	ingressReadBytes       atomic.Uint64
	ingressDispatchPackets atomic.Uint64
	ingressDispatchBytes   atomic.Uint64
	processorQueueDepth    atomic.Uint64
	processorQueuePeak     atomic.Uint64
	egressWriteCalls       atomic.Uint64
	egressWritePackets     atomic.Uint64
	egressWriteBytes       atomic.Uint64
	egressWriteErrors      atomic.Uint64
}

// ResetPacketIOStats starts a new service-generation measurement window.
func ResetPacketIOStats() {
	rawfile.ResetPacketReadStats()
	packetIOCounters.ingressReadPackets.Store(0)
	packetIOCounters.ingressReadBytes.Store(0)
	packetIOCounters.ingressDispatchPackets.Store(0)
	packetIOCounters.ingressDispatchBytes.Store(0)
	packetIOCounters.processorQueueDepth.Store(0)
	packetIOCounters.processorQueuePeak.Store(0)
	packetIOCounters.egressWriteCalls.Store(0)
	packetIOCounters.egressWritePackets.Store(0)
	packetIOCounters.egressWriteBytes.Store(0)
	packetIOCounters.egressWriteErrors.Store(0)
}

// PacketIOStatsSnapshot returns a lock-free cumulative snapshot. Individual
// fields may advance between loads; consumers compare low-frequency deltas and
// do not require a transactionally consistent packet boundary.
func PacketIOStatsSnapshot() PacketIOStats {
	read := rawfile.PacketReadStatsSnapshot()
	return PacketIOStats{
		IngressReadCalls:       read.Syscalls,
		IngressReadWouldBlock:  read.WouldBlock,
		IngressReadPackets:     packetIOCounters.ingressReadPackets.Load(),
		IngressReadBytes:       packetIOCounters.ingressReadBytes.Load(),
		IngressReadErrors:      read.Errors,
		IngressDispatchPackets: packetIOCounters.ingressDispatchPackets.Load(),
		IngressDispatchBytes:   packetIOCounters.ingressDispatchBytes.Load(),
		ProcessorQueueDepth:    packetIOCounters.processorQueueDepth.Load(),
		ProcessorQueuePeak:     packetIOCounters.processorQueuePeak.Load(),
		EgressWriteCalls:       packetIOCounters.egressWriteCalls.Load(),
		EgressWritePackets:     packetIOCounters.egressWritePackets.Load(),
		EgressWriteBytes:       packetIOCounters.egressWriteBytes.Load(),
		EgressWriteErrors:      packetIOCounters.egressWriteErrors.Load(),
	}
}

func recordIngressRead(bytes int, packets uint64) {
	packetIOCounters.ingressReadPackets.Add(packets)
	if bytes > 0 {
		packetIOCounters.ingressReadBytes.Add(uint64(bytes))
	}
}

func recordIngressDispatch(bytes int) {
	packetIOCounters.ingressDispatchPackets.Add(1)
	if bytes > 0 {
		packetIOCounters.ingressDispatchBytes.Add(uint64(bytes))
	}
}

func recordProcessorQueued() {
	depth := packetIOCounters.processorQueueDepth.Add(1)
	for {
		peak := packetIOCounters.processorQueuePeak.Load()
		if depth <= peak || packetIOCounters.processorQueuePeak.CompareAndSwap(peak, depth) {
			return
		}
	}
}

func recordProcessorDequeued(packets uint64) {
	if packets == 0 {
		return
	}
	packetIOCounters.processorQueueDepth.Add(^(packets - 1))
}

func recordEgressWriteAttempt() {
	packetIOCounters.egressWriteCalls.Add(1)
}

func recordEgressWriteSuccess(packets uint64, bytes uint64) {
	packetIOCounters.egressWritePackets.Add(packets)
	packetIOCounters.egressWriteBytes.Add(bytes)
}

func recordEgressWriteError() {
	packetIOCounters.egressWriteErrors.Add(1)
}
