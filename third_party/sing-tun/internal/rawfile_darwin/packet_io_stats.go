package rawfile

import (
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// PacketReadStats reports exact read-side syscall attempts for the active
// Darwin packet descriptor. It contains no packet contents or endpoint data.
type PacketReadStats struct {
	Syscalls   uint64
	WouldBlock uint64
	Errors     uint64
}

var packetReadCounters struct {
	syscalls   atomic.Uint64
	wouldBlock atomic.Uint64
	errors     atomic.Uint64
}

func ResetPacketReadStats() {
	packetReadCounters.syscalls.Store(0)
	packetReadCounters.wouldBlock.Store(0)
	packetReadCounters.errors.Store(0)
}

func PacketReadStatsSnapshot() PacketReadStats {
	return PacketReadStats{
		Syscalls:   packetReadCounters.syscalls.Load(),
		WouldBlock: packetReadCounters.wouldBlock.Load(),
		Errors:     packetReadCounters.errors.Load(),
	}
}

func recordPacketReadResult(errno unix.Errno) {
	packetReadCounters.syscalls.Add(1)
	if errno == unix.EWOULDBLOCK {
		packetReadCounters.wouldBlock.Add(1)
	} else if errno != 0 {
		packetReadCounters.errors.Add(1)
	}
}
