package rawfile

import (
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPacketReadStatsClassifySyscallResults(t *testing.T) {
	ResetPacketReadStats()
	recordPacketReadResult(0)
	recordPacketReadResult(unix.EWOULDBLOCK)
	recordPacketReadResult(unix.EIO)

	want := PacketReadStats{Syscalls: 3, WouldBlock: 1, Errors: 1}
	if got := PacketReadStatsSnapshot(); got != want {
		t.Fatalf("snapshot = %#v, want %#v", got, want)
	}

	ResetPacketReadStats()
	if got := PacketReadStatsSnapshot(); got != (PacketReadStats{}) {
		t.Fatalf("reset snapshot = %#v, want zero", got)
	}
}

func TestPacketReadStatsAreRaceFree(t *testing.T) {
	ResetPacketReadStats()
	const workers = 16
	const iterations = 1_000
	var wait sync.WaitGroup
	wait.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			defer wait.Done()
			for iteration := 0; iteration < iterations; iteration++ {
				recordPacketReadResult(0)
			}
		}()
	}
	wait.Wait()

	want := uint64(workers * iterations)
	if got := PacketReadStatsSnapshot(); got.Syscalls != want || got.WouldBlock != 0 || got.Errors != 0 {
		t.Fatalf("snapshot = %#v, want %d successful syscalls", got, want)
	}
}
