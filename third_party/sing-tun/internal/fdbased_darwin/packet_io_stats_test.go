package fdbased

import (
	"sync"
	"testing"
)

func TestFramedPacketPayloadBytesExcludesDarwinFamilyHeader(t *testing.T) {
	for _, test := range []struct {
		name string
		wire int
		want int
	}{
		{name: "empty", wire: 0, want: 0},
		{name: "header-only", wire: 4, want: 0},
		{name: "ipv4-payload", wire: 1_504, want: 1_500},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := framedPacketPayloadBytes(test.wire); got != test.want {
				t.Fatalf("framedPacketPayloadBytes(%d) = %d, want %d", test.wire, got, test.want)
			}
		})
	}
}

func TestPacketIOStatsAccumulateAndReset(t *testing.T) {
	ResetPacketIOStats()
	recordIngressRead(100, 1)
	recordIngressRead(300, 3)
	recordProcessorQueued()
	recordProcessorQueued()
	recordProcessorDequeued(1)
	recordIngressDispatch(96)
	recordEgressWriteAttempt()
	recordEgressWriteSuccess(2, 200)
	recordEgressWriteAttempt()
	recordEgressWriteError()

	got := PacketIOStatsSnapshot()
	want := PacketIOStats{
		IngressReadPackets:     4,
		IngressReadBytes:       400,
		IngressDispatchPackets: 1,
		IngressDispatchBytes:   96,
		ProcessorQueueDepth:    1,
		ProcessorQueuePeak:     2,
		EgressWriteCalls:       2,
		EgressWritePackets:     2,
		EgressWriteBytes:       200,
		EgressWriteErrors:      1,
	}
	if got != want {
		t.Fatalf("snapshot = %#v, want %#v", got, want)
	}

	ResetPacketIOStats()
	if got := PacketIOStatsSnapshot(); got != (PacketIOStats{}) {
		t.Fatalf("reset snapshot = %#v, want zero", got)
	}
}

func TestPacketIOStatsAreRaceFree(t *testing.T) {
	ResetPacketIOStats()
	const workers = 16
	const iterations = 1_000
	var wait sync.WaitGroup
	wait.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			defer wait.Done()
			for iteration := 0; iteration < iterations; iteration++ {
				recordIngressRead(64, 1)
				recordProcessorQueued()
				recordProcessorDequeued(1)
				recordIngressDispatch(60)
				recordEgressWriteAttempt()
				recordEgressWriteSuccess(1, 64)
			}
		}()
	}
	wait.Wait()

	want := uint64(workers * iterations)
	got := PacketIOStatsSnapshot()
	if got.IngressReadPackets != want || got.IngressDispatchPackets != want || got.EgressWritePackets != want {
		t.Fatalf("packet counts = read %d dispatch %d write %d, want %d", got.IngressReadPackets, got.IngressDispatchPackets, got.EgressWritePackets, want)
	}
	if got.ProcessorQueueDepth != 0 || got.ProcessorQueuePeak == 0 {
		t.Fatalf("queue depth/peak = %d/%d, want 0/positive", got.ProcessorQueueDepth, got.ProcessorQueuePeak)
	}
}
