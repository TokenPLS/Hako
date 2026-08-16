//go:build darwin && cgo

package hako

import "testing"

func TestProcessCPUTimeNanosecondsIsAvailableAndMonotonic(t *testing.T) {
	before := processCPUTimeNanoseconds()
	if before < 0 {
		t.Fatalf("process CPU time unavailable: %d", before)
	}

	// Exercise the current process so this also catches unit/scaling mistakes
	// without requiring the timer resolution to expose a strictly larger value.
	var sum uint64
	for i := uint64(0); i < 100_000; i++ {
		sum += i
	}
	if sum == 0 {
		t.Fatal("unreachable")
	}
	if after := processCPUTimeNanoseconds(); after < before {
		t.Fatalf("process CPU time moved backwards: before=%d after=%d", before, after)
	}
}
