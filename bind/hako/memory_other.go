//go:build !darwin || !cgo

package hako

// startMemoryPressureMonitor is a no-op off darwin/cgo — the GCD
// memory-pressure source is Apple-specific. Present so Setup can
// call it unconditionally.
func startMemoryPressureMonitor() {}

// physFootprint is darwin-only; -1 elsewhere.
func physFootprint() int64 { return -1 }

// availableMemory is only available to an iOS app/extension process.
func availableMemory() int64 { return -1 }
