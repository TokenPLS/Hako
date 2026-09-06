//go:build !darwin || !cgo

package hako

// processCPUTimeNanoseconds is unavailable outside Darwin/cgo builds.
func processCPUTimeNanoseconds() int64 { return -1 }
