//go:build !unix

package adapter

import "syscall"

// Platforms without golang.org/x/sys/unix report no symbolic name. The Kind and
// the verbatim message still travel; only the errno field is empty. Hako ships
// Apple platforms, but this tree builds for others and a gate runs `go build`
// for linux and darwin both.
func errnoName(syscall.Errno) string { return "" }
