//go:build unix

package adapter

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// errnoName gives the symbolic name ("EADDRNOTAVAIL"), which is what a reader
// can look up and what stays stable across platforms and locales -- unlike
// Errno.Error(), whose text is the operating system's and is localised on some.
func errnoName(errno syscall.Errno) string {
	return unix.ErrnoName(errno)
}
