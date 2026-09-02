package mmdb

import (
	"fmt"
	"os"
)

// MaxDatabaseBytes bounds the database file this package will open, whether it
// arrived from an update or was placed on disk by hand.
//
// The bound is not decoration on Windows: openDatabaseFile reads the file into
// the heap there (open_windows.go says why), so an oversized file is an
// allocation of that size, and a replacement holds the old reader's copy and
// the new one at the same time. Mapping is cheaper but not free either -- it
// spends address space and the parse walks the metadata. The real databases
// here are 9-12 MiB; geodata.MaxDatabaseBytes bounds the download that
// produces them and is the same number by construction.
const MaxDatabaseBytes int64 = 64 << 20

// checkDatabaseSize refuses an oversized file before anything reads or maps
// it. The size comes from the open handle where the caller has one, so the
// answer describes the file that is about to be read rather than whatever the
// path pointed at a moment earlier.
func checkDatabaseSize(path string, size int64) error {
	if size > MaxDatabaseBytes {
		return fmt.Errorf("mmdb: %s is %d bytes, larger than the %d MiB this opens", path, size, MaxDatabaseBytes>>20)
	}
	return nil
}

// statDatabaseSize is checkDatabaseSize for the caller that has only a path.
func statDatabaseSize(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	return checkDatabaseSize(path, info.Size())
}
