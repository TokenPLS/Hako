package geodata

import (
	"testing"

	"github.com/TokenPLS/Hako/component/mmdb"
)

// The MMDB download ceiling and the MMDB open ceiling are the same number.
//
// They are two constants because they bound different things -- what an
// endpoint may send (here, and component/updater/update_geo.go) and what a
// file on disk may weigh before this process reads or maps it
// (component/mmdb/open.go) -- and they live in two packages because
// component/mmdb cannot import this one: geodata publishes THROUGH mmdb.
// Nothing but this test stops them from drifting into a pair where a database
// downloads happily and then refuses to open.
func TestTheDownloadAndOpenCeilingsAgree(t *testing.T) {
	if MaxMMDBBytes != mmdb.MaxDatabaseBytes {
		t.Fatalf("MMDB download ceiling %d, open ceiling %d: a database that arrives must be a database that opens",
			MaxMMDBBytes, mmdb.MaxDatabaseBytes)
	}
}

// A .dat is not held to the MMDB ceiling.
//
// The two formats are not the same size, and for a while they shared a number:
// the updater refused a .dat over 64 MiB while the Apple pipeline installed
// one at up to 128 MiB, so a file that was already in use could never be
// refreshed. The ceilings are per format, and the .dat one is the larger.
func TestTheDatCeilingIsItsOwnAndLargerThanTheMMDBOne(t *testing.T) {
	if MaxDatFileBytes <= MaxMMDBBytes {
		t.Fatalf(".dat ceiling %d must be larger than the MMDB ceiling %d", MaxDatFileBytes, MaxMMDBBytes)
	}
}
