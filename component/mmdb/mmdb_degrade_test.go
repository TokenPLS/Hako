package mmdb

import (
	"net"
	"testing"
)

// A geodata file that will not open must not stop the process.
//
// These loaders called log.Fatalln — os.Exit — and on a packet tunnel that
// means the extension vanishes: no crash report, no jetsam record, no error
// anywhere, and the reader is told only "the VPN tunnel provider stopped
// unexpectedly", which is the system guessing because nothing told it more.
// Traced from a device log where the extension went silent and died 1.1s after
// the core began loading a profile with four ipcidr rule sets.
//
// A database that will not open is a reason for GEOIP rules not to match. It is
// never a reason to stop.
func TestLookupsSurviveAnUnavailableDatabase(t *testing.T) {
	// The zero value is what the loaders now leave behind when the file is
	// unreadable; before this, reaching a lookup through it panicked.
	var ip IPReader
	if codes := ip.LookupCode(net.ParseIP("198.51.100.1")); len(codes) != 0 {
		t.Fatalf("an unavailable database matched something: %v", codes)
	}

	var asn ASNReader
	if number, org := asn.LookupASN(net.ParseIP("198.51.100.1")); number != "" || org != "" {
		t.Fatalf("an unavailable ASN database matched: %q %q", number, org)
	}
}

// A database whose type this build cannot read is the same situation as no
// database, and used to panic.
func TestAnUnknownDatabaseTypeDoesNotPanic(t *testing.T) {
	reader := IPReader{Reader: nil, databaseType: 99}
	if codes := reader.LookupCode(net.ParseIP("198.51.100.1")); len(codes) != 0 {
		t.Fatalf("unknown type matched: %v", codes)
	}
}
