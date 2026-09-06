package mmdb

import (
	C "github.com/TokenPLS/Hako/constant"
	"github.com/TokenPLS/Hako/log"
)

type databaseType = uint8

const (
	typeMaxmind databaseType = iota
	typeSing
	typeMetaV0
)

// The two databases this package serves, each with its own transaction and
// its own refcounted reader (publisher.go). IPInstance/ASNInstance seed them
// from disk on first use; PublishIP/PublishASN replace them.
//
// The seeding state lives in the publisher, under the same mutex as the
// transaction, rather than in a sync.Once out here: a Once cannot be undone,
// so a first update or an in-memory load that FAILED still counted as
// "seeded" and the valid database on disk was never opened again.
var (
	ipPublisher  = newPublisher("MMDB", func() string { return C.Path.MMDB() })
	asnPublisher = newPublisher("ASN", func() string { return C.Path.ASN() })
)

// Unavailable geodata must not take the process with it.
//
// These three loaders called log.Fatalln, which is os.Exit — on a phone that
// means the packet tunnel vanishes with no crash report, no error, and no way
// for the app to say what happened; the reader is told only "the VPN tunnel
// provider stopped unexpectedly", which is the system guessing. A database
// that will not open is a reason for GEOIP rules not to match. It is not a
// reason to stop.
func (r IPReader) available() bool  { return r.holder.available() || r.reader != nil }
func (r ASNReader) available() bool { return r.holder.available() || r.reader != nil }

// Available reports whether a lookup has a database to answer from -- the
// current snapshot behind the holder, or a bare Reader in a test-built value.
// A caller that used to read `.Reader == nil` for this was reading the wrong
// field once the holder carried the database (the embedded Reader stays nil
// in production), and a test that early-returned on it measured nothing.
func (r IPReader) Available() bool  { return r.available() }
func (r ASNReader) Available() bool { return r.available() }

// LoadFromBytes seeds the IP database from memory. Upstream's contract, kept:
// the first load wins, so a later IPInstance does not reopen the path over it.
func LoadFromBytes(buffer []byte) {
	// Bytes that do not parse seed nothing, so the file on disk is still
	// opened when something looks an address up.
	if err := ipPublisher.Adopt(buffer); err != nil {
		log.Errorln("Can't load mmdb: %s; GEOIP rules will not match", err.Error())
	}
}

// Verify answers whether the file at path is a database this package would
// open -- through openDatabaseFile, which is the only door there is.
//
// It used to call maxminddb.Open directly, and that was one yardstick too
// many: after the size ceiling arrived (open.go), initialisation could accept
// a valid but oversized database and report success, while the first lookup
// went through the bounded opener, refused the same file, and left GEOIP or
// IP-ASN rules matching nothing with no error anywhere. A check that answers
// differently from the thing it is checking for is worse than no check.
func Verify(path string) bool {
	instance, err := openDatabaseFile(path)
	if err == nil {
		instance.Close()
	}
	return err == nil
}

func IPInstance() IPReader {
	seedFromDisk(ipPublisher, "MMDB", "GEOIP rules")
	return IPReader{holder: ipPublisher.holder}
}

func ASNInstance() ASNReader {
	seedFromDisk(asnPublisher, "ASN", "IP-ASN rules")
	return ASNReader{holder: asnPublisher.holder}
}

// seedFromDisk opens a publisher's database on first use; reloadFromDisk is
// the explicit reload. Both go through the publisher, under the same mutex as
// the transaction, so neither can publish a stale reader over what a
// concurrent Publish committed. Failure leaves the holder as it was
// (unavailable on a first load, the previous reader on a reload) and says so;
// it never aborts.
func seedFromDisk(p *publisher, name, rules string) {
	if err := p.EnsureSeeded(); err != nil {
		log.Errorln("Can't load %s: %s; %s will not match", name, err.Error(), rules)
	}
}

func reloadFromDisk(p *publisher, name, rules string) {
	log.Infoln("Load %s file: %s", name, p.path())
	if err := p.Reopen(); err != nil {
		log.Errorln("Can't load %s: %s; %s will not match", name, err.Error(), rules)
	}
}

// ReloadIP re-opens the IP database from its path and publishes it. The
// updater no longer needs this -- PublishIP publishes the reader it verified
// -- but a caller that only knows "the file changed" still has a way to say
// so. A file that will not open leaves the current reader in place.
func ReloadIP() {
	reloadFromDisk(ipPublisher, "MMDB", "GEOIP rules")
}

func ReloadASN() {
	reloadFromDisk(asnPublisher, "ASN", "IP-ASN rules")
}

// PublishIP replaces the IP database file and its reader as one transaction
// (publisher.go): nothing on disk or in memory changes unless the new bytes
// open; the old reader is closed only when its last lookup lets go.
//
// The once is completed only AFTER a successful publish. Completing it first
// stranded a perfectly good database: an update that arrived before anything
// had looked an address up (a scheduled refresh at startup) marked the once
// done, then failed on its own bytes -- and every later IPInstance took the
// no-op once, so the valid file on disk was never opened and GEOIP matched
// nothing for the life of the process. A first use racing this serializes on
// the publisher's mutex either way, and both orders end on the new database.
func PublishIP(data []byte) error { return ipPublisher.Publish(data) }

// PublishASN is PublishIP for the ASN database.
func PublishASN(data []byte) error { return asnPublisher.Publish(data) }
