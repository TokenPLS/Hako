// Command gen writes the small MMDB fixtures next to this directory.
//
// Two pairs -- a country database and an ASN database, each in an "a" and a
// "b" version -- with the SAME prefix carrying DIFFERENT records, so a test can
// tell which file is live after a publish: 1.0.0.0/24 answers "aa"/"bb" and
// AS64500 "Fixture A"/AS64501 "Fixture B". IPv4-only trees keep each file a few
// hundred bytes. Run `go run .` in this directory to regenerate; the module
// pins the writer and the build epoch so the bytes are reproducible: run it
// twice and the four files compare equal (mmdbwriter stamps time.Now() into
// the metadata when the epoch is left zero).
package main

import (
	"log"
	"net"
	"os"
	"path/filepath"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

// pinnedBuildEpoch is the build timestamp written into every fixture. Fixed,
// so regenerating yields the same bytes; the reader test pins the same value.
const pinnedBuildEpoch = 1_700_000_000

func main() {
	out := ".."
	if len(os.Args) > 1 {
		out = os.Args[1]
	}
	_, prefix, err := net.ParseCIDR("1.0.0.0/24")
	if err != nil {
		log.Fatal(err)
	}
	writeCountry := func(name, code string) {
		tree, err := mmdbwriter.New(mmdbwriter.Options{
			DatabaseType: "GeoLite2-Country", RecordSize: 24, IPVersion: 4,
			Description: map[string]string{"en": "Hako test fixture " + name}, Languages: []string{"en"},
			BuildEpoch: pinnedBuildEpoch,
		})
		if err != nil {
			log.Fatal(err)
		}
		if err := tree.Insert(prefix, mmdbtype.Map{"country": mmdbtype.Map{"iso_code": mmdbtype.String(code)}}); err != nil {
			log.Fatal(err)
		}
		write(filepath.Join(out, name), tree)
	}
	writeASN := func(name string, asn uint32, org string) {
		tree, err := mmdbwriter.New(mmdbwriter.Options{
			DatabaseType: "GeoLite2-ASN", RecordSize: 24, IPVersion: 4,
			Description: map[string]string{"en": "Hako test fixture " + name}, Languages: []string{"en"},
			BuildEpoch: pinnedBuildEpoch,
		})
		if err != nil {
			log.Fatal(err)
		}
		if err := tree.Insert(prefix, mmdbtype.Map{
			"autonomous_system_number":       mmdbtype.Uint32(asn),
			"autonomous_system_organization": mmdbtype.String(org),
		}); err != nil {
			log.Fatal(err)
		}
		write(filepath.Join(out, name), tree)
	}
	// The shape the kernel actually consumes: mihomo's own `Meta-geoip0`
	// database carries NO description, which is exactly what makes
	// Reader.Verify() reject the real geoip.metadb. A fixture that has one
	// would have let a transaction gated on Verify look healthy while it
	// rejected every real GeoIP update.
	metaV0 := func(name string) {
		tree, err := mmdbwriter.New(mmdbwriter.Options{
			DatabaseType: "Meta-geoip0", RecordSize: 24, IPVersion: 4,
			BuildEpoch: pinnedBuildEpoch,
		})
		if err != nil {
			log.Fatal(err)
		}
		// A Meta-geoip0 record is a bare string or a list of them -- not
		// MaxMind's country.iso_code map. The real database answers with a
		// list, so this one does too.
		if err := tree.Insert(prefix, mmdbtype.Slice{mmdbtype.String("cc"), mmdbtype.String("dd")}); err != nil {
			log.Fatal(err)
		}
		write(filepath.Join(out, name), tree)
	}
	metaV0("metav0-no-description.mmdb")
	// Structurally valid databases carrying records the lookup code did not
	// expect. They open, so nothing upstream of the lookup rejects them, and
	// an unchecked assertion or slice on their records is a panic -- inside
	// the packet tunnel, a process death with no crash report.
	malformed := func(name, databaseType string, record mmdbtype.DataType) {
		tree, err := mmdbwriter.New(mmdbwriter.Options{
			DatabaseType: databaseType, RecordSize: 24, IPVersion: 4,
			BuildEpoch: pinnedBuildEpoch,
		})
		if err != nil {
			log.Fatal(err)
		}
		if err := tree.Insert(prefix, record); err != nil {
			log.Fatal(err)
		}
		write(filepath.Join(out, name), tree)
	}
	// A Meta-geoip0 list whose elements are not all strings.
	malformed("metav0-mixed-record.mmdb", "Meta-geoip0",
		mmdbtype.Slice{mmdbtype.String("us"), mmdbtype.Uint32(7)})
	// An ipinfo ASN record with an `asn` too short to have the `AS` prefix.
	malformed("ipinfo-short-asn.mmdb", "ipinfo generic_asn_free.mmdb",
		mmdbtype.Map{"asn": mmdbtype.String("A"), "name": mmdbtype.String("Fixture")})
	writeCountry("country-a.mmdb", "AA")
	writeCountry("country-b.mmdb", "BB")
	writeASN("asn-a.mmdb", 64500, "Fixture A")
	writeASN("asn-b.mmdb", 64501, "Fixture B")
}

func write(path string, tree *mmdbwriter.Tree) {
	f, err := os.Create(path)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := tree.WriteTo(f); err != nil {
		log.Fatal(err)
	}
	if err := f.Close(); err != nil {
		log.Fatal(err)
	}
}
