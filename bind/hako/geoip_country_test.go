package hako

import (
	"net/netip"
	"os"
	"testing"

	"github.com/TokenPLS/Hako/component/geodata"
	"github.com/TokenPLS/Hako/component/mmdb"
	C "github.com/TokenPLS/Hako/constant"
	"github.com/TokenPLS/Hako/rules/common"
)

// stageGeoIPDatabase puts the database the app ships where C.Path.MMDB() looks, and skips
// when the fixture is not in this checkout. It does not start a core: the whole point of
// this export is that it answers with Setup alone, on a stopped tunnel.
func stageGeoIPDatabase(t *testing.T) {
	t.Helper()
	options := testOptions(t)
	if err := os.MkdirAll(options.WorkingPath, 0o755); err != nil {
		t.Fatal(err)
	}
	stageBundledGeodata(t, options.WorkingPath)
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	C.SetHomeDir(options.WorkingPath)
	previous := geodata.GeodataMode()
	geodata.SetGeodataMode(false)
	t.Cleanup(func() { geodata.SetGeodataMode(previous) })
	if !mmdb.IPInstance().Available() {
		t.Skip("no GeoIP database seeded in this process")
	}
}

// The judgement this serves: the reader's real egress is in one country and the destination
// they are proxying to is in another, so traffic is going the long way round. The client can
// get the egress address on its own; what it cannot do without asking a third-party service,
// or opening geoip.metadb itself, is turn that address into a country.
func TestGeoIPCountryAgreesWithTheRuleThatWouldMatchIt(t *testing.T) {
	stageGeoIPDatabase(t)

	// Private space is in the list on purpose: the shipped database answers "private" for
	// it, which is a real record and a real rule (GEOIP,private). A caller must not read a
	// present answer as "this address is public".
	for _, address := range []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111", "192.168.1.1", "10.0.0.1"} {
		box := GeoIPCountryForIP(address)
		if box == nil {
			t.Logf("%s: no record in this database", address)
			continue
		}
		code := box.Value
		if code == "" {
			t.Fatalf("%s: a present box must carry a code, not an empty string", address)
		}
		// Upstream's own matcher is the yardstick: a code this reports that GEOIP,<code>
		// would not match is a second opinion, which is the thing this must never become.
		rule, err := common.NewGEOIP(code, "DIRECT", false, true)
		if err != nil {
			t.Fatalf("%s -> %q is not a country upstream can build a rule for: %v", address, code, err)
		}
		if !rule.MatchIp(netip.MustParseAddr(address)) {
			t.Fatalf("%s -> %q, but GEOIP,%s does not match it", address, code, code)
		}
	}
}

// Three different "cannot answer" cases collapse to one shape, because a caller that has to
// tell them apart in order to render "unknown" is being asked to carry a distinction it
// cannot act on. nil is absent; there is no sentinel string to compare against.
func TestGeoIPCountryIsAbsentRatherThanGuessing(t *testing.T) {
	stageGeoIPDatabase(t)

	for _, address := range []string{
		"",                // nothing asked
		"not-an-address",  // not an address
		"example.com",     // a name, not an address -- this does not resolve for you
		"1.1.1.1:443",     // an endpoint, not an address
		"1.1.1.1/24",      // a prefix, not an address
		"999.999.999.999", // shaped like one, is not one
	} {
		if box := GeoIPCountryForIP(address); box != nil {
			t.Fatalf("%q must answer nil, got %q", address, box.Value)
		}
	}
}

// An IPv4 written the v6 way is the same address, and a caller that got it from a socket
// may well have it in that form. Unmapping is upstream's own habit (LookupIPWithResolver
// does it) rather than a courtesy invented here.
func TestGeoIPCountryReadsAMappedAddressAsItsIPv4(t *testing.T) {
	stageGeoIPDatabase(t)

	plain := GeoIPCountryForIP("1.1.1.1")
	mapped := GeoIPCountryForIP("::ffff:1.1.1.1")
	switch {
	case plain == nil && mapped == nil:
		t.Skip("no record for 1.1.1.1 in this database")
	case plain == nil || mapped == nil:
		t.Fatalf("one form answered and the other did not: plain=%v mapped=%v", plain, mapped)
	case plain.Value != mapped.Value:
		t.Fatalf("::ffff:1.1.1.1 -> %q but 1.1.1.1 -> %q", mapped.Value, plain.Value)
	}
}
