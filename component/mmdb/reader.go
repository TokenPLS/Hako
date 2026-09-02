package mmdb

import (
	"fmt"
	"net"
	"strings"

	"github.com/TokenPLS/Hako/log"
	"github.com/oschwald/maxminddb-golang"
)

type geoip2Country struct {
	Country struct {
		IsoCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

// IPReader is what lookups go through. In production it carries the holder and
// takes a reference-counted snapshot per lookup, so a publish never closes a
// reader mid-lookup; the direct reader and type are the legacy value shape,
// kept so a zero value and a hand-built value (the degrade tests) still answer
// "no match".
//
// The reader is NOT embedded and NOT exported. It used to be, and behind the
// holder it is always nil -- so a caller reaching for `IPInstance().Reader`,
// which was how this was used before the transaction, would compile and then
// nil-panic at the first lookup. An unexported field turns that into a
// compile error, which is the honest shape of the change: the way to ask
// whether there is a database is Available(), and the way to use one is
// LookupCode / LookupASN.
type IPReader struct {
	reader *maxminddb.Reader
	databaseType
	holder *readerHolder
}

type ASNReader struct {
	reader *maxminddb.Reader
	holder *readerHolder
}

type GeoLite2 struct {
	AutonomousSystemNumber       uint32 `maxminddb:"autonomous_system_number"`
	AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
}

type IPInfo struct {
	ASN  string `maxminddb:"asn"`
	Name string `maxminddb:"name"`
}

func (r IPReader) LookupCode(ipAddress net.IP) []string {
	// The production path: one reference for the duration of this lookup, so
	// a publish that lands meanwhile retires the old reader instead of
	// closing it under us.
	if r.holder != nil {
		s := r.holder.acquire()
		if s == nil {
			return []string{}
		}
		defer r.holder.release(s)
		return lookupCode(s.reader, s.databaseType, ipAddress)
	}
	// No database, no match. Every caller already treats an empty result as
	// "this rule did not apply", so nothing downstream has to learn a new shape.
	if r.reader == nil {
		return []string{}
	}
	return lookupCode(r.reader, r.databaseType, ipAddress)
}

func lookupCode(reader *maxminddb.Reader, kind databaseType, ipAddress net.IP) []string {
	switch kind {
	case typeMaxmind:
		var country geoip2Country
		_ = reader.Lookup(ipAddress, &country)
		if country.Country.IsoCode == "" {
			return []string{}
		}
		return []string{strings.ToLower(country.Country.IsoCode)}

	case typeSing:
		var code string
		_ = reader.Lookup(ipAddress, &code)
		if code == "" {
			return []string{}
		}
		return []string{code}

	case typeMetaV0:
		var record any
		_ = reader.Lookup(ipAddress, &record)
		switch record := record.(type) {
		case string:
			return []string{record}
		case []any: // lookup returned type of slice is []any
			result := make([]string, 0, len(record))
			for _, item := range record {
				// Checked, not asserted: a record like ["us", 7] is a
				// structurally valid database that opens, and an unchecked
				// assertion turns it into a panic -- inside the packet tunnel
				// that is the process dying with no crash report, which is
				// the outcome already ruled out for geo data.
				if code, ok := item.(string); ok {
					result = append(result, code)
				}
			}
			return result
		}
		return []string{}

	default:
		// A database of a type this build does not read is the same situation
		// as no database at all. It used to panic, which on a packet tunnel is
		// indistinguishable from a crash and just as fatal.
		log.Warnln("Unknown geoip database type: %d; GEOIP rules will not match", kind)
		return []string{}
	}
}

func (r ASNReader) LookupASN(ip net.IP) (string, string) {
	if r.holder != nil {
		s := r.holder.acquire()
		if s == nil {
			return "", ""
		}
		defer r.holder.release(s)
		return lookupASN(s.reader, ip)
	}
	if r.reader == nil {
		return "", ""
	}
	return lookupASN(r.reader, ip)
}

func lookupASN(reader *maxminddb.Reader, ip net.IP) (string, string) {
	switch reader.Metadata.DatabaseType {
	case "GeoLite2-ASN", "DBIP-ASN-Lite (compat=GeoLite2-ASN)":
		var result GeoLite2
		_ = reader.Lookup(ip, &result)
		return fmt.Sprint(result.AutonomousSystemNumber), result.AutonomousSystemOrganization
	case "ipinfo generic_asn_free.mmdb":
		var result IPInfo
		_ = reader.Lookup(ip, &result)
		// `AS13335` with the prefix taken off -- but only if it is there. A
		// record with no `asn`, or a one-character one, made this slice past
		// the end of the string and panic the tunnel.
		if len(result.ASN) < 2 || !strings.HasPrefix(result.ASN, "AS") {
			return "", result.Name
		}
		return result.ASN[2:], result.Name
	default:
		log.Warnln("Unsupported ASN type: %s", reader.Metadata.DatabaseType)
	}
	return "", ""
}
