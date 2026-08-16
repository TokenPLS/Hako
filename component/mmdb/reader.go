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

type IPReader struct {
	*maxminddb.Reader
	databaseType
}

type ASNReader struct {
	*maxminddb.Reader
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
	// No database, no match. Every caller already treats an empty result as
	// "this rule did not apply", so nothing downstream has to learn a new shape.
	if !r.available() {
		return []string{}
	}
	switch r.databaseType {
	case typeMaxmind:
		var country geoip2Country
		_ = r.Lookup(ipAddress, &country)
		if country.Country.IsoCode == "" {
			return []string{}
		}
		return []string{strings.ToLower(country.Country.IsoCode)}

	case typeSing:
		var code string
		_ = r.Lookup(ipAddress, &code)
		if code == "" {
			return []string{}
		}
		return []string{code}

	case typeMetaV0:
		var record any
		_ = r.Lookup(ipAddress, &record)
		switch record := record.(type) {
		case string:
			return []string{record}
		case []any: // lookup returned type of slice is []any
			result := make([]string, 0, len(record))
			for _, item := range record {
				result = append(result, item.(string))
			}
			return result
		}
		return []string{}

	default:
		// A database of a type this build does not read is the same situation
		// as no database at all. It used to panic, which on a packet tunnel is
		// indistinguishable from a crash and just as fatal.
		log.Warnln("Unknown geoip database type: %d; GEOIP rules will not match", r.databaseType)
		return []string{}
	}
}

func (r ASNReader) LookupASN(ip net.IP) (string, string) {
	if !r.available() {
		return "", ""
	}
	switch r.Metadata.DatabaseType {
	case "GeoLite2-ASN", "DBIP-ASN-Lite (compat=GeoLite2-ASN)":
		var result GeoLite2
		_ = r.Lookup(ip, &result)
		return fmt.Sprint(result.AutonomousSystemNumber), result.AutonomousSystemOrganization
	case "ipinfo generic_asn_free.mmdb":
		var result IPInfo
		_ = r.Lookup(ip, &result)
		return result.ASN[2:], result.Name
	default:
		log.Warnln("Unsupported ASN type: %s", r.Metadata.DatabaseType)
	}
	return "", ""
}
