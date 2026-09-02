package hako

import (
	"fmt"
	"strings"

	"github.com/TokenPLS/Hako/component/geodata"
	georouter "github.com/TokenPLS/Hako/component/geodata/router"
	"github.com/TokenPLS/Hako/component/mmdb"
	"github.com/oschwald/maxminddb-golang"
	"google.golang.org/protobuf/proto"
)

// The .dat ceiling is the core's own, not a second number that happens to
// match it today: geodata.MaxDatFileBytes is what the updater and startup
// download a .dat under, and a file this pipeline accepts has to be one the
// core will take a refresh of. An MMDB is held to the smaller number the core
// opens it at, in validateMMDBGeodata.
const maximumGeodataResourceBytes int64 = geodata.MaxDatFileBytes

// ValidateGeodataForIOS validates the exact local file the containing App
// intends to publish. It performs no network access and does not depend on
// Setup or process-global mihomo paths, so clients can preflight an immutable
// candidate before switching the active revision.
//
// Supported kind/format pairs are the pairs emitted by
// PlanResourcesForIOS: geoip/mmdb, geoip/dat, geosite/dat and asn/mmdb.
func ValidateGeodataForIOS(kind, format, path string) error {
	_, _, _, err := validateGeodataFile(kind, format, path)
	return bridgeSafeError(err)
}

// validateGeodataFile normalizes kind/format, reads the file ONCE, and runs the
// file-level validation on those bytes. The payload is returned so per-code
// checks run on the same bytes the file-level verdict was about -- the first
// version of the scoped entry point read the file twice, which was 2x the I/O
// on a file this admits at up to 128 MiB and a window in which the two reads
// could disagree. The bound itself depends on the format -- see below.
func validateGeodataFile(kind, format, path string) (string, string, []byte, error) {
	kind = strings.ToLower(strings.TrimSpace(kind))
	format = strings.ToLower(strings.TrimSpace(format))
	if !((kind == "geoip" && (format == "mmdb" || format == "dat")) ||
		(kind == "geosite" && format == "dat") ||
		(kind == "asn" && format == "mmdb")) {
		return "", "", nil, fmt.Errorf("hako: unsupported geodata kind/format %q/%q", kind, format)
	}
	// The ceiling is chosen from the FORMAT, before a byte is read. An MMDB
	// is held to what the core will open it at (mmdb.MaxDatabaseBytes); only a
	// .dat gets the larger allowance, because a .dat carrying all of GeoIP or
	// GeoSite really is that big. Reading with the larger number and rejecting
	// afterwards meant a 100 MiB MMDB was read in full -- twice over, counting
	// the caller's copy -- before anything said no.
	limit := maximumGeodataResourceBytes
	if format == "mmdb" {
		limit = mmdb.MaxDatabaseBytes
	}
	payload, err := readBoundedRegularFile(path, limit, "geodata")
	if err != nil {
		return "", "", nil, err
	}
	switch {
	case kind == "geoip" && format == "mmdb":
		err = validateMMDBGeodata(payload, false)
	case kind == "geoip" && format == "dat":
		err = validateGeoIPDat(payload)
	case kind == "geosite" && format == "dat":
		err = validateGeoSiteDat(payload)
	case kind == "asn" && format == "mmdb":
		err = validateMMDBGeodata(payload, true)
	}
	if err != nil {
		return "", "", nil, err
	}
	return kind, format, payload, nil
}

func validateMMDBGeodata(payload []byte, asn bool) error {
	// The App's verdict has to be the runtime's verdict. maximumGeodataResourceBytes
	// admits 128 MiB because a .dat can genuinely be that big; an MMDB is held to
	// the number component/mmdb will actually open it at (mmdb.MaxDatabaseBytes),
	// because the App publishes what it validates and the extension cannot repair
	// a published file -- the download URLs are rewritten away by then. A file the
	// two layers disagree about is a profile whose GEOIP and IP-ASN rules build
	// nothing, with a "validated and saved" on the record.
	if int64(len(payload)) > mmdb.MaxDatabaseBytes {
		return fmt.Errorf("hako: MMDB geodata is %d bytes, larger than the %d MiB the core opens",
			len(payload), mmdb.MaxDatabaseBytes>>20)
	}
	reader, err := maxminddb.FromBytes(payload)
	if err != nil {
		return fmt.Errorf("hako: invalid MMDB geodata: %w", err)
	}
	defer reader.Close()
	if reader.Metadata.NodeCount == 0 {
		return fmt.Errorf("hako: MMDB geodata has empty metadata")
	}
	if !databaseTypeIsUsable(reader.Metadata.DatabaseType) {
		kind := "GeoIP"
		if asn {
			kind = "ASN"
		}
		return fmt.Errorf("hako: %s MMDB declares no database type; the file is "+
			"most likely truncated or not an MMDB", kind)
	}
	return nil
}

// databaseTypeIsUsable is the whole of Hako's opinion about an MMDB's declared
// type: it must not be blank.
//
// An earlier comment here said the two behaviours "reduce to the type label is
// not blank, because that is where upstream draws the line for each of them".
// Upstream draws no line at all. `mmdb.Verify` (component/mmdb/mmdb.go:46-52) is
// `maxminddb.Open(path) == nil` and never reads the field; `IPInstance` maps any
// unrecognised type to typeMaxmind, and `ASNInstance` does not inspect it. A
// blank type loads everywhere upstream.
//
// The non-blank requirement is kept anyway, and named as ours rather than
// upstream's: a database that declares no type at all is the signature of a
// truncated or wrong-format download, which is the failure this preflight is for.
// It is deliberately the only content rule left -- the three-name ASN allow-list
// that used to sit here refused GeoIP2-ISP, DB-IP's non-compat spelling and
// ipinfo's paid build, all of which upstream loads.
//
// One predicate, not two: after the allow-list went, the GeoIP and ASN forms were
// byte-identical, and keeping both names implied a distinction the tree no longer
// makes. Worth stating plainly: nothing here can tell an ASN database from a
// GeoIP one, so ValidateGeodataForIOS("asn", ...) will accept a country database
// and vice versa. Upstream is the same -- it discovers the mismatch at lookup
// time, where LookupASN's default branch warns and returns empty
// (component/mmdb/reader.go:75-89). That warning is per ASN rule evaluation, i.e.
// per connection (rules/common/ipasn.go:31), so the cost of a wrong-typed ASN
// database is a log line per connection rather than a broken tunnel.
func databaseTypeIsUsable(databaseType string) bool {
	return strings.TrimSpace(databaseType) != ""
}

// A .dat validator has two jobs and they are not the same job. One is "can this
// file be read at all", which is a property of the file and belongs here. The
// other is "does the category my config names actually build", which is a
// property of one entry and belongs in ValidateGeodataCodesForIOS, because that
// is the only scope upstream ever judges content at: every loader resolves a
// .dat by finding the FIRST entry whose code matches the requested code and
// stops (component/geodata/standard/standard.go:38-44, and memconservative by
// byte-scanning for the same thing), then builds a matcher from that entry
// alone. A malformed CIDR under `us` makes `GEOIP,US` fail and leaves `GEOIP,CN`
// working; it never stops the file from loading.
//
// So the file-level rules below are down to two, and both are about reading:
// the protobuf parses, and no entry carries a blank country code.
//
// Duplicate codes and empty categories are accepted -- first-match-wins makes a
// later duplicate unreachable and an empty category yields a matcher that
// matches nothing, neither of which is an error upstream. Note what the
// duplicate case does NOT mean: a shadowed entry's contents are inert, not
// merged, so concatenating two .dat files adds only the codes the first lacks.
//
// An empty file is accepted for the same reason: upstream reports "country %s
// not found" when a code is looked up, and only then.
//
// A blank code is different, and the difference is memory. iOS forces
// memconservative (runtime_profile.go:151, config_pipeline.go:126) to keep the
// extension off the jetsam line, and that loader requires every entry to begin
// with field 1, byte 0x0A (component/geodata/memconservative/decode.go:44-48).
// proto3 omits an empty string field, so a blank-coded entry starts at 0x12 and
// the scan aborts; cache.go then falls back to os.ReadFile plus a full
// proto.Unmarshal of the entire list, once per requested code. The bundled
// GeoIP.dat is 17 MB and this validator admits 128 MB. One blank entry anywhere
// turns every lookup into a whole-file decode inside the extension, which is
// both stricter than upstream and platform-required -- the bar the rest failed.
func validateGeoIPDat(payload []byte) error {
	var list georouter.GeoIPList
	if err := proto.Unmarshal(payload, &list); err != nil {
		return fmt.Errorf("hako: invalid GeoIP.dat protobuf: %w", err)
	}
	for index, entry := range list.Entry {
		if strings.TrimSpace(entry.GetCountryCode()) == "" {
			return fmt.Errorf("hako: GeoIP.dat entry %d has a blank country code; "+
				"the memory-conservative loader iOS uses cannot scan past it", index)
		}
	}
	return nil
}

func validateGeoSiteDat(payload []byte) error {
	var list georouter.GeoSiteList
	if err := proto.Unmarshal(payload, &list); err != nil {
		return fmt.Errorf("hako: invalid GeoSite.dat protobuf: %w", err)
	}
	for index, entry := range list.Entry {
		if strings.TrimSpace(entry.GetCountryCode()) == "" {
			return fmt.Errorf("hako: GeoSite.dat entry %d has a blank country code; "+
				"the memory-conservative loader iOS uses cannot scan past it", index)
		}
	}
	return nil
}

// ValidateGeodataCodesForIOS is ValidateGeodataForIOS plus the per-code question:
// for each code in `codes`, does the category actually build? It answers by
// calling the kernel's own constructors, never rules of its own. For GeoIP that
// is NewGeoIPMatcher, the call LoadGeoIPMatcher makes
// (component/geodata/utils.go:180). For geosite the runtime has TWO
// constructors, chosen by the user-facing `geosite-matcher:` field
// (hub/executor/executor.go:422 -> SetSiteMatcher; succinct by default, mph on
// request, utils.go:137-141) -- and this preflight cannot see the config, so a
// category is accepted when EITHER constructor builds it and refused only when
// no matcher the runtime could choose would load it. That keeps the promise
// that matters -- never stricter than the kernel the user actually runs --
// at the cost of its converse: a category only one matcher accepts will pass
// here and still fail at load under the other, with mihomo's own message. The
// two genuinely disagree in both directions: the succinct trie refuses values
// mph accepts, and mph refuses domain types succinct silently skips.
//
// `codes` is comma- or whitespace-separated and normalized the way upstream
// normalizes a rule payload before lookup: lowercased, a leading '!' dropped
// (LoadGeoSiteMatcher, utils.go:74-81) and an '@attr' suffix dropped
// (utils.go:84-87), then matched with EqualFold (standard.go:39). Naming no
// codes is not an error -- it just asks nothing beyond the file-level check.
//
// Cost note: building a matcher is real work (geosite `cn` is ~90k domains and
// the succinct matcher builds a trie for them). This is a containing-App
// preflight, called before publishing a downloaded file, not something the
// extension runs; the matcher is dropped as soon as it is built.
//
// mmdb kinds have no per-code content to build -- a lookup is a tree walk, not a
// constructor -- so for those this is exactly ValidateGeodataForIOS.
func ValidateGeodataCodesForIOS(kind, format, path, codes string) error {
	normalizedKind, normalizedFormat, payload, err := validateGeodataFile(kind, format, path)
	if err != nil {
		return bridgeSafeError(err)
	}
	wanted := normalizeGeodataCodes(codes)
	if len(wanted) == 0 || normalizedFormat != "dat" {
		return nil
	}
	if normalizedKind == "geoip" {
		return bridgeSafeError(validateGeoIPDatCodes(payload, wanted))
	}
	return bridgeSafeError(validateGeoSiteDatCodes(payload, wanted))
}

func normalizeGeodataCodes(codes string) []string {
	fields := strings.FieldsFunc(codes, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
	normalized := make([]string, 0, len(fields))
	for _, field := range fields {
		code := strings.TrimSpace(field)
		code = strings.TrimPrefix(code, "!")
		if attribute := strings.IndexByte(code, '@'); attribute >= 0 {
			code = code[:attribute]
		}
		code = strings.TrimSpace(strings.ToLower(code))
		if code != "" {
			normalized = append(normalized, code)
		}
	}
	return normalized
}

func validateGeoIPDatCodes(payload []byte, codes []string) error {
	var list georouter.GeoIPList
	if err := proto.Unmarshal(payload, &list); err != nil {
		return fmt.Errorf("hako: invalid GeoIP.dat protobuf: %w", err)
	}
	for _, code := range codes {
		found := false
		for _, entry := range list.Entry {
			if !strings.EqualFold(entry.GetCountryCode(), code) {
				continue
			}
			found = true
			if _, err := georouter.NewGeoIPMatcher(entry.GetCidr()); err != nil {
				return fmt.Errorf("hako: GeoIP.dat country %q does not load: %w", code, err)
			}
			break
		}
		if !found {
			return fmt.Errorf("hako: GeoIP.dat has no country %q", code)
		}
	}
	return nil
}

func validateGeoSiteDatCodes(payload []byte, codes []string) error {
	var list georouter.GeoSiteList
	if err := proto.Unmarshal(payload, &list); err != nil {
		return fmt.Errorf("hako: invalid GeoSite.dat protobuf: %w", err)
	}
	for _, code := range codes {
		found := false
		for _, entry := range list.Entry {
			if !strings.EqualFold(entry.GetCountryCode(), code) {
				continue
			}
			found = true
			_, succinctErr := georouter.NewSuccinctMatcherGroup(entry.GetDomain())
			if succinctErr != nil {
				if _, mphErr := georouter.NewMphMatcherGroup(entry.GetDomain()); mphErr != nil {
					return fmt.Errorf("hako: GeoSite.dat list %q does not load under either matcher: %v (succinct); %v (mph)", code, succinctErr, mphErr)
				}
			}
			break
		}
		if !found {
			return fmt.Errorf("hako: GeoSite.dat has no list %q", code)
		}
	}
	return nil
}
