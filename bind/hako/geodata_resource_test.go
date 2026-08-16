package hako

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	georouter "github.com/TokenPLS/Hako/component/geodata/router"
	"google.golang.org/protobuf/proto"
)

func writeGeodataFixture(t *testing.T, payload []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "resource")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestValidateGeoIPDatForIOS(t *testing.T) {
	payload, err := proto.Marshal(&georouter.GeoIPList{Entry: []*georouter.GeoIP{{
		CountryCode: "CN",
		Cidr: []*georouter.CIDR{{
			Ip:     []byte{1, 1, 1, 0},
			Prefix: 24,
		}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateGeodataForIOS("geoip", "dat", writeGeodataFixture(t, payload)); err != nil {
		t.Fatalf("valid GeoIP.dat rejected: %v", err)
	}
}

func TestValidateGeoSiteDatForIOS(t *testing.T) {
	payload, err := proto.Marshal(&georouter.GeoSiteList{Entry: []*georouter.GeoSite{{
		CountryCode: "private",
		Domain: []*georouter.Domain{{
			Type:  georouter.Domain_Domain,
			Value: "example.com",
		}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateGeodataForIOS("geosite", "dat", writeGeodataFixture(t, payload)); err != nil {
		t.Fatalf("valid GeoSite.dat rejected: %v", err)
	}
}

func TestSupportedGeoIPDatabaseTypeMirrorsUpstreamTypeMaxmind(t *testing.T) {
	// Upstream component/mmdb loads any DatabaseType as a MaxMind country DB
	// (named sing-geoip/Meta-geoip0 fast paths, everything else via default:
	// typeMaxmind, which reads country.iso_code), so an allow-list of type labels
	// would reject valid MaxMind country DBs it uses. Any non-empty type is
	// accepted; only an empty type is rejected.
	for _, dbType := range []string{
		"GeoIP2-Enterprise",
		"GeoIP2-Precision-Enterprise",
		"DBIP-Location-ISP (compat=Enterprise)",
		"a-custom-typed-geoip-db",
		"sing-geoip",
		"Meta-geoip0",
		"GeoLite2-Country",
		"GeoIP2-City",
	} {
		if !databaseTypeIsUsable(dbType) {
			t.Errorf("GeoIP MMDB type %q must be accepted (upstream typeMaxmind loads it)", dbType)
		}
	}
	for _, empty := range []string{"", "   "} {
		if databaseTypeIsUsable(empty) {
			t.Errorf("empty GeoIP MMDB type %q must be rejected", empty)
		}
	}
}

func TestValidateGeodataRejectsMalformedAndMismatchedResources(t *testing.T) {
	path := writeGeodataFixture(t, []byte("not geodata"))
	for _, test := range []struct {
		kind, format string
	}{
		{"geoip", "dat"},
		{"geoip", "mmdb"},
		{"geosite", "dat"},
		{"asn", "mmdb"},
		{"asn", "dat"},
	} {
		if err := ValidateGeodataForIOS(test.kind, test.format, path); err == nil {
			t.Errorf("malformed %s/%s resource accepted", test.kind, test.format)
		}
	}
}

func TestValidateGeodataRejectsSymlinkAndOversizedFile(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := ValidateGeodataForIOS("geoip", "dat", link); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("symlink was not rejected: %v", err)
	}

	oversized := filepath.Join(directory, "oversized")
	file, err := os.Create(oversized)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maximumGeodataResourceBytes + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ValidateGeodataForIOS("geoip", "dat", oversized); err == nil || !strings.Contains(err.Error(), "size") {
		t.Fatalf("oversized file was not rejected: %v", err)
	}
}

// An ASN database whose DatabaseType is not one of the three strings the
// allow-list names is still a database upstream loads. `LookupASN`
// (component/mmdb/reader.go:75-89) switches on the type, and its default branch
// logs "Unsupported ASN type" and returns ("", "") -- it does not error and it
// does not stop the reader being constructed. So on desktop the config starts,
// ASN rules simply never match; refusing the resource here turns that into a
// config that will not start at all on iOS.
//
// The names below are real shipping products, not invented ones: MaxMind
// renamed its Lite ASN build, DB-IP publishes the non-compat spelling, and
// ipinfo's paid tier ships a different filename in the same field.
func TestASNDatabaseTypeIsNotAnAllowList(t *testing.T) {
	for _, databaseType := range []string{
		"DBIP-ASN-Lite",
		"GeoIP2-ISP",
		"ipinfo standard_asn.mmdb",
		"GeoLite2-ASN-CSV",
	} {
		if !databaseTypeIsUsable(databaseType) {
			t.Errorf("rejected %q, which upstream loads and reads (it warns and "+
				"returns empty for the lookup, it does not refuse the database)",
				databaseType)
		}
	}
}

// Concatenating .dat files yields duplicate codes, and duplicates are not an
// error -- but not for the reason the first version of this comment gave.
//
// It claimed the merged file "resolves exactly like the official one plus the
// additions". That is wrong, and it contradicted the sentence beside it: first
// match wins, so a second entry under a code the official file already carries
// is never reached and its domains are dead weight. Appending only adds
// categories whose codes are NEW. Measured on this fixture: GEOSITE,cn resolves
// to [example.cn] and private.example is unreachable.
//
// What survives is the narrow claim, which is the one that matters here:
// upstream reads a file with duplicate codes without complaint -- linear scan,
// first match, stop (component/geodata/standard/standard.go:47-60; the
// memconservative byte scan Hako forces on iOS does the same). Refusing the
// whole file turns "some appended entries are inert" into "nothing loads", which
// is strictly worse for the user and is a rule upstream does not have.
func TestConcatenatedDatIsNotADuplicateCodeError(t *testing.T) {
	marshal := func(code, domain string) []byte {
		list := &georouter.GeoSiteList{Entry: []*georouter.GeoSite{{
			CountryCode: code,
			Domain: []*georouter.Domain{
				{Type: georouter.Domain_Domain, Value: domain},
			},
		}}}
		encoded, err := proto.Marshal(list)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	merged := append(marshal("cn", "example.cn"), marshal("cn", "private.example")...)

	var parsed georouter.GeoSiteList
	if err := proto.Unmarshal(merged, &parsed); err != nil {
		t.Fatalf("fixture does not reproduce the shape: %v", err)
	}
	if len(parsed.Entry) != 2 {
		t.Fatalf("fixture does not reproduce the shape: %d entries", len(parsed.Entry))
	}

	if err := validateGeoSiteDat(merged); err != nil {
		t.Fatalf("rejected a merged GeoSite.dat that upstream resolves: %v", err)
	}
}

// The GeoIP half of the same shape.
func TestConcatenatedGeoIPDatIsNotADuplicateCodeError(t *testing.T) {
	marshal := func(code string, ip []byte, prefix uint32) []byte {
		list := &georouter.GeoIPList{Entry: []*georouter.GeoIP{{
			CountryCode: code,
			Cidr:        []*georouter.CIDR{{Ip: ip, Prefix: prefix}},
		}}}
		encoded, err := proto.Marshal(list)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	merged := append(
		marshal("cn", []byte{1, 0, 0, 0}, 8),
		marshal("cn", []byte{203, 0, 113, 0}, 24)...,
	)
	if err := validateGeoIPDat(merged); err != nil {
		t.Fatalf("rejected a merged GeoIP.dat that upstream resolves: %v", err)
	}
}

// A blank CountryCode has to stay rejected, and the reason is the loader iOS
// actually runs.
//
// The runtime profile forces `memconservative` (runtime_profile.go:151,
// config_pipeline.go:126) precisely to keep the extension's heap down. That
// loader does not `proto.Unmarshal` the file: it hand-scans the wire format and
// requires every entry to begin with field 1, `0x0A`
// (component/geodata/memconservative/decode.go:44-48). proto3 omits an empty
// string field entirely, so an entry with a blank CountryCode starts at `0x12`
// and the scan aborts with errInvalidGeodataFile.
//
// What happens next is the memory event: cache.go:54-64 catches that and falls
// back to `os.ReadFile` plus a full `proto.Unmarshal` of the entire list, once
// per requested country code. The bundled GeoIP.dat is 17 MB and the validator
// admits files up to 128 MB, against a Network Extension living under roughly
// 50 MiB. One blank entry anywhere in the file converts every geoip lookup into
// a whole-file decode.
//
// So this one is stricter than upstream AND platform-required, which is the bar
// -- unlike the duplicate-code and empty-list rules deleted alongside it, which
// were stricter than upstream and cost the extension nothing.
func TestBlankCountryCodeStaysRejected(t *testing.T) {
	blank, err := proto.Marshal(&georouter.GeoIPList{Entry: []*georouter.GeoIP{
		{CountryCode: "cn", Cidr: []*georouter.CIDR{{Ip: []byte{1, 0, 0, 0}, Prefix: 8}}},
		{CountryCode: "", Cidr: []*georouter.CIDR{{Ip: []byte{9, 0, 0, 0}, Prefix: 8}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateGeoIPDat(blank); err == nil {
		t.Fatal("a blank CountryCode was accepted; memconservative aborts on it and " +
			"falls back to whole-file proto.Unmarshal inside the extension")
	}

	site, err := proto.Marshal(&georouter.GeoSiteList{Entry: []*georouter.GeoSite{
		{CountryCode: "", Domain: []*georouter.Domain{
			{Type: georouter.Domain_Domain, Value: "example.com"},
		}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateGeoSiteDat(site); err == nil {
		t.Fatal("a blank CountryCode was accepted in GeoSite.dat")
	}
}

// The other half of what 042a3785d deleted: an entry that names a code but
// carries no members. Restoring that rejection used to pass the whole suite,
// which meant nothing recorded the decision either way.
//
// Upstream builds a matcher from the empty list and it matches nothing --
// `trie.NewDomainSet()` returns nil for an empty trie and `Has` nil-guards
// (component/trie/domain_set.go:75-77); `NewGeoIPMatcher(nil)` constructs. An
// empty category is an empty result, not a broken file.
func TestEmptyCategoriesAreAcceptedNotRejected(t *testing.T) {
	ip, err := proto.Marshal(&georouter.GeoIPList{Entry: []*georouter.GeoIP{
		{CountryCode: "cn", Cidr: []*georouter.CIDR{{Ip: []byte{1, 0, 0, 0}, Prefix: 8}}},
		{CountryCode: "xx"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateGeoIPDat(ip); err != nil {
		t.Errorf("a GeoIP entry with no CIDRs was rejected: %v", err)
	}

	site, err := proto.Marshal(&georouter.GeoSiteList{Entry: []*georouter.GeoSite{
		{CountryCode: "cn", Domain: []*georouter.Domain{
			{Type: georouter.Domain_Domain, Value: "example.cn"},
		}},
		{CountryCode: "xx"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateGeoSiteDat(site); err != nil {
		t.Errorf("a GeoSite category with no domains was rejected: %v", err)
	}
}

// A defect inside one category must not refuse the file. Upstream resolves a .dat
// by finding the FIRST entry whose code matches the code that was asked for
// (component/geodata/standard/standard.go:38-44) and builds a matcher from that
// entry alone, so `NewGeoIPMatcher`'s "invalid IP" (condition.go:162-165) fails
// `us` and leaves `cn` working; on the geosite side the succinct matcher iOS uses
// by default (geoSiteMatcher = "succinct", utils.go:16 and :137-141) has no
// default branch in its type switch (condition.go:67-88), so a domain type it does
// not know is skipped without an error at all.
//
// An empty file is the same story: upstream reports "country %s not found" for the
// code that was asked for, and only then.
//
// What these whole-file rejections did: one bad byte in a category nobody
// references refused a .dat that the kernel would have loaded fine.
func TestPerEntryDefectsDoNotRefuseTheWholeFile(t *testing.T) {
	site := mustMarshalGeodata(t, &georouter.GeoSiteList{Entry: []*georouter.GeoSite{
		{CountryCode: "cn", Domain: []*georouter.Domain{
			{Type: georouter.Domain_Domain, Value: "example.cn"},
		}},
		{CountryCode: "broken", Domain: []*georouter.Domain{
			{Type: georouter.Domain_Type(99), Value: "example.invalid"}, // unknown type
			{Type: georouter.Domain_Full, Value: "   "},                 // unusable value
		}},
	}})
	if err := ValidateGeodataForIOS("geosite", "dat", writeGeodataFixture(t, site)); err != nil {
		t.Errorf("one bad category refused the whole GeoSite.dat: %v", err)
	}

	ip := mustMarshalGeodata(t, &georouter.GeoIPList{Entry: []*georouter.GeoIP{
		{CountryCode: "cn", Cidr: []*georouter.CIDR{{Ip: []byte{1, 0, 0, 0}, Prefix: 8}}},
		{CountryCode: "broken", Cidr: []*georouter.CIDR{
			{Ip: []byte{1, 2, 3}, Prefix: 8}, // not a 4- or 16-byte address
		}},
	}})
	if err := ValidateGeodataForIOS("geoip", "dat", writeGeodataFixture(t, ip)); err != nil {
		t.Errorf("one bad category refused the whole GeoIP.dat: %v", err)
	}

	// A list with no entries is content, and content-wise it is fine: upstream
	// only fails when a code is looked up and missing.
	if err := validateGeoIPDat(mustMarshalGeodata(t, &georouter.GeoIPList{})); err != nil {
		t.Errorf("a GeoIP.dat carrying no entries was refused: %v", err)
	}
	if err := validateGeoSiteDat(mustMarshalGeodata(t, &georouter.GeoSiteList{})); err != nil {
		t.Errorf("a GeoSite.dat carrying no entries was refused: %v", err)
	}

	// The boundary that stays, stated out loud so it is not mistaken for a
	// content rule: an empty list encodes to zero bytes, and a zero-length FILE
	// is refused by the shared read helper (resource_file.go:21) before any
	// format is known, for providers as much as geodata. That guard is stricter
	// than upstream -- proto.Unmarshal of nothing yields an empty list and every
	// lookup then reports "not found" -- and it is not platform-required either.
	// It is kept deliberately, on the one ground the deleted content rules could
	// not claim: the only file it can refuse is a file with no data in it, so it
	// cannot falsely reject anything a user actually has. Deleting it belongs to
	// an audit of the read path, not of geodata content.
	if err := ValidateGeodataForIOS("geoip", "dat", writeGeodataFixture(t, nil)); err == nil {
		t.Error("a zero-length file was accepted; the read-path guard is gone")
	}
}

// The scoped entry point is where per-code content is judged, and it judges it by
// running upstream's own constructor -- the same call the runtime makes -- so it
// cannot be stricter than the kernel by construction.
func TestScopedValidationJudgesOnlyTheRequestedCodes(t *testing.T) {
	ip := writeGeodataFixture(t, mustMarshalGeodata(t, &georouter.GeoIPList{Entry: []*georouter.GeoIP{
		{CountryCode: "cn", Cidr: []*georouter.CIDR{{Ip: []byte{1, 0, 0, 0}, Prefix: 8}}},
		{CountryCode: "us", Cidr: []*georouter.CIDR{{Ip: []byte{1, 2, 3}, Prefix: 8}}},
	}}))

	if err := ValidateGeodataCodesForIOS("geoip", "dat", ip, "cn"); err != nil {
		t.Errorf("a good code was failed by a bad sibling: %v", err)
	}
	err := ValidateGeodataCodesForIOS("geoip", "dat", ip, "cn,us")
	if err == nil {
		t.Fatal("a code that cannot build its matcher was accepted")
	}
	if !strings.Contains(err.Error(), `"us"`) {
		t.Errorf("the error does not name the code that failed: %v", err)
	}

	// Upstream normalizes before it looks up: EqualFold on the code
	// (standard.go:39), leading '!' and an '@attr' suffix stripped by
	// LoadGeoSiteMatcher (utils.go:74-87).
	site := writeGeodataFixture(t, mustMarshalGeodata(t, &georouter.GeoSiteList{Entry: []*georouter.GeoSite{
		{CountryCode: "cn", Domain: []*georouter.Domain{{Type: georouter.Domain_Domain, Value: "example.cn"}}},
	}}))
	for _, code := range []string{"cn", "CN", "!cn", "cn@ads", "!CN@ads", " cn "} {
		if err := ValidateGeodataCodesForIOS("geosite", "dat", site, code); err != nil {
			t.Errorf("code %q was not normalized the way upstream normalizes it: %v", code, err)
		}
	}

	if err := ValidateGeodataCodesForIOS("geosite", "dat", site, "nosuchcode"); err == nil {
		t.Error("a code the file does not carry was accepted")
	}

	// And it tracks the matchers exactly, including where they are lenient. An
	// unknown domain type falls through succinct's type switch with no default
	// and is silently skipped (condition.go:67-88); an invalid regex fails BOTH
	// constructors (both compile it via matcherTypeMap). Same file, same code
	// path, two different answers -- which is the point of asking the
	// constructors instead of writing our own rule. The both-fail vector is a
	// bad regex rather than a bad trie value, because a trie-invalid value like
	// "   " is exactly what mph accepts -- see
	// TestScopedValidationAcceptsWhatEitherRuntimeMatcherAccepts.
	mixed := writeGeodataFixture(t, mustMarshalGeodata(t, &georouter.GeoSiteList{Entry: []*georouter.GeoSite{
		{CountryCode: "skipped", Domain: []*georouter.Domain{
			{Type: georouter.Domain_Type(99), Value: "example.invalid"},
		}},
		{CountryCode: "broken", Domain: []*georouter.Domain{
			{Type: georouter.Domain_Regex, Value: "("},
		}},
	}}))
	if err := ValidateGeodataCodesForIOS("geosite", "dat", mixed, "skipped"); err != nil {
		t.Errorf("a domain type the matcher skips was treated as a failure: %v", err)
	}
	if err := ValidateGeodataCodesForIOS("geosite", "dat", mixed, "broken"); err == nil {
		t.Error("a value no matcher accepts was accepted")
	}
	// No codes named means no per-code opinion, which is what the unscoped entry
	// point already promises.
	if err := ValidateGeodataCodesForIOS("geoip", "dat", ip, "  "); err != nil {
		t.Errorf("naming no codes still judged the file: %v", err)
	}
}

func mustMarshalGeodata(t *testing.T, message proto.Message) []byte {
	t.Helper()
	encoded, err := proto.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// The runtime's geosite matcher is chosen by the user-facing `geosite-matcher:`
// field (config.go:437 -> executor.go:422 -> SetSiteMatcher; "mph"/"hybrid"
// selects NewMphMatcherGroup), and bind/hako neither strips nor reads that
// field. So a preflight judging with ONE constructor can be stricter than the
// kernel the user actually runs: the two disagree in both directions -- the
// succinct trie refuses a value like "   " that mph accepts, and mph errors on
// an unknown domain type that succinct silently skips. Acceptance is therefore
// the UNION: a category passes if either constructor builds it, and fails only
// when no matcher the runtime could choose would load it.
func TestScopedValidationAcceptsWhatEitherRuntimeMatcherAccepts(t *testing.T) {
	site := writeGeodataFixture(t, mustMarshalGeodata(t, &georouter.GeoSiteList{Entry: []*georouter.GeoSite{
		{CountryCode: "succinct-only", Domain: []*georouter.Domain{
			{Type: georouter.Domain_Type(99), Value: "example.invalid"}, // mph errors, succinct skips
		}},
		{CountryCode: "mph-only", Domain: []*georouter.Domain{
			{Type: georouter.Domain_Full, Value: "   "}, // succinct trie refuses, mph accepts
		}},
		{CountryCode: "neither", Domain: []*georouter.Domain{
			{Type: georouter.Domain_Regex, Value: "("}, // invalid regex fails both
		}},
	}}))
	if err := ValidateGeodataCodesForIOS("geosite", "dat", site, "succinct-only"); err != nil {
		t.Errorf("a category only the succinct matcher accepts was refused: %v", err)
	}
	if err := ValidateGeodataCodesForIOS("geosite", "dat", site, "mph-only"); err != nil {
		t.Errorf("a category only the mph matcher accepts was refused: %v", err)
	}
	err := ValidateGeodataCodesForIOS("geosite", "dat", site, "neither")
	if err == nil {
		t.Fatal("a category no runtime matcher can build was accepted")
	}
	if !strings.Contains(err.Error(), "either matcher") {
		t.Errorf("the error should say both matchers were tried: %v", err)
	}
}
