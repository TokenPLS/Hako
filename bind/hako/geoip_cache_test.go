package hako

import (
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/TokenPLS/Hako/component/geodata"
	C "github.com/TokenPLS/Hako/constant"
)

func countriesIn(t *testing.T, content string) []string {
	t.Helper()
	found := GeoIPCountriesIn(content)
	slices.Sort(found)
	return found
}

func TestGeoIPCountriesInReadsBothRuleSpellings(t *testing.T) {
	found := countriesIn(t, `rules:
  - GEOIP,cn,DIRECT
  - GEOIP,us,PROXY,no-resolve
  - SRC-GEOIP,jp,DIRECT
  - GEOIP, hk ,DIRECT
`)
	for _, want := range []string{"cn", "us", "jp", "hk"} {
		if !slices.Contains(found, want) {
			t.Fatalf("missed %q in %v", want, found)
		}
	}
}

// The trap this extractor exists to avoid. dns.fallback-filter.geoip is a BOOLEAN, so a
// scanner that treats "geoip:" as a reference the way "geosite:" is one would compile a
// country code named "true". Geosite has a geosite: token form; geoip has none.
func TestGeoIPCountriesInDoesNotReadTheFallbackFilterBoolean(t *testing.T) {
	found := countriesIn(t, `dns:
  fallback-filter:
    geoip: true
    geoip-code: CN
`)
	if slices.Contains(found, "true") {
		t.Fatalf("read the fallback-filter boolean as a country code: %v", found)
	}
	// geoip-code names a real country and must be collected, structurally.
	if !slices.Contains(found, "cn") {
		t.Fatalf("missed the fallback-filter geoip-code: %v", found)
	}
}

// Negation and logic rules are both spellings a configuration can carry.
func TestGeoIPCountriesInHandlesNegationAndLogicRules(t *testing.T) {
	found := countriesIn(t, `rules:
  - GEOIP,!cn,PROXY
  - AND,((GEOIP,us),(DST-PORT,443)),DIRECT
`)
	// !cn and cn read the same artifact, so the negation must not become part of the name.
	if slices.Contains(found, "!cn") {
		t.Fatalf("collected a negated name that no lookup uses: %v", found)
	}
	for _, want := range []string{"cn", "us"} {
		if !slices.Contains(found, want) {
			t.Fatalf("missed %q in %v", want, found)
		}
	}
}

// lan is handled before any matcher is loaded (rules/common/geoip.go), so compiling it
// would always fail and report a failure that is not one.
func TestGeoIPCountriesInSkipsLan(t *testing.T) {
	if found := countriesIn(t, "rules:\n  - GEOIP,lan,DIRECT\n"); slices.Contains(found, "lan") {
		t.Fatalf("collected lan, which never loads a matcher: %v", found)
	}
}

func TestGeoIPCountriesInIgnoresProseAndLongerWords(t *testing.T) {
	found := countriesIn(t, `# the geoip database is large
# notgeoip,zz,DIRECT
rules:
  - GEOSITE,cn,DIRECT
`)
	if len(found) != 0 {
		t.Fatalf("collected %v from a configuration naming no GEOIP rule", found)
	}
}

// A configuration naming nothing must not make the App do work, and must say so rather
// than returning an empty success a reader cannot distinguish from a failure.
func TestPrepareGeoIPCacheReportsWhenNothingIsNamed(t *testing.T) {
	summary, err := PrepareGeoIPCache("rules:\n  - MATCH,DIRECT\n")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(summary, "no countries") {
		t.Fatalf("summary does not say nothing was named: %q", summary)
	}
}

// The App writes and the tunnel reads, and nothing asserted they agree on where.
//
// A reviewer changed CompileGeoIP to store into CompiledGeoIPDir()+"-WRONG" and every
// suite in the repository stayed green -- while on a device that is every GEOIP rule
// silently matching nothing, which the task brief itself called worse than the defect
// being fixed.
//
// This drives BOTH real halves: the App's PrepareGeoIPCache compiles, then the tunnel's
// own policy loads. It uses no path of its own, so it fails if either side moves.
func TestTheAppCompilesWhereTheTunnelReads(t *testing.T) {
	options := testOptions(t)
	if err := os.MkdirAll(options.WorkingPath, 0o755); err != nil {
		t.Fatal(err)
	}
	stageBundledGeodata(t, options.WorkingPath)
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	C.SetHomeDir(options.WorkingPath)
	geodata.SetGeodataMode(true)
	geodata.SetLoader("memconservative")
	t.Cleanup(func() {
		geodata.SetCompiledGeoIPOnly(false)
		geodata.ClearGeoIPCache()
	})

	const config = "rules:\n  - GEOIP,cn,DIRECT\n  - MATCH,DIRECT\n"

	// The App's half.
	geodata.SetCompiledGeoIPOnly(false)
	summary, err := PrepareGeoIPCache(config)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(summary, "geoip: 1 compiled") {
		t.Fatalf("the App did not compile the country the configuration named: %s", summary)
	}

	// The tunnel's half: compiled-only, so a matcher can ONLY come from an artifact the
	// App wrote. If the two disagree on the directory this is the empty one.
	geodata.ClearGeoIPCache()
	geodata.SetCompiledGeoIPOnly(true)
	matcher, err := geodata.LoadGeoIPMatcher("cn")
	if err != nil {
		t.Fatal(err)
	}
	if matcher.Count() == 0 {
		t.Fatal("the tunnel read an EMPTY cn matcher after the App reported compiling it: " +
			"the two disagree on where artifacts live, and every GEOIP rule would silently " +
			"match nothing")
	}
	// And it must hold real addresses, not merely a non-zero count.
	if !matcher.Match(netip.MustParseAddr("114.114.114.114")) {
		t.Fatal("the matcher the tunnel read does not contain a mainland address")
	}
}

// A rule-provider payload is fetched at runtime, after the App's compile pass would have
// run, so a country named only in a payload has no artifact and hits the degraded path.
//
// The scanner already handles the shapes a payload arrives in -- this pins that, because
// the client's prepareRulePayloads hands these strings straight to PrepareGeoIPCache and a
// scanner that only understood a full config would silently return nothing for them.
func TestGeoIPCountriesInReadsRuleProviderPayloads(t *testing.T) {
	// classical YAML, the shape blackmatrix7 and similar publish
	classical := "payload:\n  - GEOIP,jp,PROXY\n  - DOMAIN-SUFFIX,example.com,DIRECT\n"
	if found := countriesIn(t, classical); !slices.Contains(found, "jp") {
		t.Fatalf("a classical payload's GEOIP rule was not seen: %v", found)
	}
	// classical text, the .list shape
	text := "GEOIP,kr,PROXY\nDOMAIN-SUFFIX,a.b,DIRECT\n"
	if found := countriesIn(t, text); !slices.Contains(found, "kr") {
		t.Fatalf("a text payload's GEOIP rule was not seen: %v", found)
	}
	// and the no-resolve form, which is what these payloads usually carry
	noResolve := "payload:\n  - GEOIP,sg,DIRECT,no-resolve\n"
	if found := countriesIn(t, noResolve); !slices.Contains(found, "sg") {
		t.Fatalf("a no-resolve payload rule was not seen: %v", found)
	}
}

// The line forms are what actually reaches Swift. gomobile drops []string, so the slice
// forms are Go-side only -- a handoff document offered one anyway and the header said
// "skipped function", which is the fourth time this week an assertion pointed at something
// other than what the other side receives.
func TestTheLineFormsCarryWhatTheSliceFormsFound(t *testing.T) {
	const config = `rules:
  - GEOIP,cn,DIRECT
  - GEOIP,jp,PROXY
  - GEOSITE,private,DIRECT
`
	countries := GeoIPCountryLines(config)
	for _, want := range GeoIPCountriesIn(config) {
		if !slices.Contains(strings.Split(countries, "\n"), want) {
			t.Fatalf("the line form dropped %q that the slice form found: %q", want, countries)
		}
	}
	categories := GeoSiteCategoryLines(config)
	for _, want := range GeoSiteCategoriesIn(config) {
		if !slices.Contains(strings.Split(categories, "\n"), want) {
			t.Fatalf("the line form dropped %q that the slice form found: %q", want, categories)
		}
	}
	// Empty is empty, not a single blank line the caller has to filter.
	if got := GeoIPCountryLines("rules:\n  - MATCH,DIRECT\n"); got != "" {
		t.Fatalf("a configuration naming no country produced %q, not an empty string", got)
	}
}
