package hako

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/TokenPLS/Hako/component/geodata"
	"github.com/TokenPLS/Hako/component/geodata/compiled"
	"github.com/TokenPLS/Hako/config"
	C "github.com/TokenPLS/Hako/constant"
	"github.com/TokenPLS/Hako/log"
	"gopkg.in/yaml.v3"
)

// GeoIPCountriesIn reports every GeoIP country code a configuration names.
//
// The GeoIP surfaces are narrower than geosite's, and deliberately handled as such rather
// than by copying the geosite scanner. Geosite has a token form -- geosite:cn as a DNS
// nameserver-policy key -- and GeoIP has none: the ONLY marker-led spelling is a rule
// (GEOIP,cn / SRC-GEOIP,cn, and the parser trims, so GEOIP , cn is the same rule).
//
// Reusing the geosite scanner's "marker followed by a colon" branch here would be actively
// wrong: dns.fallback-filter.geoip is a BOOLEAN, so "geoip: true" would be read as a
// country code named true. The one colon-led surface that does name a country,
// fallback-filter.geoip-code, is read structurally instead.
//
// Naming a country that does not exist costs a failed compile and nothing else, so this
// errs toward collecting too much.
func GeoIPCountriesIn(content string) []string {
	lowered := strings.ToLower(content)

	isCountryByte := func(b byte) bool {
		switch {
		case b >= 'a' && b <= 'z', b >= '0' && b <= '9':
			return true
		case b == '-', b == '_':
			return true
		}
		return false
	}
	// SRC-GEOIP must count, and it puts a '-' immediately before the word, so the boundary
	// rule cannot reject '-' the way the geosite one does. "notgeoip" is still rejected
	// because a letter precedes the word.
	atBoundary := func(index int) bool {
		if index == 0 {
			return true
		}
		previous := lowered[index-1]
		if previous == '-' {
			return true
		}
		return !isCountryByte(previous)
	}
	endsSegment := func(b byte) bool {
		switch b {
		case '\n', '\r', '"', '\'', ':', ']', '#', '(', ')':
			return true
		}
		return false
	}
	isSpace := func(b byte) bool { return b == ' ' || b == '\t' }

	seen := make(map[string]struct{})
	var found []string
	collect := func(name string) {
		name = strings.ToLower(strings.TrimSpace(name))
		// Negation is applied to the matcher after loading, so !cn and cn read the same
		// artifact; keeping the '!' would compile a second copy nothing looks up.
		name = strings.TrimPrefix(name, "!")
		if name == "" {
			return
		}
		// lan is answered before any matcher is loaded (rules/common/geoip.go:48), so
		// compiling it would report a failure that is not one.
		if name == "lan" {
			return
		}
		for i := 0; i < len(name); i++ {
			if !isCountryByte(name[i]) {
				return
			}
		}
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		found = append(found, name)
	}

	const word = "geoip"
	for offset := 0; ; {
		index := strings.Index(lowered[offset:], word)
		if index < 0 {
			break
		}
		index += offset
		offset = index + len(word)
		if !atBoundary(index) {
			continue
		}
		next := offset
		for next < len(lowered) && isSpace(lowered[next]) {
			next++
		}
		// Only the comma form. A colon here is geoip: (a boolean) or geoip-code (read
		// structurally below), and neither names a country at this position.
		if next >= len(lowered) || lowered[next] != ',' {
			continue
		}
		start := next + 1
		end := start
		for end < len(lowered) && !endsSegment(lowered[end]) {
			end++
		}
		// Rule form: the first piece is the country, the rest is the target and params.
		pieces := strings.Split(lowered[start:end], ",")
		collect(pieces[0])
		// The segment is consumed for the reason the geosite scanner documents: rescanning
		// it makes repeated markers on one crafted line quadratic, on the activation path.
		offset = end
	}
	collectFallbackFilterGeoIPCode(content, collect)
	return found
}

// collectFallbackFilterGeoIPCode reads dns.fallback-filter.geoip-code, the one surface that
// names a country with no marker in front of it. Read as structure because a text scan has
// nothing to anchor on -- and because the sibling key on the same block is a boolean.
// Content that does not parse as YAML is left to the text scan that already ran; this path
// only ever adds.
func collectFallbackFilterGeoIPCode(content string, collect func(string)) {
	var document struct {
		DNS struct {
			FallbackFilter struct {
				GeoIPCode string `yaml:"geoip-code"`
			} `yaml:"fallback-filter"`
		} `yaml:"dns"`
	}
	if yaml.Unmarshal([]byte(content), &document) != nil {
		return
	}
	collect(document.DNS.FallbackFilter.GeoIPCode)
}

// PrepareGeoIPCache compiles every GeoIP country a configuration names, so the tunnel can
// read the result instead of building it.
//
// It belongs in the containing App. Building geoip:us peaks at 130 MiB against a packet
// tunnel's 50 MiB ceiling, and loading every country the shipped file holds peaks at
// 164 MiB -- to arrive at 27.9 MiB of matchers that would have fitted all along. The App
// has the memory to do it once; the artifacts for the whole world are 18.3 MiB and read
// back under budget.
//
// A country that will not compile is reported and skipped, for the reason
// PrepareGeoSiteCache documents: failing the whole preparation would turn "one country is
// unavailable" into "no profile".
//
// geodataMode is the configuration's geodata-mode, which the caller reads with
// GeodataModeEnabled from the profile (a rule-provider payload does not carry the key).
// Off, which is the default, means the tunnel answers GEOIP from geoip.metadb
// (rules/common/geoip.go) and never opens compiled-geoip, so there is nothing to prepare.
// Before this gate the pass ran anyway, and ran wrong: the preflight had just called
// C.Path.MMDB(), which renames the process-wide C.GeoipName to "geoip.metadb", so the
// compile decoded the MMDB as protobuf, failed with "cannot parse invalid wire-format
// data", and warned that the country would match nothing -- about a file the tunnel does
// not read (found in a device log, 2026-09-02).
func PrepareGeoIPCache(content string, geodataMode bool) (string, error) {
	if !geodataMode {
		return "geoip: skipped, tunnel reads geoip.metadb", nil
	}
	countries := GeoIPCountriesIn(content)
	if len(countries) == 0 {
		return "geoip: no countries named", nil
	}
	// Compiling reads source material, which is exactly what the constrained runtime
	// refuses to do. This process is not that one.
	previous := geodata.CompiledGeoIPOnly()
	geodata.SetCompiledGeoIPOnly(false)
	defer geodata.SetCompiledGeoIPOnly(previous)

	// An artifact older than the source it was built from is stale; anything newer is the
	// same work already done.
	sourceModified := time.Time{}
	if info, err := os.Stat(C.Path.GeoIP()); err == nil {
		sourceModified = info.ModTime()
	}

	prepared, reused := 0, 0
	var failures []string
	for _, country := range countries {
		// Newer than its source AND not empty, for the reason the geosite pass documents:
		// an artifact holding nothing is a country that will silently match nothing, and a
		// timestamp-only check would make that permanent.
		if path, err := compiled.IPCIDRPath(geodata.CompiledGeoIPDir(), country); err == nil {
			if info, err := os.Stat(path); err == nil && info.ModTime().After(sourceModified) {
				if count, err := compiled.EntryCountIPCIDR(
					geodata.CompiledGeoIPDir(), country,
				); err == nil && count > 0 {
					reused++
					continue
				}
			}
		}
		if err := geodata.CompileGeoIP(country); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %s", country, err))
			continue
		}
		prepared++
	}
	// Returned rather than only logged, for the reason the geosite pass documents: this
	// runs in the containing App, where the core's logger has no platform sink.
	summary := fmt.Sprintf("geoip: %d compiled, %d current, %d failed of %d named, dir=%s",
		prepared, reused, len(countries)-prepared-reused, len(countries),
		geodata.CompiledGeoIPDir())
	if len(failures) > 0 {
		summary += " | " + strings.Join(failures, "; ")
		// A category that would not compile is a category the tunnel matches nothing for, which
		// is a statement about the user's rules rather than about this process. The summary
		// above is instrumentation -- it carries a container path and a tally -- and the
		// consuming lane selects reader-facing lines by level as well as prefix, so a failure
		// reported only there reaches nobody. This is the same failure named, at the level that
		// travels.
		// One literal, not a concatenation: the consuming lane greps this text, and a
		// sentence split across two source lines is a sentence their grep misses.
		log.Warnln("[Apple] geoip: %d of %d named countries will match nothing (compile failed): %s",
			len(failures), len(countries), strings.Join(failures, "; "))
	}
	log.Infoln("[Apple] %s", summary)
	// Compiling holds the source material to build each artifact; the tunnel must not
	// inherit a heap shaped by work it will never repeat.
	geodata.ClearGeoIPCache()
	return bridgeSafeString(summary), nil
}

// GeodataModeEnabled reports whether a configuration turns geodata-mode on, decoded the
// way the plan decodes it: plan_resources.go stages GeoIP.dat or geoip.metadb from the
// same raw field, so the compile pass and the staged file cannot disagree about which one
// the tunnel will read. A configuration that does not decode enables nothing; it will not
// activate either, and that is reported where it is parsed.
func GeodataModeEnabled(content string) bool {
	raw, err := config.UnmarshalRawConfig([]byte(content))
	if err != nil {
		return false
	}
	return raw.GeodataMode
}

// GeoIPCountryLines is GeoIPCountriesIn for a caller that cannot receive a slice.
//
// gomobile does not carry []string, so the generated header says
// "skipped function GeoIPCountriesIn with unsupported parameter or return types" -- the
// function exists, is tested, and is unreachable from Swift. A handoff document offered it
// to the client anyway, which is the fourth time this week an assertion pointed at
// something other than what the other side actually receives.
//
// Newline-delimited for the same reason PrepareGeoIPCache returns a string rather than
// logging: this crosses to a process where the core's logger has no sink, so the value has
// to BE the answer. The slice form stays as the Go-side source of truth and keeps the
// tests; this only changes the shape at the boundary.
//
// Empty string when nothing is named, which is distinct from a one-element list containing
// "" and does not need the caller to filter.
func GeoIPCountryLines(content string) string {
	return bridgeSafeString(strings.Join(GeoIPCountriesIn(content), "\n"))
}
