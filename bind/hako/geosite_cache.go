package hako

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/TokenPLS/Hako/component/geodata"
	"github.com/TokenPLS/Hako/component/geodata/compiled"
	C "github.com/TokenPLS/Hako/constant"
	"github.com/TokenPLS/Hako/log"
	"gopkg.in/yaml.v3"
)

// GeoSiteCategoriesIn reports every geosite category a configuration names.
//
// Two spellings reach the same loader with a marker in front: a rule
// (GEOSITE,cn,DIRECT — and the parser trims, so GEOSITE, cn is the same rule)
// and a geosite: token (a DNS nameserver-policy key, a fake-ip-filter entry).
// Those are scanned as text rather than through the parser because this runs
// before the configuration is accepted — the point is to have the artifacts
// ready by the time it is. One surface names categories bare: the
// dns.fallback-filter.geosite list has no marker at all, so it is read
// structurally.
//
// A downloaded classical rule-provider payload is these same shapes — GEOSITE
// entries in text or YAML-list form — so the App scans materialised payloads
// with this function too.
//
// Naming a category that does not exist costs a failed compile and nothing
// else, so this errs toward collecting too much.
func GeoSiteCategoriesIn(content string) []string {
	lowered := strings.ToLower(content)

	isCategoryByte := func(b byte) bool {
		switch {
		case b >= 'a' && b <= 'z', b >= '0' && b <= '9':
			return true
		case b == '-', b == '_', b == '.', b == '@', b == '!':
			return true
		}
		return false
	}
	// A marker only counts at a token boundary: "notgeosite:cn" is not a
	// reference, and neither is the tail of a longer word.
	atBoundary := func(index int) bool {
		return index == 0 || !isCategoryByte(lowered[index-1])
	}

	seen := make(map[string]struct{})
	var found []string
	// A candidate is a category only if it reads as one whole: segments are
	// trimmed, so "GEOSITE, cn" yields cn, while prose that happens to follow
	// a marker ("geosite:cn database is...") yields a fragment with spaces
	// inside and is dropped rather than compiled.
	collect := func(name string) {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			return
		}
		for i := 0; i < len(name); i++ {
			if !isCategoryByte(name[i]) {
				return
			}
		}
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		found = append(found, name)
	}

	// The segment after a reference runs to whatever ends the enclosing token
	// — the line, a closing quote, a YAML key's colon, a comment, or the
	// parenthesis of a logic rule (AND,((GEOSITE,cn),...)). Within it, commas
	// separate categories (policy form) or cut the category from the rule's
	// target (rule form, which keeps only the first piece).
	endsSegment := func(b byte) bool {
		switch b {
		case '\n', '\r', '"', '\'', ':', ']', '#', '(', ')':
			return true
		}
		return false
	}
	isSpace := func(b byte) bool { return b == ' ' || b == '\t' }
	// One pass over every "geosite" word. What follows the word decides the
	// shape: a comma — possibly after whitespace, because the rule parser
	// trims every piece, so GEOSITE , cn is the same rule — or a directly
	// attached colon, because the policy spellings are prefix-matched
	// verbatim by the core. Anything else is a longer word or prose.
	const word = "geosite"
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
		var start int
		var wantEveryPiece bool
		switch {
		case next < len(lowered) && lowered[next] == ',':
			start, wantEveryPiece = next+1, false
		case next == offset && next < len(lowered) && lowered[next] == ':':
			start, wantEveryPiece = next+1, true
		default:
			continue
		}
		end := start
		for end < len(lowered) && !endsSegment(lowered[end]) {
			end++
		}
		// The one place upstream's schema puts a bare `geosite:` key with a
		// non-category value is geox-url.geosite -- a URL (config.go:391-396
		// RawGeoXUrl; category references live elsewhere entirely, read from
		// parsed values at config.go:1398 and rules/parser.go:28). A category's
		// tail can never be `://`, so a segment that stopped at one is that
		// key's URL scheme, not a reference. Unquoted is the shape that bites:
		// quotes end the segment before the scheme, and the script round trip
		// legally strips quotes -- which is how a working config gained a
		// phantom category "https" and the extension died at startup with
		// code=12 before its first log line. The geoip twin met the same
		// collision (upstream's `geoip:` boolean key) and dropped its colon
		// form entirely; geosite needs the colon form for policy keys, so it
		// excludes the one colliding value shape instead.
		if end < len(lowered) && lowered[end] == ':' && strings.HasPrefix(lowered[end+1:], "//") {
			offset = end
			continue
		}
		pieces := strings.Split(lowered[start:end], ",")
		if !wantEveryPiece && len(pieces) > 1 {
			pieces = pieces[:1]
		}
		for _, piece := range pieces {
			collect(piece)
		}
		// The segment is consumed: another "geosite" word inside it is rule
		// target/params text or a policy piece already collected, never a new
		// reference (a nested logic reference sits behind a parenthesis, and
		// parentheses end segments). Rescanning it made repeated markers on
		// one crafted line quadratic — 13s for 352 KiB, hours at the 16 MiB
		// payload limit, all on the activation path.
		offset = end
	}
	collectFallbackFilterGeoSite(content, collect)
	return found
}

// collectFallbackFilterGeoSite reads dns.fallback-filter.geosite, the one
// surface that names categories with no marker in front of them — a text scan
// has nothing to anchor on, so it is read as structure. Content that does not
// parse as YAML is simply left to the text scan that already ran; this path
// only ever adds.
func collectFallbackFilterGeoSite(content string, collect func(string)) {
	var document struct {
		DNS struct {
			FallbackFilter struct {
				GeoSite []string `yaml:"geosite"`
			} `yaml:"fallback-filter"`
		} `yaml:"dns"`
	}
	if yaml.Unmarshal([]byte(content), &document) != nil {
		return
	}
	for _, category := range document.DNS.FallbackFilter.GeoSite {
		collect(category)
	}
}

// PrepareGeoSiteCache compiles every geosite category a configuration names, so
// the tunnel can read the result instead of building it.
//
// It belongs in the containing App. Building geosite:cn peaks at 72.7 MiB
// against a packet tunnel's 50 MiB ceiling, which is why a configuration naming
// it in a DNS nameserver-policy could not start however it was written; the App
// has the memory to do it once, and the artifact costs 2 ms and 1.2 MiB to read
// afterwards.
//
// A category that will not compile is reported and skipped. Failing the whole
// preparation would turn "one category is unavailable" into "no profile", which
// is the trade this work exists to stop making.
func PrepareGeoSiteCache(content string) (string, error) {
	categories := GeoSiteCategoriesIn(content)
	if len(categories) == 0 {
		return "geosite: no categories named", nil
	}
	// Compiling reads source material, which is exactly what the constrained
	// runtime refuses to do. This process is not that one.
	previous := geodata.CompiledGeoSiteOnly()
	geodata.SetCompiledGeoSiteOnly(false)
	defer geodata.SetCompiledGeoSiteOnly(previous)

	// An artifact older than the source it was built from is stale; anything
	// newer is the same work already done. Recompiling regardless would put
	// 72.7 MiB and 150 ms into every profile switch for a file that has not
	// changed since the last one.
	sourceModified := time.Time{}
	if info, err := os.Stat(C.Path.GeoSite()); err == nil {
		sourceModified = info.ModTime()
	}

	prepared, reused := 0, 0
	var failures []string
	for _, category := range categories {
		// Newer than its source AND not empty. An artifact holding nothing is
		// not a cached answer, it is a category that will silently match
		// nothing — and once written, a timestamp-only check made it permanent.
		if path, err := compiled.Path(geodata.CompiledGeoSiteDir(), category); err == nil {
			if info, err := os.Stat(path); err == nil && info.ModTime().After(sourceModified) {
				if count, err := compiled.EntryCount(
					geodata.CompiledGeoSiteDir(), category,
				); err == nil && count > 0 {
					reused++
					continue
				}
			}
		}
		if err := geodata.CompileGeoSite(category); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %s", category, err))
			continue
		}
		prepared++
	}
	// Returned rather than only logged: this runs in the containing App, where
	// the core's logger has no platform sink, so every warning it wrote here
	// went nowhere. Three rounds of measurement could not say whether compiling
	// had even run.
	summary := fmt.Sprintf("geosite: %d compiled, %d current, %d failed of %d named, dir=%s",
		prepared, reused, len(categories)-prepared-reused, len(categories),
		geodata.CompiledGeoSiteDir())
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
		log.Warnln("[Apple] geosite: %d of %d named categories will match nothing (compile failed): %s",
			len(failures), len(categories), strings.Join(failures, "; "))
	}
	log.Infoln("[Apple] %s", summary)
	// Compiling holds the source material to build each artifact; the tunnel
	// must not inherit a heap shaped by work it will never repeat.
	geodata.ClearGeoSiteCache()
	return summary, nil
}

// GeoSiteCategoryLines is GeoSiteCategoriesIn for a caller that cannot receive a slice.
// See GeoIPCountryLines for why the shape changes at the boundary.
func GeoSiteCategoryLines(content string) string {
	return strings.Join(GeoSiteCategoriesIn(content), "\n")
}
