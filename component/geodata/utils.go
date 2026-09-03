package geodata

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/TokenPLS/Hako/common/singleflight"
	"github.com/TokenPLS/Hako/component/cidr"
	"github.com/TokenPLS/Hako/component/geodata/compiled"
	"github.com/TokenPLS/Hako/component/geodata/router"
	"github.com/TokenPLS/Hako/component/trie"
	C "github.com/TokenPLS/Hako/constant"
	"github.com/TokenPLS/Hako/log"
)

var (
	geoMode        bool
	geoLoaderName  = "memconservative"
	geoSiteMatcher = "succinct"

	// A runtime with a hard memory ceiling reads compiled categories and never
	// decodes one. Decoding geosite:cn peaks at 72.7 MiB against a packet
	// tunnel's 50 MiB, so "try it and see" is not a fallback — it is a kill.
	// When the artifact is absent such a runtime matches nothing for that
	// category and says so, because a tunnel that starts with one category
	// unmatched is worth more to a reader than a tunnel that does not start.
	// Atomic because it is written by normalizeRawConfigForApple on every config reload
	// while connection goroutines read it through the matching path -- rules/common
	// reaches the loaders on every match, and a reload happens while the old rule set is
	// still forwarding traffic. Upstream's own geoMode and geoLoaderName are left as they
	// are: they are mihomo's, and changing them is a fork delta for no platform reason.
	compiledGeoSiteOnly atomic.Bool

	// The same policy for GeoIP, and it is a separate flag rather than a
	// widening of the one above because the two resources are compiled by
	// different passes and can be absent independently. Decoding geoip:us
	// peaks at 130 MiB and loading every country code the shipped file holds
	// peaks at 164 MiB, both against the same 50 MiB. The result was never the
	// problem -- every matcher in the file weighs 27.9 MiB resident -- so a
	// runtime with a ceiling reads artifacts and never decodes one.
	compiledGeoIPOnly atomic.Bool

	// A func value is TWO words, so an unsynchronised write is not merely a stale read --
	// a reader can see half of one function and half of another and jump into nothing.
	progressReporterValue atomic.Pointer[func(string)]
)

// SetCompiledGeoIPOnly declares that this process must not decode GeoIP source
// material, only read compiled country codes.
func SetCompiledGeoIPOnly(only bool) {
	compiledGeoIPOnly.Store(only)
}

// CompiledGeoIPOnly reports the current policy.
func CompiledGeoIPOnly() bool {
	return compiledGeoIPOnly.Load()
}

// CompiledGeoIPDir is where compiled country codes are read from and written to.
//
// Separate from CompiledGeoSiteDir because the two namespaces overlap: cn is a
// country code and also a category, so one directory would let whichever was
// written second answer for both.
func CompiledGeoIPDir() string {
	return filepath.Join(C.Path.HomeDir(), compiled.IPCIDRDirectoryName)
}

// SetCompiledGeoSiteOnly declares that this process must not decode geosite
// source material, only read compiled categories.
func SetCompiledGeoSiteOnly(only bool) {
	compiledGeoSiteOnly.Store(only)
}

// CompiledGeoSiteOnly reports the current policy.
func CompiledGeoSiteOnly() bool {
	return compiledGeoSiteOnly.Load()
}

// CompiledGeoSiteDir is where compiled categories are read from and written to.
func CompiledGeoSiteDir() string {
	return filepath.Join(C.Path.HomeDir(), compiled.DirectoryName)
}

//  geoLoaderName = "standard"

func GeodataMode() bool {
	return geoMode
}

func LoaderName() string {
	return geoLoaderName
}

func SiteMatcherName() string {
	return geoSiteMatcher
}

func SetGeodataMode(newGeodataMode bool) {
	geoMode = newGeodataMode
}

func SetLoader(newLoader string) {
	if newLoader == "memc" {
		newLoader = "memconservative"
	}
	geoLoaderName = newLoader
}

func SetSiteMatcher(newMatcher string) {
	switch newMatcher {
	case "mph", "hybrid":
		geoSiteMatcher = "mph"
	default:
		geoSiteMatcher = "succinct"
	}
}

func Verify(name string) error {
	switch name {
	case C.GeositeName:
		_, err := LoadGeoSiteMatcher("CN")
		return err
	case C.GeoipName:
		_, err := LoadGeoIPMatcher("CN")
		return err
	default:
		return fmt.Errorf("not support name")
	}
}

var loadGeoSiteMatcherListSF = singleflight.Group[[]*router.Domain]{StoreResult: true}
var loadGeoSiteMatcherSF = singleflight.Group[router.DomainMatcher]{StoreResult: true}

func LoadGeoSiteMatcher(countryCode string) (router.DomainMatcher, error) {
	if countryCode == "" {
		return nil, fmt.Errorf("country code could not be empty")
	}

	not := false
	if countryCode[0] == '!' {
		not = true
		countryCode = countryCode[1:]
		if countryCode == "" {
			return nil, fmt.Errorf("country code could not be empty")
		}
	}
	countryCode = strings.ToLower(countryCode)

	parts := strings.Split(countryCode, "@")
	listName := strings.TrimSpace(parts[0])
	attrVal := parts[1:]
	attrs := parseAttrs(attrVal)

	if listName == "" {
		return nil, fmt.Errorf("empty listname in rule: %s", countryCode)
	}

	matcherName := canonicalGeoSiteKey(listName, attrs)
	matcher, err, shared := loadGeoSiteMatcherSF.Do(matcherName, func() (router.DomainMatcher, error) {
		// INSIDE the singleflight, so it announces a BUILD and not a lookup.
		// GEOSITE.MatchDomain calls this loader on every match (rules/common/geosite.go:34),
		// and upstream keeps the work behind Do precisely so a repeat call is a map lookup.
		// Outside, every connection evaluating a geo rule paid a mutex, a file read, a cgo
		// task_info and a file write -- measured at ~197us each, forever.
		reportProgress("geosite:" + matcherName)
		// The compiled artifact is the same matcher, already built. Reading it
		// costs what the matcher costs; building it from source costs an order
		// of magnitude more, which is the difference between a tunnel that
		// starts and one the system kills.
		if set, count, residual, err := compiled.Load(CompiledGeoSiteDir(), matcherName); err == nil {
			matcher, err := router.NewSuccinctMatcherFromParts(set, count, toRouterResidual(residual))
			if err == nil {
				log.Infoln("Load GeoSite rule: %s (compiled, %d entries)", matcherName, count)
				return matcher, nil
			}
			log.Warnln("compiled GeoSite rule %s could not be assembled (%s); falling back to source",
				matcherName, err)
		} else if !errors.Is(err, compiled.ErrNotCompiled) {
			log.Warnln("compiled GeoSite rule %s could not be read (%s); falling back to source", matcherName, err)
		}
		if compiledGeoSiteOnly.Load() {
			log.Warnln("GeoSite rule %s has not been compiled for this runtime and will match nothing "+
				"(looked in %s): decoding it needs more memory than this process is allowed, "+
				"so the alternative is not starting",
				matcherName, CompiledGeoSiteDir())
			// Unavailable rather than empty: an empty matcher wrapped by a leading '!'
			// inverts to match EVERYTHING, so GEOSITE,!cn would swallow every domain and
			// kill every rule below it.
			return router.NewUnavailableDomainMatcher(), nil
		}
		log.Infoln("Load GeoSite rule: %s", matcherName)
		domains, err, shared := loadGeoSiteMatcherListSF.Do(listName, func() ([]*router.Domain, error) {
			geoLoader, err := GetGeoDataLoader(geoLoaderName)
			if err != nil {
				return nil, err
			}
			return geoLoader.LoadGeoSite(listName)
		})
		if err != nil {
			if !shared {
				loadGeoSiteMatcherListSF.Forget(listName) // don't store the error result
			}
			return nil, err
		}

		if attrs.IsEmpty() {
			if strings.Contains(countryCode, "@") {
				log.Warnln("empty attribute list: %s", countryCode)
			}
		} else {
			filteredDomains := make([]*router.Domain, 0, len(domains))
			hasAttrMatched := false
			for _, domain := range domains {
				if attrs.Match(domain) {
					hasAttrMatched = true
					filteredDomains = append(filteredDomains, domain)
				}
			}
			if !hasAttrMatched {
				log.Warnln("attribute match no rule: geosite: %s", countryCode)
			}
			domains = filteredDomains
		}

		/**
		linear: linear algorithm
		matcher, err := router.NewDomainMatcher(domains)
		mph：minimal perfect hash algorithm
		*/
		var built router.DomainMatcher
		if geoSiteMatcher == "mph" {
			built, err = router.NewMphMatcherGroup(domains)
		} else {
			built, err = router.NewSuccinctMatcherGroup(domains)
		}
		// The decoded domain list is scaffolding: once the matcher is built
		// nothing reads it again, but singleflight's StoreResult keeps it for
		// the life of the process so a second geosite:cn@attr can skip the
		// file. That is a fair trade with a heap to spare and the wrong one
		// under memconservative, which is the reader saying they would rather
		// re-read the file than hold it. On a packet tunnel with a 50 MiB
		// ceiling this list was the difference between starting and being
		// killed mid-parse.
		if geoLoaderName == "memconservative" {
			loadGeoSiteMatcherListSF.Forget(listName)
		}
		return built, err
	})
	if err != nil {
		if !shared {
			loadGeoSiteMatcherSF.Forget(matcherName) // don't store the error result
		}
		return nil, err
	}
	if not && !router.Unavailable(matcher) {
		matcher = router.NewNotDomainMatcherGroup(matcher)
	}

	return matcher, nil
}

var loadGeoIPMatcherSF = singleflight.Group[router.IPMatcher]{StoreResult: true}

func LoadGeoIPMatcher(country string) (router.IPMatcher, error) {
	if len(country) == 0 {
		return nil, fmt.Errorf("country code could not be empty")
	}

	not := false
	if country[0] == '!' {
		not = true
		country = country[1:]
	}
	country = strings.ToLower(country)

	matcher, err, shared := loadGeoIPMatcherSF.Do(country, func() (router.IPMatcher, error) {
		// INSIDE the singleflight, for the reason LoadGeoSiteMatcher documents: GEOIP.Match
		// reaches this on every match (rules/common/geoip.go:62,109,135).
		reportProgress("geoip:" + country)
		// The compiled artifact is the same set, already built. Reading it
		// costs what the set costs; building it from source costs an order of
		// magnitude more, which is the difference between a tunnel that starts
		// and one the system kills. Mirrors LoadGeoSiteMatcher above so the two
		// read alike.
		if set, count, err := compiled.LoadIPCIDR(CompiledGeoIPDir(), country); err == nil {
			matcher, err := router.NewGeoIPMatcherFromCidrSet(set, count)
			if err == nil {
				log.Infoln("Load GeoIP rule: %s (compiled, %d entries)", country, count)
				return matcher, nil
			}
			log.Warnln("compiled GeoIP rule %s could not be assembled (%s); falling back to source",
				country, err)
		} else if !errors.Is(err, compiled.ErrNotCompiled) {
			log.Warnln("compiled GeoIP rule %s could not be read (%s); falling back to source", country, err)
		}
		if compiledGeoIPOnly.Load() {
			log.Warnln("GeoIP rule %s has not been compiled for this runtime and will match nothing "+
				"(looked in %s): decoding it needs more memory than this process is allowed, "+
				"so the alternative is not starting",
				country, CompiledGeoIPDir())
			// Unavailable rather than empty, for the reason the geosite branch documents:
			// GEOIP,!CN,PROXY with cn unavailable would otherwise match every address and
			// route domestic traffic through the proxy, and dns.fallback-filter.geoip
			// computes !Match so every answer would be judged polluted.
			return router.NewUnavailableIPMatcher(), nil
		}
		log.Infoln("Load GeoIP rule: %s", country)
		geoLoader, err := GetGeoDataLoader(geoLoaderName)
		if err != nil {
			return nil, err
		}
		cidrList, err := geoLoader.LoadGeoIP(country)
		if err != nil {
			return nil, err
		}
		return router.NewGeoIPMatcher(cidrList)
	})
	if err != nil {
		if !shared {
			loadGeoIPMatcherSF.Forget(country) // don't store the error result
			log.Warnln("Load GeoIP rule: %s", country)
		}
		return nil, err
	}
	if not && !router.Unavailable(matcher) {
		matcher = router.NewNotIpMatcherGroup(matcher)
	}
	return matcher, nil
}

func ClearGeoSiteCache() {
	loadGeoSiteMatcherListSF.Reset()
	loadGeoSiteMatcherSF.Reset()
}

func ClearGeoIPCache() {
	loadGeoIPMatcherSF.Reset()
}

// A set that answers no for everything, so a missing compiled category is a
// category that matches nothing rather than a nil dereference at match time.
func emptyDomainSet() *trie.DomainSet {
	return trie.New[struct{}]().NewDomainSet()
}

// CompileGeoSite builds the compiled artifact for one category from source.
//
// This is the expensive direction and belongs where there is memory to spare:
// the containing App at profile activation, never the tunnel.
//
// It reads the source itself rather than borrowing LoadGeoSiteMatcher's result.
// That matters: the App runs its preflight as the tunnel would — CheckConfig
// parses with underNetworkExtension true — which turns compiled-only on in the
// App's own process and leaves an empty matcher cached for every category it
// declined to decode. Compiling from that cache wrote artifacts holding
// nothing, reported success, and the tunnel then matched nothing while
// believing a compiled category existed.
func CompileGeoSite(category string) error {
	listName, attrs, err := splitGeoSiteCategory(category)
	if err != nil {
		return err
	}
	geoLoader, err := GetGeoDataLoader(geoLoaderName)
	if err != nil {
		return err
	}
	domains, err := geoLoader.LoadGeoSite(listName)
	if err != nil {
		return err
	}
	if !attrs.IsEmpty() {
		filtered := make([]*router.Domain, 0, len(domains))
		for _, domain := range domains {
			if attrs.Match(domain) {
				filtered = append(filtered, domain)
			}
		}
		domains = filtered
	}
	if len(domains) == 0 {
		// Writing an empty artifact is worse than writing none: the tunnel
		// would read it, believe the category holds nothing, and never say so.
		return fmt.Errorf("geosite %s holds no entries", category)
	}
	set, count, residual, err := router.CompileDomains(domains)
	if err != nil {
		return err
	}
	return compiled.Store(
		CompiledGeoSiteDir(), canonicalGeoSiteKey(listName, attrs),
		set, count, fromRouterResidual(residual),
	)
}

// canonicalGeoSiteKey is the one name a category is compiled under and looked
// up by. Negation is not part of it — a NOT is applied to the matcher after
// loading, so !cn and cn read the same artifact — and attributes are printed
// the way AttributeList prints them, because that is the string the loader
// keys its cache and its artifact lookup with.
func canonicalGeoSiteKey(listName string, attrs *AttributeList) string {
	if attrs.IsEmpty() {
		return listName
	}
	return listName + "@" + attrs.String()
}

// splitGeoSiteCategory reads the name the way LoadGeoSiteMatcher does, so a
// category compiles under exactly the name the tunnel will look for.
func splitGeoSiteCategory(category string) (string, *AttributeList, error) {
	name := strings.ToLower(strings.TrimSpace(category))
	name = strings.TrimPrefix(name, "!")
	parts := strings.Split(name, "@")
	listName := strings.TrimSpace(parts[0])
	if listName == "" {
		return "", nil, fmt.Errorf("empty listname in rule: %s", category)
	}
	return listName, parseAttrs(parts[1:]), nil
}

func toRouterResidual(residual []compiled.Residual) []router.ResidualDomain {
	if len(residual) == 0 {
		return nil
	}
	out := make([]router.ResidualDomain, 0, len(residual))
	for _, entry := range residual {
		out = append(out, router.ResidualDomain{
			Type: router.Domain_Type(entry.Type), Value: entry.Value,
		})
	}
	return out
}

func fromRouterResidual(residual []router.ResidualDomain) []compiled.Residual {
	if len(residual) == 0 {
		return nil
	}
	out := make([]compiled.Residual, 0, len(residual))
	for _, entry := range residual {
		out = append(out, compiled.Residual{Type: int32(entry.Type), Value: entry.Value})
	}
	return out
}

// CompileGeoIP builds the artifact for one country code and writes it.
//
// Belongs where there is memory to hold the source: geoip:us decodes at a 130 MiB peak to
// produce a 3.15 MiB set, so this runs in the containing App and the tunnel reads what it
// wrote. Mirrors CompileGeoSite.
func CompileGeoIP(country string) error {
	name := strings.ToLower(strings.TrimSpace(country))
	if strings.HasPrefix(name, "!") {
		// Negation is applied to the matcher after loading, so !cn and cn read the same
		// artifact and compiling under the negated name would write a second copy that
		// nothing ever looks up.
		name = name[1:]
	}
	if name == "" {
		return fmt.Errorf("country code could not be empty")
	}
	geoLoader, err := GetGeoDataLoader(geoLoaderName)
	if err != nil {
		return err
	}
	cidrList, err := geoLoader.LoadGeoIP(name)
	if err != nil {
		return err
	}
	if len(cidrList) == 0 {
		// Writing an empty artifact is worse than writing none: the tunnel would read it,
		// believe the country holds nothing, and never say so.
		return fmt.Errorf("geoip %s holds no entries", name)
	}
	set := cidr.NewIpCidrSet()
	for _, entry := range cidrList {
		addr, ok := netip.AddrFromSlice(entry.Ip)
		if !ok {
			return fmt.Errorf("geoip %s: invalid IP", name)
		}
		if err := set.AddIpCidr(netip.PrefixFrom(addr, int(entry.Prefix))); err != nil {
			return err
		}
	}
	if err := set.Merge(); err != nil {
		return err
	}
	return compiled.StoreIPCIDR(CompiledGeoIPDir(), name, set, len(cidrList))
}

// progressReporter is told which geo resource is about to be built, before the work that
// might not survive it starts.
//
// A packet tunnel killed by jetsam never runs a handler, so the only account of what it
// was doing is one written before it stopped. This is the seam that lets the bind layer
// record that without geodata knowing anything about files, containers or Apple.
// SetGeodataProgressReporter installs the seam. Nil disables it, which is the default and
// what every non-Apple build gets.
func SetGeodataProgressReporter(report func(string)) {
	if report == nil {
		progressReporterValue.Store(nil)
		return
	}
	progressReporterValue.Store(&report)
}

func reportProgress(resource string) {
	if report := progressReporterValue.Load(); report != nil {
		(*report)(resource)
	}
}

// GeodataProgressReporter reports the installed seam, so a consumer can restore it.
func GeodataProgressReporter() func(string) {
	if report := progressReporterValue.Load(); report != nil {
		return *report
	}
	return nil
}
