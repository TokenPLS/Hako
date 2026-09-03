package hako

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/TokenPLS/Hako/component/cidr"
	"github.com/TokenPLS/Hako/component/geodata"
	"github.com/TokenPLS/Hako/component/geodata/compiled"
	"github.com/TokenPLS/Hako/component/geodata/router"
	C "github.com/TokenPLS/Hako/constant"

	"google.golang.org/protobuf/proto"
)

// Every geo resource, every name in it, all at once.
//
// The per-resource numbers in CORE-TASK-GEODATA-STARTUP-OOM measure one country code or
// one category in isolation. That is not what a configuration does. A configuration names
// several, and the loaders cache what they build -- loadGeoIPMatcherSF and
// loadGeoSiteMatcherSF are singleflight groups with StoreResult:true
// (component/geodata/utils.go:94-95, 220) -- so every matcher a config reaches STAYS
// resident for the life of the process.
//
// That makes retained, not peak, the number that decides whether a stacked config lives.
// A config that peaks at 40 MiB ten times and keeps 8 MiB each time is dead at the tenth,
// and no single-resource measurement would ever say so.
//
// Skipped by default: it loads real geodata, all of it, and takes real time.

const packetTunnelBudgetBytes = 50 << 20

// settledHeap reports heap in use after collection, which is what jetsam-relevant growth
// looks like once the transient decode is gone.
func settledHeap() uint64 {
	runtime.GC()
	runtime.GC()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return stats.HeapAlloc
}

func mib(bytes uint64) float64 { return float64(bytes) / (1 << 20) }

// enumerateShippedGeoNames reads every country code and every category out of the files we
// ship. It is deliberately done the way the `standard` loader does it -- read the file
// whole, proto.Unmarshal the whole list -- so the cost printed here IS the standard
// loader's cost, and says what forcing memconservative buys
// (bind/hako/config_pipeline.go:121, override.go:48).
func enumerateShippedGeoNames(t *testing.T, workingPath string) (codes []string, categories []string) {
	t.Helper()

	before := settledHeap()
	ipBytes, err := os.ReadFile(C.Path.GeoIP())
	if err != nil {
		t.Skipf("GeoIP.dat unavailable: %v", err)
	}
	var ipList router.GeoIPList
	if err := proto.Unmarshal(ipBytes, &ipList); err != nil {
		t.Fatalf("GeoIP.dat: %v", err)
	}
	cidrTotal := 0
	for _, entry := range ipList.Entry {
		codes = append(codes, strings.ToLower(entry.CountryCode))
		cidrTotal += len(entry.Cidr)
	}

	siteBytes, err := os.ReadFile(C.Path.GeoSite())
	if err != nil {
		t.Skipf("GeoSite.dat unavailable: %v", err)
	}
	var siteList router.GeoSiteList
	if err := proto.Unmarshal(siteBytes, &siteList); err != nil {
		t.Fatalf("GeoSite.dat: %v", err)
	}
	domainTotal := 0
	for _, entry := range siteList.Entry {
		categories = append(categories, strings.ToLower(entry.CountryCode))
		domainTotal += len(entry.Domain)
	}
	whole := settledHeap()

	t.Logf("shipped inventory: %d country codes / %d CIDRs, %d categories / %d domains",
		len(codes), cidrTotal, len(categories), domainTotal)
	t.Logf("both files unmarshalled whole (what geodata-loader: standard does): "+
		"retained %.1f MiB above baseline -- forced to memconservative on iOS at "+
		"config_pipeline.go:121", mib(whole)-mib(before))

	sort.Strings(codes)
	sort.Strings(categories)
	ipList.Reset()
	siteList.Reset()
	return codes, categories
}

// Load every country code the shipped file has, one at a time, and report where the
// accumulated matchers cross the tunnel's budget.
func TestMaximalGeoIPStackCrossesTheBudget(t *testing.T) {
	stageGeoMeasurement(t)
	options := testOptions(t)
	codes, _ := enumerateShippedGeoNames(t, options.WorkingPath)

	baseline := settledHeap()
	var crossedAt int

	// Retained and peak have to be read together. Retained says whether the end state
	// fits; peak says whether the process survives reaching it. They can disagree
	// completely, and here they do.
	measurePeakAndRetained(t, "loading ALL "+fmt.Sprint(len(codes))+" country codes", func() {
		for index, code := range codes {
			matcher, err := geodata.LoadGeoIPMatcher(code)
			if err != nil {
				continue
			}
			_ = matcher
			if index%40 == 39 || index == len(codes)-1 {
				settled := settledHeap()
				t.Logf("after %3d/%d country codes: retained %.1f MiB above baseline",
					index+1, len(codes), mib(settled)-mib(baseline))
				if crossedAt == 0 && settled-baseline > packetTunnelBudgetBytes {
					crossedAt = index + 1
				}
			}
		}
	})

	final := settledHeap()
	t.Logf("ALL %d country codes resident: %.1f MiB above baseline [tunnel budget 50 MiB]",
		len(codes), mib(final)-mib(baseline))
	if crossedAt > 0 {
		t.Logf("retained crossed the 50 MiB budget at roughly country code #%d of %d",
			crossedAt, len(codes))
	} else {
		t.Logf("retained never crossed 50 MiB: every matcher the shipped file can produce " +
			"fits at once. Read the peak above -- if it exceeds the budget, the end state " +
			"fits and the PATH to it does not, which is the whole case for compiling.")
	}
}

// The same for geosite, with the shipped protection OFF -- what the containing App pays to
// compile, and what the tunnel would pay if it ever decoded.
func TestMaximalGeoSiteStackWithoutCompiledArtifacts(t *testing.T) {
	stageGeoMeasurement(t)
	geodata.SetCompiledGeoSiteOnly(false)
	t.Cleanup(func() { geodata.SetCompiledGeoSiteOnly(false) })
	options := testOptions(t)
	_, categories := enumerateShippedGeoNames(t, options.WorkingPath)

	baseline := settledHeap()
	loaded, domains := 0, 0

	measurePeakAndRetained(t, "decoding ALL "+fmt.Sprint(len(categories))+" categories", func() {
		for index, category := range categories {
			matcher, err := geodata.LoadGeoSiteMatcher(category)
			if err != nil {
				continue
			}
			loaded++
			// LoadGeoSiteMatcher returns an EMPTY matcher and no error when the
			// compiled-only policy is on and no artifact exists
			// (component/geodata/utils.go:136-146). Counting successes would then
			// report 1527 loaded categories weighing nothing at all, which is how a
			// protection gets mistaken for a cheap decode. Count the contents.
			domains += matcher.Count()
			if index%250 == 249 || index == len(categories)-1 {
				t.Logf("after %4d/%d categories: retained %.1f MiB above baseline",
					index+1, len(categories), mib(settledHeap())-mib(baseline))
			}
		}
	})

	t.Logf("ALL %d categories resident (%d loaded, %d domains matched): %.1f MiB above baseline",
		len(categories), loaded, domains, mib(settledHeap())-mib(baseline))
	if domains == 0 {
		t.Fatal("every category loaded and none contains a domain: this measured the " +
			"empty-matcher path, not a decode")
	}
}

// The decisive one: compile every country code the shipped file has, then load every
// artifact back, and see whether the maximal stack fits once nothing decodes.
//
// This is the whole route in one measurement. If reading 260 artifacts costs about what
// holding 260 matchers costs -- and holding them was measured at 27.9 MiB -- then the
// tunnel can serve every country code in the shipped file, and the 149 MiB it pays today
// is paid entirely for a decode whose result was always small enough.
func TestMaximalGeoIPStackFitsOnceCompiled(t *testing.T) {
	stageGeoMeasurement(t)
	options := testOptions(t)
	codes, _ := enumerateShippedGeoNames(t, options.WorkingPath)

	loader, err := geodata.GetGeoDataLoader("memconservative")
	if err != nil {
		t.Fatal(err)
	}

	// Artifacts go to DISK, and the read side reads them from disk one at a time.
	// Holding all 260 blobs in a map would put 18.3 MiB of the test's own bookkeeping
	// inside the measurement and report a budget overrun the tunnel would never have --
	// the tunnel opens one file, builds one set, and moves on.
	artifactDir := t.TempDir()
	compiled := make([]string, 0, len(codes))
	totalBytes := 0
	for _, code := range codes {
		cidrList, err := loader.LoadGeoIP(code)
		if err != nil {
			continue
		}
		set := cidr.NewIpCidrSet()
		for _, entry := range cidrList {
			addr, ok := netip.AddrFromSlice(entry.Ip)
			if !ok {
				continue
			}
			_ = set.AddIpCidr(netip.PrefixFrom(addr, int(entry.Prefix)))
		}
		if err := set.Merge(); err != nil {
			continue
		}
		var encoded bytes.Buffer
		if err := set.WriteBin(&encoded); err != nil {
			continue
		}
		path := filepath.Join(artifactDir, code+".ipcidr")
		if err := os.WriteFile(path, encoded.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		compiled = append(compiled, path)
		totalBytes += encoded.Len()
	}
	geodata.ClearGeoIPCache()

	t.Logf("compiled %d/%d country codes into %.1f MiB of artifacts on disk",
		len(compiled), len(codes), float64(totalBytes)/(1<<20))
	if len(compiled) == 0 {
		t.Fatal("compiled nothing; this would measure an empty loop")
	}

	// Load: this is the tunnel's job, and it is the number that decides the route.
	loadedSets := make([]*cidr.IpCidrSet, 0, len(compiled))
	measurePeakAndRetained(t, "reading back ALL "+fmt.Sprint(len(compiled))+" compiled country codes", func() {
		for _, path := range compiled {
			file, err := os.Open(path)
			if err != nil {
				continue
			}
			set, err := cidr.ReadIpCidrSet(file)
			file.Close()
			if err != nil {
				continue
			}
			// Held, exactly as the loader's cache would hold them, or this would
			// measure 260 sets being collected instead of 260 sets resident.
			loadedSets = append(loadedSets, set)
		}
	})
	if len(loadedSets) != len(compiled) {
		t.Fatalf("read back %d of %d artifacts", len(loadedSets), len(compiled))
	}
	// Touch one, so a structure that defers work cannot hide it past the measurement.
	if !loadedSets[0].IsContainForString("0.0.0.0") {
		t.Logf("(sanity: first set does not contain 0.0.0.0, as expected)")
	}
	runtime.KeepAlive(loadedSets)
}

// And the shape a reader could actually write: one configuration naming every country code,
// every category, ASN and the DNS-side geoip filter, parsed under both policies.
func TestMaximalStackedConfigurationParse(t *testing.T) {
	stageGeoMeasurement(t)
	options := testOptions(t)
	codes, categories := enumerateShippedGeoNames(t, options.WorkingPath)

	var rules strings.Builder
	for _, code := range codes {
		fmt.Fprintf(&rules, "  - GEOIP,%s,DIRECT\n", code)
		fmt.Fprintf(&rules, "  - SRC-GEOIP,%s,DIRECT\n", code)
	}
	for _, category := range categories {
		fmt.Fprintf(&rules, "  - GEOSITE,%s,DIRECT\n", category)
	}
	rules.WriteString("  - IP-ASN,13335,DIRECT\n")
	rules.WriteString("  - SRC-IP-ASN,15169,DIRECT\n")
	rules.WriteString("  - MATCH,DIRECT\n")

	config := fmt.Sprintf(`mode: rule
ipv6: true
geodata-mode: true
geodata-loader: standard
proxies: []
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  nameserver:
    - 223.5.5.5
  nameserver-policy:
    "geosite:cn": [223.5.5.5]
    "geosite:geolocation-!cn": [1.1.1.1]
    "geosite:category-companies": [1.1.1.1]
  fallback:
    - 1.1.1.1
  fallback-filter:
    geoip: true
    geoip-code: CN
rules:
%s`, rules.String())

	t.Logf("stacked configuration: %d GEOIP + %d SRC-GEOIP + %d GEOSITE + 2 ASN rules, %d bytes",
		len(codes), len(codes), len(categories), len(config))

	for _, underNE := range []bool{true, false} {
		where := "containing App"
		if underNE {
			where = "packet tunnel"
		}
		geodata.ClearGeoIPCache()
		geodata.ClearGeoSiteCache()
		geodata.SetGeodataMode(true)
		geodata.SetLoader("memconservative")

		measurePeakAndRetained(t, "maximal stacked parse in the "+where, func() {
			if _, err := parseConfigForIOS(config, underNE); err != nil {
				t.Logf("parse failed (data, not a test error): %v", err)
			}
		})
	}
}

// End to end, with the real shipped file: the App compiles, the tunnel reads, and the
// number that used to be 149 MiB is measured again on the same configuration.
//
// This is the test the whole task was for. Everything above measures a cost; this measures
// whether the wiring actually collects it -- App-side compilation and tunnel-side loading
// have to agree on the same artifacts, and if they do not, every GEOIP rule silently
// matches nothing, which is worse than the defect being fixed.
func TestCompiledGeoIPTakesTheTunnelUnderBudget(t *testing.T) {
	stageGeoMeasurement(t)
	options := testOptions(t)
	codes, _ := enumerateShippedGeoNames(t, options.WorkingPath)

	var rules strings.Builder
	for _, code := range codes {
		fmt.Fprintf(&rules, "  - GEOIP,%s,DIRECT\n", code)
	}
	rules.WriteString("  - MATCH,DIRECT\n")
	config := fmt.Sprintf(`mode: rule
geodata-mode: true
proxies: []
dns:
  enable: true
  nameserver:
    - 223.5.5.5
rules:
%s`, rules.String())

	// The App's pass, which is allowed to be expensive.
	summary, err := PrepareGeoIPCache(config, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("app-side: %s", summary)
	// Counted, not substring-matched: "260 compiled" contains "0 compiled".
	if !strings.HasPrefix(summary, fmt.Sprintf("geoip: %d compiled", len(codes))) {
		t.Fatalf("the App did not compile every country it was given, so the tunnel "+
			"measurement below would be measuring something else: %s", summary)
	}

	// The tunnel's pass, on the same configuration, with the shipped policy.
	geodata.ClearGeoIPCache()
	geodata.SetGeodataMode(true)
	geodata.SetLoader("memconservative")
	peak := measurePeakAndRetained(t, "tunnel parse of ALL country codes, compiled", func() {
		if _, err := parseConfigForIOS(config, true); err != nil {
			t.Fatalf("the tunnel could not parse a configuration the App prepared: %v", err)
		}
	})
	// This one ASSERTS. Every other measurement in this package reports, because no
	// ceiling had been agreed for those paths; here there is one, it is the tunnel's
	// whole budget, and the worst configuration anyone can write now fits inside it.
	// 149.0 MiB before compiling, 67.3 with artifacts read one decoder at a time,
	// 47.4 with the decoder shared. If this goes red, the tunnel is dying again.
	if peak > packetTunnelBudgetBytes {
		t.Fatalf("the worst legal configuration peaks at %.1f MiB, over the tunnel budget "+
			"of %.0f MiB: on a device this is a kill",
			mib(peak), float64(packetTunnelBudgetBytes)/(1<<20))
	}

	// And the matchers must actually answer, or "under budget" would just mean the tunnel
	// loaded nothing at all -- which is exactly what a staging disagreement looks like.
	geodata.SetCompiledGeoIPOnly(true)
	t.Cleanup(func() { geodata.SetCompiledGeoIPOnly(false) })
	geodata.ClearGeoIPCache()
	matcher, err := geodata.LoadGeoIPMatcher("cn")
	if err != nil {
		t.Fatal(err)
	}
	if matcher.Count() == 0 {
		t.Fatal("the tunnel read an EMPTY cn matcher: the App and the tunnel disagree on " +
			"where artifacts live, and every GEOIP rule would silently match nothing")
	}
	t.Logf("tunnel reads compiled cn: %d records", matcher.Count())
}

// Where does the difference go? Reading 260 raw sets measured +34.7 MiB, but reading the
// same 260 through the compiled artifact measured much more. The artifact adds exactly one
// thing -- the zstd frame the rule-set layout requires -- so this isolates it rather than
// guessing at it.
func TestCompiledGeoIPReadCostIsNotTheFormatItself(t *testing.T) {
	stageGeoMeasurement(t)
	options := testOptions(t)
	codes, _ := enumerateShippedGeoNames(t, options.WorkingPath)

	config := "rules:\n"
	for _, code := range codes {
		config += fmt.Sprintf("  - GEOIP,%s,DIRECT\n", code)
	}
	if _, err := PrepareGeoIPCache(config, true); err != nil {
		t.Fatal(err)
	}
	geodata.ClearGeoIPCache()

	held := make([]any, 0, len(codes))
	measurePeakAndRetained(t, "compiled.LoadIPCIDR x"+fmt.Sprint(len(codes))+" (zstd framed)", func() {
		for _, code := range codes {
			set, _, err := compiled.LoadIPCIDR(geodata.CompiledGeoIPDir(), code)
			if err != nil {
				continue
			}
			held = append(held, set)
		}
	})
	if len(held) != len(codes) {
		t.Fatalf("read %d of %d artifacts", len(held), len(codes))
	}
	runtime.KeepAlive(held)
}
