package hako

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/component/geodata"
	"github.com/TokenPLS/Hako/component/mmdb"
	C "github.com/TokenPLS/Hako/constant"

	"net/netip"
)

// What a hostile-but-legal configuration costs to start, measured rather than argued.
//
// The 50 MiB an iOS packet tunnel gets is not a budget to be careful inside; it is a
// budget some work does not fit in at all. geosite:cn peaks at 72.7 MiB to produce a
// 0.9 MiB matcher, which is why the App compiles categories and the tunnel only reads
// them. That protection covers geosite and NOTHING ELSE:
//
//	geosite  -> compiledGeoSiteOnly, App-side, tunnel reads artefacts   PROTECTED
//	GeoIP    -> InitGeoIP + LoadGeoIPMatcher, in whatever process asks  UNMEASURED
//	ASN      -> mmdb.ASNInstance()                                      UNMEASURED
//
// So this file measures the two nobody has. It is skipped by default because it loads
// real geodata and takes real time; set HAKO_MEASURE_STARTUP_OOM to run it.
//
// The fixture is not "lots of rules". It aims at the specific hazards on record:
//
// 1. MANY DISTINCT COUNTRY CODES. recorded the degenerate path: an empty country
//     code shifts a record's first byte from 0x0A to 0x12, memconservative's scan gives
//     up, and it falls back to proto.Unmarshal of the WHOLE FILE -- once per country
//     code. GeoIP.dat is 17 MB. Ten codes on that path is not ten times one matcher.
//  2. dns.fallback-filter.geoip, which loads the database from the DNS side rather than
//     the rules side, reaching it before any rule has matched.
//  3. IP-ASN, the only consumer of ASN.mmdb.
//  4. Several geosite categories named through nameserver-policy -- the shape that
//     killed a reader's tunnel before compiled artefacts existed.
//
// Read the numbers, not the verdict: this test does not assert a ceiling, because
// nobody has established what the ceiling should be for these paths. It reports, and
// the reporting is the point.

// hostileGeoConfig names every geo resource a legal configuration can reach, in the
// shapes most likely to cost memory.
//
// geodataMode is the switch that decides which GeoIP resource the same GEOIP rules
// reach: true decodes GeoIP.dat, false looks up geoip.metadb (rules/common/geoip.go:52,
// 108, 134, 175). Both are measured, because the difference between them turns out to
// be the difference between fitting in the budget and not.
func hostileGeoConfig(geodataMode bool) string {
	countries := []string{"cn", "us", "jp", "hk", "sg", "kr", "de", "gb", "ru", "in"}
	var rules strings.Builder
	for _, code := range countries {
		fmt.Fprintf(&rules, "  - GEOIP,%s,DIRECT\n", code)
	}
	// Same codes again with no-resolve: a different rule object per line, each holding
	// its own matcher reference.
	for _, code := range countries {
		fmt.Fprintf(&rules, "  - GEOIP,%s,DIRECT,no-resolve\n", code)
	}
	rules.WriteString("  - IP-ASN,13335,DIRECT\n")
	rules.WriteString("  - IP-ASN,15169,DIRECT\n")
	rules.WriteString("  - GEOSITE,cn,DIRECT\n")
	rules.WriteString("  - GEOSITE,geolocation-!cn,DIRECT\n")
	rules.WriteString("  - MATCH,DIRECT\n")

	return fmt.Sprintf(`mode: rule
ipv6: true
geodata-mode: %t
geodata-loader: memconservative
proxies: []
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  nameserver:
    - 223.5.5.5
  nameserver-policy:
    "geosite:cn,private": [223.5.5.5]
    "geosite:gfw": [1.1.1.1]
    "geosite:geolocation-!cn": [1.1.1.1]
  fallback:
    - 1.1.1.1
  fallback-filter:
    geoip: true
    geoip-code: CN
rules:
%s`, geodataMode, rules.String())
}

func measurePeakAndRetained(t *testing.T, label string, work func()) (peakDelta uint64) {
	t.Helper()
	settled := func() uint64 {
		runtime.GC()
		runtime.GC()
		var stats runtime.MemStats
		runtime.ReadMemStats(&stats)
		return stats.HeapAlloc
	}
	before := settled()

	var peak atomic.Uint64
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		var stats runtime.MemStats
		for {
			select {
			case <-stop:
				return
			default:
			}
			runtime.ReadMemStats(&stats)
			if stats.HeapAlloc > peak.Load() {
				peak.Store(stats.HeapAlloc)
			}
			time.Sleep(time.Millisecond)
		}
	}()

	work()

	close(stop)
	<-done
	after := settled()

	mib := func(bytes uint64) float64 { return float64(bytes) / (1 << 20) }
	t.Logf("%s: peak=%.1f MiB (+%.1f above baseline)  retained=%.1f MiB (+%.1f)  [NE budget 50 MiB]",
		label, mib(peak.Load()), mib(peak.Load())-mib(before),
		mib(after), mib(after)-mib(before))
	if peak.Load() > 50<<20 {
		t.Logf("%s: PEAK EXCEEDS THE PACKET TUNNEL BUDGET — on a device this is a kill, "+
			"not a slow start", label)
	}
	// Returned so a caller with an agreed ceiling can assert instead of report. Most
	// callers here have none, which is why this reports by default.
	if peak.Load() > before {
		return peak.Load() - before
	}
	return 0
}

// The tunnel's own shape: compiled-geosite on, so geosite is protected and whatever is
// left is what the unprotected paths cost.
func TestStartupOOMBudgetUnderPacketTunnelPolicy(t *testing.T) {
	if os.Getenv("HAKO_MEASURE_STARTUP_OOM") == "" {
		t.Skip("set HAKO_MEASURE_STARTUP_OOM to measure geo startup cost")
	}
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
	t.Cleanup(geodata.ClearGeoSiteCache)
	t.Cleanup(geodata.ClearGeoIPCache)

	// Both GeoIP resources, same rules. geodata-mode false is what a configuration that
	// never mentions the key gets, and is the one that decides whether the common case
	// is safe.
	for _, geodataMode := range []bool{false, true} {
		config := hostileGeoConfig(geodataMode)
		geodata.SetGeodataMode(geodataMode)
		label := fmt.Sprintf("packet-tunnel parse (geodata-mode %t)", geodataMode)
		measurePeakAndRetained(t, label, func() {
			if _, err := parseConfigForIOS(config, true); err != nil {
				// A failure is a result too: it says which resource the tunnel cannot
				// reach, which is the same information in a different shape.
				t.Logf("parse failed (this is data, not a test error): %v", err)
			}
		})
		geodata.ClearGeoIPCache()
		geodata.ClearGeoSiteCache()
	}
}

// The containing App runs the same configuration without compiled-only, which is where
// geosite compilation happens. This is the measurement that says whether the App's own
// pass is affordable on a phone.
func TestStartupOOMBudgetInContainingApp(t *testing.T) {
	if os.Getenv("HAKO_MEASURE_STARTUP_OOM") == "" {
		t.Skip("set HAKO_MEASURE_STARTUP_OOM to measure geo startup cost")
	}
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
	t.Cleanup(geodata.ClearGeoSiteCache)
	t.Cleanup(geodata.ClearGeoIPCache)

	for _, geodataMode := range []bool{false, true} {
		config := hostileGeoConfig(geodataMode)
		geodata.SetGeodataMode(geodataMode)
		label := fmt.Sprintf("containing-app parse (geodata-mode %t)", geodataMode)
		measurePeakAndRetained(t, label, func() {
			if _, err := parseConfigForIOS(config, false); err != nil {
				t.Logf("parse failed (this is data, not a test error): %v", err)
			}
		})
		geodata.ClearGeoIPCache()
		geodata.ClearGeoSiteCache()
	}
}

// Isolate the path with no protection at all: GeoIP alone, one country code at a time,
// so the cost of the tenth is visible next to the cost of the first. If the degenerate
// full-file decode is reachable, this is where it shows up as a flat 17 MB per code
// instead of a matcher-sized increment.
func TestGeoIPPerCountryCodeBudget(t *testing.T) {
	if os.Getenv("HAKO_MEASURE_STARTUP_OOM") == "" {
		t.Skip("set HAKO_MEASURE_STARTUP_OOM to measure geoip load cost")
	}
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
	t.Cleanup(geodata.ClearGeoIPCache)

	for _, code := range []string{"cn", "us", "jp", "hk", "sg"} {
		measurePeakAndRetained(t, "geoip:"+code, func() {
			matcher, err := geodata.LoadGeoIPMatcher(code)
			if err != nil {
				t.Logf("geoip %s: %v", code, err)
				return
			}
			t.Logf("geoip %s: %d records", code, matcher.Count())
		})
	}
}

// stageGeoMeasurement brings up a working directory with every shipped geo resource in it,
// under the loader iOS forces.
func stageGeoMeasurement(t *testing.T) {
	t.Helper()
	if os.Getenv("HAKO_MEASURE_STARTUP_OOM") == "" {
		t.Skip("set HAKO_MEASURE_STARTUP_OOM to measure geo load cost")
	}
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
	t.Cleanup(geodata.ClearGeoSiteCache)
	t.Cleanup(geodata.ClearGeoIPCache)
}

// GeoSite.dat, the resource that already has a protection built for it. Measured here too
// so the four sit in one table: a number is only alarming next to its neighbours.
func TestGeoSiteCategoryBudgetAcrossResources(t *testing.T) {
	stageGeoMeasurement(t)
	geodata.SetCompiledGeoSiteOnly(false)
	t.Cleanup(func() { geodata.SetCompiledGeoSiteOnly(false) })

	for _, category := range []string{"cn", "geolocation-!cn", "private"} {
		measurePeakAndRetained(t, "geosite:"+category, func() {
			matcher, err := geodata.LoadGeoSiteMatcher(category)
			if err != nil {
				t.Logf("geosite %s: %v", category, err)
				return
			}
			t.Logf("geosite %s: %d records", category, matcher.Count())
		})
	}
}

// ASN.mmdb, the only consumer of which is IP-ASN. maxminddb.Open memory-maps, so the
// expectation is cheap -- but "expected cheap" is what GeoIP was until it was measured at
// 131 MiB, so it gets a number like everything else.
func TestASNDatabaseBudget(t *testing.T) {
	stageGeoMeasurement(t)

	measurePeakAndRetained(t, "asn.mmdb open+lookup", func() {
		reader := mmdb.ASNInstance()
		// The file was staged above; a reader that cannot answer is a failed
		// measurement, not a quiet one. (`.Reader == nil` used to be read
		// here, and it is always nil behind the holder -- which made this an
		// early return that measured nothing.)
		if !reader.Available() {
			t.Fatal("ASN reader unavailable after staging ASN.mmdb")
		}
		// One lookup, so the cost of touching a page is inside the measurement rather
		// than deferred past it -- an mmap that is never read proves nothing.
		asn, org := reader.LookupASN(netip.MustParseAddr("1.1.1.1").AsSlice())
		t.Logf("asn: 1.1.1.1 -> AS%v %v", asn, org)
	})
}

// geoip.metadb, the path taken when geodata-mode is false -- the OTHER way a
// configuration reaches IP geolocation, and the default for anyone who does not set
// geodata-mode at all.
func TestGeoIPMetaDatabaseBudget(t *testing.T) {
	stageGeoMeasurement(t)
	geodata.SetGeodataMode(false)
	t.Cleanup(func() { geodata.SetGeodataMode(true) })

	measurePeakAndRetained(t, "geoip.metadb open+lookup", func() {
		reader := mmdb.IPInstance()
		if !reader.Available() {
			t.Fatal("mmdb reader unavailable after staging geoip.metadb")
		}
		codes := reader.LookupCode(netip.MustParseAddr("1.1.1.1").AsSlice())
		t.Logf("metadb: 1.1.1.1 -> %v", codes)
	})
}
