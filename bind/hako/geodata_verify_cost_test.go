package hako

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func stageBundledGeodata(t *testing.T, workingPath string) {
	t.Helper()
	bundled := os.Getenv("HAKO_TEST_BUNDLED_GEO")
	if bundled == "" {
		// Found rather than spelled out. The client product tree has been renamed once
		// already, and a hardcoded path would have gone quietly stale then -- these tests
		// skip when the fixture is missing, so a wrong path reads as "no fixture here"
		// rather than as a failure. A glob also keeps the private tree's name out of a
		// file that ships.
		if matches, _ := filepath.Glob("../../apple/*/Resources/BundledGeoData"); len(matches) > 0 {
			bundled = matches[0]
		}
	}
	// GeoIP.dat and ASN.mmdb ride along because they ship to readers and nothing was
	// ever staging them: both paths had no fixture, so no test could reach either, and
	// both first measured as 0.0 MiB because the file was absent rather than because
	// the code was cheap (found while measuring startup OOM, 2026-08-06).
	for _, name := range []string{"geoip.metadb", "GeoSite.dat", "GeoIP.dat", "ASN.mmdb"} {
		src, err := os.Open(filepath.Join(bundled, name))
		if err != nil {
			t.Skipf("bundled geodata unavailable: %v", err)
		}
		dst, err := os.Create(filepath.Join(workingPath, name))
		if err != nil {
			src.Close()
			t.Fatal(err)
		}
		if _, err := io.Copy(dst, src); err != nil {
			t.Fatal(err)
		}
		src.Close()
		dst.Close()
	}
}

// A configuration that asks geosite for one small code must not pay for `CN`.
//
// mihomo's InitGeoSite health-checks the file by building the whole CN matcher
// — about ninety thousand domains — and the singleflight underneath
// (StoreResult: true) retains it for the life of the process. On this bundled
// GeoSite.dat that is ~14 MiB of Go heap for a matcher no rule asked for,
// measured against a config whose only geosite reference is `gfw` (4,335
// records). The iPad paid it for real: both 2026-08-01 TestFlight subscriptions
// carry `dns.fallback-filter: {geosite: [gfw]}` with zero GEOSITE rules, and
// jetsam killed the extension at the 50 MiB per-process limit with
// `rpages=3264` — about 51 MiB, one page row over the line the CN matcher put
// it on.
//
// On iOS that health check is redundant: the App validated the staged file
// before publishing it (ValidateGeodataForIOS, atomic immutable revisions), so
// the service marks it verified and mihomo goes straight to the matcher the
// configuration actually names. A corrupt file still fails closed — the gfw
// load itself errors and the config refuses to start with a readable reason.
//
// The bound is generous on purpose: the gfw-only heap delta measures ~1.8 MiB,
// the CN-tainted one ~16 MiB. Ten sits between the two far from both.
func TestGeositeStartDoesNotBuildTheCNMatcher(t *testing.T) {
	options := testOptions(t)
	options.MemoryLimit = 50 << 20 // the iOS Packet Tunnel regime
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	stageBundledGeodata(t, options.WorkingPath)

	content := `
mode: rule
dns:
  enable: true
  nameserver: [223.5.5.5]
  fallback: [1.1.1.1]
  fallback-filter: { geoip: false, geosite: [gfw] }
proxies:
  - {name: A, type: socks5, server: 127.0.0.1, port: 1080}
rules:
  - MATCH,DIRECT
`
	service, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatal(err)
	}

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	if err := service.Start(content); err != nil {
		t.Fatalf("start refused: %v", err)
	}
	t.Cleanup(func() { _ = service.Close() })

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	deltaMiB := (float64(after.HeapAlloc) - float64(before.HeapAlloc)) / (1 << 20)
	t.Logf("heap delta across Start: %.1f MiB", deltaMiB)
	if deltaMiB > 10 {
		t.Fatalf("Start cost %.1f MiB of retained heap for a gfw-only geosite config — the CN health-check matcher is back", deltaMiB)
	}
}

// The redundant health check is the only thing skipped, never the real load: a
// GeoSite.dat the configuration cannot use still refuses to start, with the
// core's own words.
//
// The code here is one no sibling test caches: mihomo's matcher singleflight is
// process-global with StoreResult, so a code another test already loaded would
// serve from cache and never touch the corrupt bytes.
func TestCorruptGeositeStillFailsClosed(t *testing.T) {
	options := testOptions(t)
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	stageBundledGeodata(t, options.WorkingPath)
	if err := os.WriteFile(
		filepath.Join(options.WorkingPath, "GeoSite.dat"),
		[]byte("<!DOCTYPE html>\nnot a geosite database\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}

	content := `
mode: rule
dns:
  enable: true
  nameserver: [223.5.5.5]
  fallback: [1.1.1.1]
  fallback-filter: { geoip: false, geosite: [netflix] }
proxies:
  - {name: A, type: socks5, server: 127.0.0.1, port: 1080}
rules:
  - MATCH,DIRECT
`
	service, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatal(err)
	}
	err = service.Start(content)
	if err == nil {
		_ = service.Close()
		t.Fatal("a corrupt GeoSite.dat started anyway — fail-closed is gone")
	}
	if testing.Verbose() {
		fmt.Println("refused with:", err)
	}
}
