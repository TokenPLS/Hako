package hako

import (
	"bytes"
	"net/netip"
	"os"
	"testing"

	"github.com/TokenPLS/Hako/component/cidr"
	"github.com/TokenPLS/Hako/component/geodata"
)

// Can the tunnel hold every country code, if it never decodes one?
//
// The peak measured in CORE-TASK-GEODATA-STARTUP-OOM is the DECODE, not the result:
// geosite:cn peaks at 72.7 MiB to produce a 0.9 MiB matcher. So the question is not
// "how do we avoid GeoIP" but "what does GeoIP cost once it is already built".
//
// Upstream answers that itself. router.geoIPMatcher holds a *cidr.IpCidrSet
// (router/condition.go:158), and cidr.IpCidrSet already has both halves of a compact
// serialisation -- WriteBin and ReadIpCidrSet (component/cidr/ipcidr_set_bin.go:12,38) --
// because MRS rule-sets with behavior ipcidr are stored that way
// (rules/provider/ipcidr_strategy.go:18,58). Nothing has to be invented; the format we
// would want is the one mihomo already ships.
//
// This probe reproduces NewGeoIPMatcher's own construction (router/condition.go:156-171)
// rather than reaching into the matcher, so it measures the real thing without adding an
// accessor to upstream code for a measurement's sake.
//
// Three numbers decide the route:
//
//	decode  -- building the set from GeoIP.dat, what the tunnel pays today
//	bytes   -- what the built set weighs on disk
//	read    -- loading it back, what the tunnel would pay instead
func TestGeoIPCompactionIsWorthIt(t *testing.T) {
	if os.Getenv("HAKO_MEASURE_STARTUP_OOM") == "" {
		t.Skip("set HAKO_MEASURE_STARTUP_OOM to measure geoip compaction")
	}
	stageGeoMeasurement(t)

	loader, err := geodata.GetGeoDataLoader("memconservative")
	if err != nil {
		t.Fatal(err)
	}

	// us is the worst code in the shipped file: 343,952 records, 131.2 MiB to decode.
	// If the route holds for us it holds for everything.
	for _, code := range []string{"us", "cn", "jp"} {
		var encoded bytes.Buffer

		measurePeakAndRetained(t, "geoip:"+code+" decode from GeoIP.dat", func() {
			cidrList, err := loader.LoadGeoIP(code)
			if err != nil {
				t.Fatalf("geoip %s: %v", code, err)
			}
			set := cidr.NewIpCidrSet()
			for _, entry := range cidrList {
				addr, ok := netip.AddrFromSlice(entry.Ip)
				if !ok {
					t.Fatalf("geoip %s: invalid IP", code)
				}
				if err := set.AddIpCidr(netip.PrefixFrom(addr, int(entry.Prefix))); err != nil {
					t.Fatalf("geoip %s: AddIpCidr: %v", code, err)
				}
			}
			if err := set.Merge(); err != nil {
				t.Fatalf("geoip %s: Merge: %v", code, err)
			}
			if err := set.WriteBin(&encoded); err != nil {
				t.Fatalf("geoip %s: WriteBin: %v", code, err)
			}
			t.Logf("geoip:%s = %d records -> %.2f MiB artifact",
				code, len(cidrList), float64(encoded.Len())/(1<<20))
		})

		measurePeakAndRetained(t, "geoip:"+code+" read back compiled", func() {
			set, err := cidr.ReadIpCidrSet(bytes.NewReader(encoded.Bytes()))
			if err != nil {
				t.Fatalf("geoip %s: ReadIpCidrSet: %v", code, err)
			}
			// Touch it, so a lazy structure cannot hide its cost past the measurement.
			if set.IsContainForString("1.1.1.1") {
				t.Logf("geoip:%s contains 1.1.1.1", code)
			}
		})
	}
}
