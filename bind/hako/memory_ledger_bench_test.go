package hako

// The coefficient bench: what one of each thing costs, measured, regenerated per release,
// shipped as data.
//
// exists. The geo table in CLIENT-CONSUME-2026-08-06 was the prototype; this generalizes
// it across the allocating families of CONFIG-FIELD-INVENTORY, and the coverage gate
// (check_memory_ledger_coverage.py) goes red when a family has no row here — the case set
// closes at the inventory instead of growing one patch at a time.
//
// Method, and its honesty constraints, learned the hard way this week:
//   - Δ physFootprint, not HeapAlloc: jetsam judges phys_footprint, and the client's own
//     device numbers are footprint numbers. The two disagree by the runtime's overhead.
//   - Under the tunnel's own GC posture (SetMemoryLimit 37.5 MiB, SetGCPercent 10).
//     Host-default measurements were 35% high on the same workload and were retracted.
//   - N=1/10/100/1000 rather than one point, because per-entry cost is the SLOPE: the
//     intercept is the family's fixed machinery, and quoting N=1 as "per entry" charges
//     every entry for it.
//   - A zero delta is a claim that the expensive thing did not happen. Every family
//     asserts its work actually ran (a count, a parse success) before its number is real.
//
// Run:
//   HAKO_MEMORY_LEDGER=1 go test -run TestGenerateMemoryLedger -count=1 ./...
// writes (path via HAKO_MEMORY_LEDGER_OUT).

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/TokenPLS/Hako/common/lru"
	"github.com/TokenPLS/Hako/component/geodata"
	C "github.com/TokenPLS/Hako/constant"

	D "github.com/miekg/dns"
)

type ledgerRow struct {
	// Family matches a family name in memory-ledger-families.json; the coverage gate
	// joins on it.
	Family string `json:"family"`
	// Unit is what N counts: "rule", "node", "domain", "entry", "connection".
	Unit string `json:"unit"`
	// PerEntryBytes is the slope between the largest two N points — the marginal cost of
	// one more, with the family's fixed machinery excluded.
	PerEntryBytes int64 `json:"perEntryBytes"`
	// FixedBytes is the intercept at N=1 minus one slope — what the family costs to exist
	// at all.
	FixedBytes int64 `json:"fixedBytes"`
	// Points carry BOTH readings per N. Slope comes from heap: on Darwin FreeOSMemory
	// is MADV_FREE, so freed pages leave phys_footprint only when the system reclaims
	// them -- a later family allocates into pages the footprint already counts and reads
	// Δ0, which is how a 1000-entry cache first benched as free. Footprint is what jetsam
	// judges and is kept as data; heap is what a marginal entry costs and is stable.
	Points     map[string]int64 `json:"footprintPoints"`
	HeapPoints map[string]int64 `json:"heapPoints"`
	Note       string           `json:"note,omitempty"`
}

type ledgerFile struct {
	SchemaVersion int         `json:"schemaVersion"`
	CoreRevision  string      `json:"coreRevision"`
	Regime        string      `json:"regime"`
	Rows          []ledgerRow `json:"rows"`
}

// settledReadings reads phys_footprint and HeapAlloc after the heap has quiesced.
func settledReadings() (footprint int64, heap uint64) {
	runtime.GC()
	runtime.GC()
	debug.FreeOSMemory()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return MemoryFootprint(), stats.HeapAlloc
}

// benchFamily measures one family across the N ladder. build must construct exactly n of
// the unit and return a witness count proving the work ran; the constructed value is
// returned to keep it live across the measurement.
func benchFamily(t *testing.T, family, unit, note string, ns []int,
	build func(n int) (witness int, keepAlive any)) ledgerRow {
	t.Helper()
	points := make(map[string]int64, len(ns))
	heapPoints := make(map[string]int64, len(ns))
	var keep []any
	for _, n := range ns {
		beforeFp, beforeHeap := settledReadings()
		witness, alive := build(n)
		if witness < n {
			t.Fatalf("%s: built %d of %d %ss — a shortfall here is the measurement not "+
				"happening, which reads as cheapness", family, witness, n, unit)
		}
		keep = append(keep, alive)
		afterFp, afterHeap := settledReadings()
		points[fmt.Sprint(n)] = afterFp - beforeFp
		heapPoints[fmt.Sprint(n)] = int64(afterHeap) - int64(beforeHeap)
		keep = keep[:0]
		runtime.GC()
	}
	_ = keep
	last, prev := ns[len(ns)-1], ns[len(ns)-2]
	slope := (heapPoints[fmt.Sprint(last)] - heapPoints[fmt.Sprint(prev)]) / int64(last-prev)
	fixed := heapPoints[fmt.Sprint(ns[0])] - slope*int64(ns[0])
	if fixed < 0 {
		fixed = 0
	}
	return ledgerRow{Family: family, Unit: unit, PerEntryBytes: slope, FixedBytes: fixed,
		Points: points, HeapPoints: heapPoints, Note: note}
}

func TestGenerateMemoryLedger(t *testing.T) {
	if os.Getenv("HAKO_MEMORY_LEDGER") == "" {
		t.Skip("set HAKO_MEMORY_LEDGER to regenerate the coefficient bench")
	}
	options := testOptions(t)
	if err := os.MkdirAll(options.WorkingPath, 0o755); err != nil {
		t.Fatal(err)
	}
	stageBundledGeodata(t, options.WorkingPath)
	options.MemoryLimit = 50 << 20 // the tunnel's regime: soft limit 37.5 MiB, GC 10%
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	C.SetHomeDir(options.WorkingPath)
	geodata.SetGeodataMode(true)
	geodata.SetLoader("memconservative")
	t.Cleanup(func() {
		geodata.ClearGeoIPCache()
		geodata.ClearGeoSiteCache()
	})

	ladder := []int{1, 10, 100, 1000}
	var rows []ledgerRow

	// ---- per-entry resident: configuration families, measured through the real parse ----

	// parseWith returns the parsed config so the caller can KEEP IT ALIVE across the
	// measurement. The first draft returned nothing and kept the YAML string instead, so
	// every per-entry structure was garbage by the time the after-reading ran -- the bench
	// measured what survives GC with no live reference, which is nothing, and printed
	// 0 B/entry as if the family were free. Resident means held by a running tunnel; the
	// config object is what a running tunnel holds.
	parseWith := func(t *testing.T, body string) any {
		t.Helper()
		cfg, err := parseConfigForIOS(body, true)
		if err != nil {
			t.Fatalf("parse failed, so nothing was measured: %v", err)
		}
		return cfg
	}

	rows = append(rows, benchFamily(t, "rules.inline", "rule", "DOMAIN-SUFFIX rules", ladder,
		func(n int) (int, any) {
			var rules strings.Builder
			for i := 0; i < n; i++ {
				fmt.Fprintf(&rules, "  - DOMAIN-SUFFIX,host%d.example,DIRECT\n", i)
			}
			body := "mode: rule\nproxies: []\ndns:\n  enable: true\n  nameserver: [223.5.5.5]\nrules:\n" +
				rules.String() + "  - MATCH,DIRECT\n"
			cfg := parseWith(t, body)
			return n, cfg
		}))

	rows = append(rows, benchFamily(t, "hosts.entries", "entry", "static hosts", ladder,
		func(n int) (int, any) {
			var hosts strings.Builder
			for i := 0; i < n; i++ {
				fmt.Fprintf(&hosts, "  host%d.example: 198.51.100.%d\n", i, i%250+1)
			}
			body := "mode: rule\nproxies: []\nhosts:\n" + hosts.String() +
				"dns:\n  enable: true\n  nameserver: [223.5.5.5]\nrules:\n  - MATCH,DIRECT\n"
			cfg := parseWith(t, body)
			return n, cfg
		}))

	rows = append(rows, benchFamily(t, "proxies.inline", "node", "socks5 nodes", ladder,
		func(n int) (int, any) {
			var proxies strings.Builder
			for i := 0; i < n; i++ {
				fmt.Fprintf(&proxies, "  - {name: n%d, type: socks5, server: 198.51.100.1, port: %d}\n", i, 1024+i%40000)
			}
			body := "mode: rule\nproxies:\n" + proxies.String() +
				"dns:\n  enable: true\n  nameserver: [223.5.5.5]\nrules:\n  - MATCH,DIRECT\n"
			cfg := parseWith(t, body)
			return n, cfg
		}))

	rows = append(rows, benchFamily(t, "proxy-groups", "group", "select groups over one node", []int{1, 10, 100},
		func(n int) (int, any) {
			var groups strings.Builder
			for i := 0; i < n; i++ {
				fmt.Fprintf(&groups, "  - {name: g%d, type: select, proxies: [n0]}\n", i)
			}
			body := "mode: rule\nproxies:\n  - {name: n0, type: socks5, server: 198.51.100.1, port: 1080}\n" +
				"proxy-groups:\n" + groups.String() +
				"dns:\n  enable: true\n  nameserver: [223.5.5.5]\nrules:\n  - MATCH,DIRECT\n"
			cfg := parseWith(t, body)
			return n, cfg
		}))

	rows = append(rows, benchFamily(t, "dns.nameserver-policy.plain", "entry", "exact-domain policy keys", ladder,
		func(n int) (int, any) {
			var policy strings.Builder
			for i := 0; i < n; i++ {
				fmt.Fprintf(&policy, "    \"host%d.example\": [223.5.5.5]\n", i)
			}
			body := "mode: rule\nproxies: []\ndns:\n  enable: true\n  nameserver: [223.5.5.5]\n  nameserver-policy:\n" +
				policy.String() + "rules:\n  - MATCH,DIRECT\n"
			cfg := parseWith(t, body)
			return n, cfg
		}))

	rows = append(rows, benchFamily(t, "dns.fake-ip-filter", "entry", "fake-ip-filter suffixes", ladder,
		func(n int) (int, any) {
			var filter strings.Builder
			for i := 0; i < n; i++ {
				fmt.Fprintf(&filter, "    - \"+.host%d.example\"\n", i)
			}
			body := "mode: rule\nproxies: []\ndns:\n  enable: true\n  enhanced-mode: fake-ip\n" +
				"  fake-ip-range: 198.18.0.1/16\n  fake-ip-filter:\n" + filter.String() +
				"  nameserver: [223.5.5.5]\nrules:\n  - MATCH,DIRECT\n"
			cfg := parseWith(t, body)
			return n, cfg
		}))

	rows = append(rows, benchFamily(t, "sub-rules", "rule", "rules inside one sub-rule", []int{1, 10, 100, 1000},
		func(n int) (int, any) {
			var sub strings.Builder
			for i := 0; i < n; i++ {
				fmt.Fprintf(&sub, "    - DOMAIN-SUFFIX,host%d.example,DIRECT\n", i)
			}
			body := "mode: rule\nproxies: []\nsub-rules:\n  branch:\n" + sub.String() +
				"dns:\n  enable: true\n  nameserver: [223.5.5.5]\nrules:\n  - SUB-RULE,(DST-PORT,443),branch\n  - MATCH,DIRECT\n"
			cfg := parseWith(t, body)
			return n, cfg
		}))

	// Geo naming: the per-code coefficients already measured live in the geo table; here
	// the bench rows carry the same shape so the bill has one source. Compiled path, which
	// is what a tunnel actually pays.
	rows = append(rows, benchFamily(t, "geo.geoip-compiled", "country", "compiled artifact read-back", []int{1, 10, 100},
		func(n int) (int, any) {
			codes, _ := enumerateShippedGeoNames(t, options.WorkingPath)
			if n > len(codes) {
				n = len(codes)
			}
			if _, err := PrepareGeoIPCache(geoRuleConfig(codes[:n])); err != nil {
				t.Fatal(err)
			}
			geodata.ClearGeoIPCache()
			geodata.SetCompiledGeoIPOnly(true)
			defer geodata.SetCompiledGeoIPOnly(false)
			loaded := 0
			var keep []any
			for _, code := range codes[:n] {
				matcher, err := geodata.LoadGeoIPMatcher(code)
				if err != nil || matcher.Count() == 0 {
					continue
				}
				loaded++
				keep = append(keep, matcher)
			}
			geodata.ClearGeoIPCache()
			return loaded, keep
		}))

	// Flat toggles are deliberately NOT benched at parse: sniffer allocates at apply and a
	// parse-side row printed -16 KiB of page noise as if it were a fact. The probe lines
	// apply:sniffer and apply:dns cover them with live numbers, and the families file
	// records that ruling so the coverage gate holds it.

	// ---- runtime per-connection half: DNS cache entries, the one measurable off-device ----

	rows = append(rows, benchFamily(t, "dns.cache-entries", "entry", "cached A answers", ladder,
		func(n int) (int, any) {
			// The SAME structure the resolver holds -- lru of *D.Msg, keyed by the question
			// string (dns/resolver.go newCache) -- built through the public lru package
			// rather than through an accessor invented on the upstream dns package for a
			// bench's sake. If the resolver's cache type changes, the families file is
			// where that change must be re-ruled.
			cache := lru.New(lru.WithSize[string, *D.Msg](4096), lru.WithStale[string, *D.Msg](true))
			for i := 0; i < n; i++ {
				name := fmt.Sprintf("host%d.example.", i)
				msg := new(D.Msg)
				msg.SetQuestion(name, D.TypeA)
				answer := msg.Copy()
				answer.Answer = []D.RR{&D.A{
					Hdr: D.RR_Header{Name: name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 300},
					A:   []byte{198, 51, 100, byte(i%250 + 1)},
				}}
				cache.Set(msg.Question[0].String(), answer)
			}
			return n, cache
		}))

	revision := "unknown"
	if content, err := os.ReadFile(filepath.Join("..", "..", ".git", "HEAD")); err == nil {
		revision = strings.TrimSpace(string(content))
	}
	output := ledgerFile{
		SchemaVersion: 1,
		CoreRevision:  revision,
		Regime:        "SetMemoryLimit=37.5MiB SetGCPercent=10 physFootprint",
		Rows:          rows,
	}
	target := os.Getenv("HAKO_MEMORY_LEDGER_OUT")
	if target == "" {
		target = filepath.Join("..", "..", "docs", "ios-adaptation", "MEMORY-LEDGER-BENCH.json")
	}
	encoded, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, append(encoded, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		t.Logf("%-28s %8d B/%s  fixed %d B", row.Family, row.PerEntryBytes, row.Unit, row.FixedBytes)
	}
}

func geoRuleConfig(codes []string) string {
	var rules strings.Builder
	for _, code := range codes {
		fmt.Fprintf(&rules, "  - GEOIP,%s,DIRECT\n", code)
	}
	return "rules:\n" + rules.String() + "  - MATCH,DIRECT\n"
}
