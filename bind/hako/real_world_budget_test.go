package hako

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/TokenPLS/Hako/component/geodata"
	C "github.com/TokenPLS/Hako/constant"
	"gopkg.in/yaml.v3"
)

// The budget is SHARED, and the geo measurements alone never said so.
//
// geodata_maximal_stack_test.go took the whole 50 MiB as geo's to spend, got the worst geo
// configuration down to 47.4 MiB, and called it under budget. That is only true if nothing
// else in the configuration costs anything, and a real one is mostly the something else:
// dozens of rule-providers, several proxy-providers with a hundred nodes between them,
// fake-ip, a DNS cache, a sniffer, filtered groups.
//
// Both shapes are real. A reader can name every geo resource in a DNS block, and a reader
// can name none and carry fifty rule-providers instead. This file measures the second,
// from an actual configuration, so geo's real allowance is a number rather than an
// assumption.
//
// It runs against a staged directory rather than a checked-in fixture because a real
// configuration carries subscription credentials, and those do not enter the repository
// (AGENTS.md §6). Point HAKO_REAL_CONFIG at a config whose providers have already been
// rewritten to file form -- which is what the App does before the tunnel ever sees it
// .
func stagedRealConfig(t *testing.T) string {
	t.Helper()
	stage := os.Getenv("HAKO_REAL_STAGE")
	if stage == "" {
		t.Skip("set HAKO_REAL_STAGE to a directory holding config.yaml, proxy_provider/ and ruleset/")
	}
	content, err := os.ReadFile(filepath.Join(stage, "config.yaml"))
	if err != nil {
		t.Fatalf("staged configuration unavailable: %v", err)
	}

	// Provider payloads have to live under the home directory: the core refuses a path
	// outside it or SAFE_PATHS, which is the same containment the App relies on. Copying
	// them in and rewriting the prefix is what the App does with a downloaded payload.
	home := C.Path.HomeDir()
	for _, directory := range []string{"proxy_provider", "ruleset"} {
		source := filepath.Join(stage, directory)
		entries, err := os.ReadDir(source)
		if err != nil {
			t.Fatalf("staged %s unavailable: %v", directory, err)
		}
		target := filepath.Join(home, directory)
		if err := os.MkdirAll(target, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			payload, err := os.ReadFile(filepath.Join(source, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(target, entry.Name()), payload, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	return strings.ReplaceAll(string(content), stage, home)
}

// countProviders reports what the configuration actually carries, so a cheap measurement
// cannot be mistaken for a cheap configuration.
func countProviders(config string) (ruleProviders, proxyProviders int) {
	for _, line := range strings.Split(config, "\n") {
		if strings.Contains(line, "path:") && strings.Contains(line, "/ruleset/") {
			ruleProviders++
		}
		if strings.Contains(line, "path:") && strings.Contains(line, "/proxy_provider/") {
			proxyProviders++
		}
	}
	return ruleProviders, proxyProviders
}

// What a real reader's configuration costs the tunnel, end to end.
func TestRealWorldConfigurationFitsTheTunnel(t *testing.T) {
	stageGeoMeasurement(t)
	config := stagedRealConfig(t)

	ruleProviders, proxyProviders := countProviders(config)
	t.Logf("configuration carries %d rule-providers and %d proxy-providers",
		ruleProviders, proxyProviders)
	if ruleProviders == 0 {
		t.Fatal("no file rule-providers found: this would measure a configuration that " +
			"aborts before loading anything, which is how the previous attempt produced " +
			"0.6 MiB and meant nothing")
	}

	// The App's passes first, as they run on a device.
	geoSiteSummary, err := PrepareGeoSiteCache(config)
	if err != nil {
		t.Fatal(err)
	}
	geoIPSummary, err := PrepareGeoIPCache(config, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("app-side: %s", geoSiteSummary)
	t.Logf("app-side: %s", geoIPSummary)

	geodata.ClearGeoIPCache()
	geodata.ClearGeoSiteCache()

	peak := measurePeakAndRetained(t, "real reader's configuration in the tunnel", func() {
		if _, err := parseConfigForIOS(config, true); err != nil {
			// A parse that fails has not loaded the providers, so its cost is the cost
			// of failing -- reported loudly rather than recorded as a small number.
			t.Fatalf("the tunnel could not parse the staged configuration, so nothing "+
				"below was measured: %v", err)
		}
	})
	t.Logf("BUDGET: %.1f MiB of 50 MiB used, %.1f MiB left for everything geo could add",
		mib(peak), 50-mib(peak))
	if peak > packetTunnelBudgetBytes {
		t.Errorf("a real reader's configuration peaks at %.1f MiB against a 50 MiB tunnel: "+
			"this is a kill on a device", mib(peak))
	}
}

// The stack the reader described: a real configuration -- fifty-odd rule-providers, three
// subscriptions, fake-ip, a sniffer -- AND a DNS block stuffed with geo resources.
//
// Neither half is hypothetical. The rule-provider half came from a configuration someone
// actually runs; the geo half is what a reader adds when they want per-category DNS. The
// question this answers is the one the isolated measurements could not: does the sum fit.
func TestRealWorldConfigurationStackedWithHeavyGeoDNS(t *testing.T) {
	stageGeoMeasurement(t)
	base := stagedRealConfig(t)
	options := testOptions(t)
	codes, categories := enumerateShippedGeoNames(t, options.WorkingPath)

	// A real MERGE, not an append. The base configuration already has dns: and rules:,
	// and appending a second copy of either makes the later one win -- which silently
	// removed every RULE-SET reference, left all 53 providers unloaded, and produced a
	// 0.6 MiB reading that looked like a pass.
	var document map[string]any
	if err := yaml.Unmarshal([]byte(base), &document); err != nil {
		t.Fatal(err)
	}
	document["geodata-mode"] = true

	dns, _ := document["dns"].(map[string]any)
	if dns == nil {
		t.Fatal("the base configuration has no dns block, so there is nothing to stack onto")
	}
	policy, _ := dns["nameserver-policy"].(map[string]any)
	if policy == nil {
		policy = map[string]any{}
	}
	for index, category := range categories {
		if index >= 400 {
			break // already far past what anyone writes
		}
		policy["geosite:"+category] = []any{"223.5.5.5"}
	}
	dns["nameserver-policy"] = policy
	document["dns"] = dns

	rules, _ := document["rules"].([]any)
	if len(rules) == 0 {
		t.Fatal("the base configuration has no rules, so its providers would never load")
	}
	geoRules := make([]any, 0, len(codes)+len(rules))
	for _, code := range codes {
		geoRules = append(geoRules, "GEOIP,"+code+",DIRECT")
	}
	// Geo rules FIRST, the reader's own rules after, so every RULE-SET reference survives
	// and its provider still loads.
	document["rules"] = append(geoRules, rules...)

	merged, err := yaml.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	stacked := string(merged)
	if strings.Count(stacked, "RULE-SET") < 30 {
		t.Fatalf("the merge dropped the reader's RULE-SET rules (%d left): the providers "+
			"would not load and this would measure nothing",
			strings.Count(stacked, "RULE-SET"))
	}
	t.Logf("stacked: %d rules (%d geo + %d original), %d rule-providers, %d geosite policies",
		len(document["rules"].([]any)), len(codes), len(rules),
		len(document["rule-providers"].(map[string]any)), len(policy))

	for _, compiledArtifacts := range []bool{false, true} {
		geodata.ClearGeoIPCache()
		geodata.ClearGeoSiteCache()
		label := "stacked, NO artifacts (what ships today)"
		if compiledArtifacts {
			if _, err := PrepareGeoSiteCache(stacked); err != nil {
				t.Fatal(err)
			}
			if _, err := PrepareGeoIPCache(stacked, true); err != nil {
				t.Fatal(err)
			}
			geodata.ClearGeoIPCache()
			geodata.ClearGeoSiteCache()
			label = "stacked, artifacts compiled"
		}
		geodata.SetGeodataMode(true)
		geodata.SetLoader("memconservative")

		peak := measurePeakAndRetained(t, label, func() {
			if _, err := parseConfigForIOS(stacked, true); err != nil {
				t.Logf("parse failed (data, not a test error): %v", err)
			}
		})
		verdict := "FITS"
		if peak > packetTunnelBudgetBytes {
			verdict = "OOM"
		}
		t.Logf("VERDICT %s -> %.1f MiB of 50 MiB: %s", label, mib(peak), verdict)
	}
}

// Where is the actual ceiling? The extreme says the sum does not fit; a reader needs to
// know how many geo resources they can name before it stops fitting, on top of a
// configuration that already carries fifty rule-providers.
func TestRealWorldGeoHeadroomSweep(t *testing.T) {
	stageGeoMeasurement(t)
	base := stagedRealConfig(t)
	options := testOptions(t)
	codes, categories := enumerateShippedGeoNames(t, options.WorkingPath)

	for _, size := range []int{10, 25, 50, 100, 200} {
		var document map[string]any
		if err := yaml.Unmarshal([]byte(base), &document); err != nil {
			t.Fatal(err)
		}
		document["geodata-mode"] = true
		dns, _ := document["dns"].(map[string]any)
		policy, _ := dns["nameserver-policy"].(map[string]any)
		if policy == nil {
			policy = map[string]any{}
		}
		for index := 0; index < size && index < len(categories); index++ {
			policy["geosite:"+categories[index]] = []any{"223.5.5.5"}
		}
		dns["nameserver-policy"] = policy
		document["dns"] = dns
		rules, _ := document["rules"].([]any)
		geoRules := make([]any, 0, size+len(rules))
		for index := 0; index < size && index < len(codes); index++ {
			geoRules = append(geoRules, "GEOIP,"+codes[index]+",DIRECT")
		}
		document["rules"] = append(geoRules, rules...)
		merged, err := yaml.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		stacked := string(merged)

		geodata.ClearGeoIPCache()
		geodata.ClearGeoSiteCache()
		if _, err := PrepareGeoSiteCache(stacked); err != nil {
			t.Fatal(err)
		}
		if _, err := PrepareGeoIPCache(stacked, true); err != nil {
			t.Fatal(err)
		}
		geodata.ClearGeoIPCache()
		geodata.ClearGeoSiteCache()
		geodata.SetGeodataMode(true)
		geodata.SetLoader("memconservative")

		peak := measurePeakAndRetained(t, fmt.Sprintf("real config + %d countries + %d categories", size, size), func() {
			if _, err := parseConfigForIOS(stacked, true); err != nil {
				t.Logf("parse failed: %v", err)
			}
		})
		verdict := "FITS"
		if peak > packetTunnelBudgetBytes {
			verdict = "OOM"
		}
		t.Logf("SWEEP %3d+%3d -> %.1f MiB : %s", size, size, mib(peak), verdict)
	}
}

// Calibration: does what the App can SEE predict what the tunnel will PAY?
//
// A warning is only worth giving if it is right, and a coefficient invented to make a
// sentence sound confident is worse than no sentence. The App knows one thing exactly
// after its compile pass -- how many bytes of artifacts it wrote -- so this measures
// whether that quantity tracks the tunnel's peak, and reports the ratio rather than
// assuming one.
func TestGeoBudgetEstimatorCalibration(t *testing.T) {
	stageGeoMeasurement(t)
	base := stagedRealConfig(t)
	options := testOptions(t)
	codes, categories := enumerateShippedGeoNames(t, options.WorkingPath)

	artifactBytes := func(directory string) int64 {
		var total int64
		entries, err := os.ReadDir(directory)
		if err != nil {
			return 0
		}
		for _, entry := range entries {
			if info, err := entry.Info(); err == nil {
				total += info.Size()
			}
		}
		return total
	}

	t.Logf("%-12s %14s %12s %10s", "named", "artifact bytes", "peak MiB", "ratio")
	for _, size := range []int{200, 215, 230, 245, len(codes)} {
		var document map[string]any
		if err := yaml.Unmarshal([]byte(base), &document); err != nil {
			t.Fatal(err)
		}
		document["geodata-mode"] = true
		dns, _ := document["dns"].(map[string]any)
		policy, _ := dns["nameserver-policy"].(map[string]any)
		if policy == nil {
			policy = map[string]any{}
		}
		for index := 0; index < size && index < len(categories); index++ {
			policy["geosite:"+categories[index]] = []any{"223.5.5.5"}
		}
		dns["nameserver-policy"] = policy
		document["dns"] = dns
		rules, _ := document["rules"].([]any)
		geoRules := make([]any, 0, size+len(rules))
		for index := 0; index < size && index < len(codes); index++ {
			geoRules = append(geoRules, "GEOIP,"+codes[index]+",DIRECT")
		}
		document["rules"] = append(geoRules, rules...)
		merged, err := yaml.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		stacked := string(merged)

		geodata.ClearGeoIPCache()
		geodata.ClearGeoSiteCache()
		if _, err := PrepareGeoSiteCache(stacked); err != nil {
			t.Fatal(err)
		}
		if _, err := PrepareGeoIPCache(stacked, true); err != nil {
			t.Fatal(err)
		}
		written := artifactBytes(geodata.CompiledGeoIPDir()) + artifactBytes(geodata.CompiledGeoSiteDir())
		geodata.ClearGeoIPCache()
		geodata.ClearGeoSiteCache()
		geodata.SetGeodataMode(true)
		geodata.SetLoader("memconservative")

		peak := measurePeakAndRetained(t, fmt.Sprintf("calibrate %d", size), func() {
			if _, err := parseConfigForIOS(stacked, true); err != nil {
				t.Logf("parse failed: %v", err)
			}
		})
		ratio := 0.0
		if written > 0 {
			ratio = float64(peak) / float64(written)
		}
		t.Logf("CAL %-8d %14d %12.1f %10.2f", size, written, mib(peak), ratio)
	}
}

// Everything above was measured under the HOST's memory regime, and the tunnel does not
// run under it.
//
// setup.go:227 sets a Go soft memory limit of three quarters of the 50 MiB budget --
// 37.5 MiB -- and SetGCPercent(10), against the host default of no limit and GOGC=100.
// Those two settings are most of what decides a peak: a heap allowed to grow to twice its
// live set before collecting peaks at roughly twice its live set, and one held to 10% does
// not. Measuring geo cost without them measured a process nobody ships.
//
// So this repeats the stacked measurement under the tunnel's own settings, and the
// difference between the two is how wrong the earlier numbers were.
func TestStackedCostUnderTheTunnelsOwnMemoryRegime(t *testing.T) {
	stageGeoMeasurement(t)
	base := stagedRealConfig(t)
	options := testOptions(t)
	codes, categories := enumerateShippedGeoNames(t, options.WorkingPath)

	build := func(size int) string {
		var document map[string]any
		if err := yaml.Unmarshal([]byte(base), &document); err != nil {
			t.Fatal(err)
		}
		document["geodata-mode"] = true
		dns, _ := document["dns"].(map[string]any)
		policy, _ := dns["nameserver-policy"].(map[string]any)
		if policy == nil {
			policy = map[string]any{}
		}
		for index := 0; index < size && index < len(categories); index++ {
			policy["geosite:"+categories[index]] = []any{"223.5.5.5"}
		}
		dns["nameserver-policy"] = policy
		document["dns"] = dns
		rules, _ := document["rules"].([]any)
		geoRules := make([]any, 0, size+len(rules))
		for index := 0; index < size && index < len(codes); index++ {
			geoRules = append(geoRules, "GEOIP,"+codes[index]+",DIRECT")
		}
		document["rules"] = append(geoRules, rules...)
		merged, err := yaml.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		return string(merged)
	}

	for _, size := range []int{100, 200, len(codes)} {
		stacked := build(size)
		geodata.ClearGeoIPCache()
		geodata.ClearGeoSiteCache()
		if _, err := PrepareGeoSiteCache(stacked); err != nil {
			t.Fatal(err)
		}
		if _, err := PrepareGeoIPCache(stacked, true); err != nil {
			t.Fatal(err)
		}
		geodata.ClearGeoIPCache()
		geodata.ClearGeoSiteCache()
		geodata.SetGeodataMode(true)
		geodata.SetLoader("memconservative")

		// The tunnel's regime, restored afterwards so the rest of the package is not left
		// running under a 37.5 MiB ceiling.
		previousGC := debug.SetGCPercent(10)
		previousLimit := debug.SetMemoryLimit(50 << 20 * 3 / 4)

		peak := measurePeakAndRetained(t, fmt.Sprintf("tunnel regime, %d countries + %d categories", size, size), func() {
			if _, err := parseConfigForIOS(stacked, true); err != nil {
				t.Logf("parse failed: %v", err)
			}
		})

		debug.SetGCPercent(previousGC)
		debug.SetMemoryLimit(previousLimit)

		verdict := "FITS"
		if peak > packetTunnelBudgetBytes {
			verdict = "OOM"
		}
		t.Logf("REGIME %3d -> %.1f MiB of 50 MiB: %s", size, mib(peak), verdict)
	}
}
