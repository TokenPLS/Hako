package hako

import (
	"bytes"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/component/geodata"
	compiledlib "github.com/TokenPLS/Hako/component/geodata/compiled"
	"github.com/TokenPLS/Hako/component/geodata/router"
	P "github.com/TokenPLS/Hako/constant/provider"
	"github.com/TokenPLS/Hako/rules/provider"
)

// The same question as the geosite measurement, asked of the other way a reader
// brings rules in: a rule-provider. A text or yaml list is source material and
// pays the same scaffolding; a compiled one is the result. Both numbers matter
// because a subscription decides which one the tunnel gets, and the reader has
// no say in it.
func TestRuleProviderSourceVersusCompiledBudget(t *testing.T) {
	if os.Getenv("HAKO_MEASURE_GEOSITE") == "" {
		t.Skip("set HAKO_MEASURE_GEOSITE to measure rule-provider load cost")
	}
	options := testOptions(t)
	if err := os.MkdirAll(options.WorkingPath, 0o755); err != nil {
		t.Fatal(err)
	}
	stageBundledGeodata(t, options.WorkingPath)
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	geodata.SetGeodataMode(true)
	geodata.SetLoader("memconservative")

	// A realistic list rather than a generated one: the domains a reader's
	// China rule set actually holds.
	loader, err := geodata.GetGeoDataLoader("memconservative")
	if err != nil {
		t.Fatal(err)
	}
	domains, err := loader.LoadGeoSite("cn")
	if err != nil {
		t.Skipf("bundled geosite unavailable: %v", err)
	}
	var text strings.Builder
	lines := 0
	for _, domain := range domains {
		if domain.Type != router.Domain_Domain && domain.Type != router.Domain_Full {
			continue
		}
		fmt.Fprintf(&text, "%s\n", domain.Value)
		lines++
	}
	domains = nil
	source := []byte(text.String())
	text.Reset()
	runtime.GC()

	mib := func(value uint64) float64 { return float64(value) / 1024 / 1024 }

	var asMrs bytes.Buffer
	peak, before, _, elapsed := sampledPeak(t, func() {
		if err := provider.ConvertToMrs(source, P.Domain, P.TextRule, &asMrs); err != nil {
			t.Fatal(err)
		}
	})
	t.Logf("compile text->mrs  %6v  peak=+%.1f MiB   (%d lines, %.1f MiB text -> %.1f MiB compiled)",
		elapsed.Round(time.Millisecond), mib(peak)-mib(before), lines,
		float64(len(source))/1024/1024, float64(asMrs.Len())/1024/1024)

	// The read path, not a re-export: ConvertToMrs with an MRS input dumps every
	// key back to text, which materializes exactly the scaffolding this artifact
	// exists to avoid, and measuring that would have flattered nothing.
	compiledBytes := asMrs.Bytes()
	var restoredCount int
	peak, before, after, elapsed := sampledPeak(t, func() {
		_, count, _, err := compiledlib.Read(bytes.NewReader(compiledBytes))
		if err != nil {
			t.Fatal(err)
		}
		restoredCount = count
	})
	if restoredCount != lines {
		t.Fatalf("compiled artifact holds %d rules, want %d", restoredCount, lines)
	}
	t.Logf("read compiled mrs  %6v  peak=+%.1f MiB  retained=+%.1f MiB",
		elapsed.Round(time.Millisecond), mib(peak)-mib(before), mib(after)-mib(before))
}
