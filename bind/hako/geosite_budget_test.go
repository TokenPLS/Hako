package hako

import (
	"os"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/component/geodata"
	C "github.com/TokenPLS/Hako/constant"
)

// What a single geosite category costs, in the two numbers a 50 MiB packet
// tunnel actually lives or dies by: the peak while it is being built, and what
// stays behind afterwards. Reported, never asserted — the device is the judge
// of the ceiling, and a host threshold here would be a number invented to be
// met. A reader's configuration whose DNS nameserver-policy names geosite:cn
// was killed at exactly this step, and until this ran the split between "the
// build is expensive" and "we keep the scaffolding" was a guess.
func TestGeositeCategoryMemoryBudget(t *testing.T) {
	if os.Getenv("HAKO_MEASURE_GEOSITE") == "" {
		t.Skip("set HAKO_MEASURE_GEOSITE to measure geosite load cost")
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
	geodata.SetSiteMatcher("succinct")

	for _, category := range []string{"cn", "geolocation-!cn", "private", "apple"} {
		t.Run(category, func(t *testing.T) {
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
					time.Sleep(200 * time.Microsecond)
				}
			}()

			start := time.Now()
			matcher, err := geodata.LoadGeoSiteMatcher(category)
			elapsed := time.Since(start)
			close(stop)
			<-done
			if err != nil {
				t.Skipf("category unavailable: %v", err)
			}
			runtime.KeepAlive(matcher)
			after := settled()

			mib := func(value uint64) float64 { return float64(value) / 1024 / 1024 }
			t.Logf("%s: %v  peak=%.1f MiB (+%.1f above baseline)  retained=%.1f MiB (+%.1f)",
				category, elapsed.Round(time.Millisecond),
				mib(peak.Load()), mib(peak.Load())-mib(before),
				mib(after), mib(after)-mib(before))
		})
	}
}
