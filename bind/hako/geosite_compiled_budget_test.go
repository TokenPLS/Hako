package hako

import (
	"bytes"
	"os"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/component/geodata"
	"github.com/TokenPLS/Hako/component/geodata/router"
	"github.com/TokenPLS/Hako/component/trie"
	C "github.com/TokenPLS/Hako/constant"
)

func sampledPeak(t *testing.T, work func()) (peak uint64, settledBefore uint64, settledAfter uint64, elapsed time.Duration) {
	t.Helper()
	settle := func() uint64 {
		runtime.GC()
		runtime.GC()
		var stats runtime.MemStats
		runtime.ReadMemStats(&stats)
		return stats.HeapAlloc
	}
	settledBefore = settle()
	var sampled atomic.Uint64
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
			if stats.HeapAlloc > sampled.Load() {
				sampled.Store(stats.HeapAlloc)
			}
			time.Sleep(200 * time.Microsecond)
		}
	}()
	start := time.Now()
	work()
	elapsed = time.Since(start)
	close(stop)
	<-done
	return sampled.Load(), settledBefore, settle(), elapsed
}

// The two ways to obtain the same matcher, measured against the one budget that
// decides whether a tunnel starts: 50 MiB.
//
// Decoding a geosite category materializes every domain as its own heap object
// before the succinct set is built, and the scaffolding is an order of magnitude
// larger than the result. The compiled form skips all of it — it IS the result,
// written out — which is why MRS rule sets load the way they do and geosite does
// not. A reader's configuration naming geosite:cn in a DNS nameserver-policy was
// killed at exactly this step.
func TestCompiledDomainSetVersusGeositeDecode(t *testing.T) {
	if os.Getenv("HAKO_MEASURE_GEOSITE") == "" {
		t.Skip("set HAKO_MEASURE_GEOSITE to compare compiled and decoded domain sets")
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

	mib := func(value uint64) float64 { return float64(value) / 1024 / 1024 }

	// The path the packet tunnel takes today.
	var decoded router.DomainMatcher
	peak, before, after, elapsed := sampledPeak(t, func() {
		matcher, err := geodata.LoadGeoSiteMatcher("cn")
		if err != nil {
			t.Fatal(err)
		}
		decoded = matcher
	})
	t.Logf("decode geosite:cn      %6v  peak=+%.1f MiB  retained=+%.1f MiB",
		elapsed.Round(time.Millisecond), mib(peak)-mib(before), mib(after)-mib(before))
	runtime.KeepAlive(decoded)

	// Compile it once, the way MRS stores a domain set.
	loader, err := geodata.GetGeoDataLoader("memconservative")
	if err != nil {
		t.Fatal(err)
	}
	domains, err := loader.LoadGeoSite("cn")
	if err != nil {
		t.Fatal(err)
	}
	tree := trie.New[struct{}]()
	kept := 0
	for _, domain := range domains {
		if domain.Type != router.Domain_Domain && domain.Type != router.Domain_Full {
			continue
		}
		prefix := "+."
		if domain.Type == router.Domain_Full {
			prefix = ""
		}
		if err := tree.Insert(prefix+domain.Value, struct{}{}); err == nil {
			kept++
		}
	}
	var compiled bytes.Buffer
	if err := tree.NewDomainSet().WriteBin(&compiled); err != nil {
		t.Fatal(err)
	}
	domains = nil
	tree = nil
	blob := compiled.Bytes()

	// The path a compiled artifact would take.
	var restored *trie.DomainSet
	peak, before, after, elapsed = sampledPeak(t, func() {
		set, err := trie.ReadDomainSetBin(bytes.NewReader(blob))
		if err != nil {
			t.Fatal(err)
		}
		restored = set
	})
	t.Logf("read compiled set     %6v  peak=+%.1f MiB  retained=+%.1f MiB  (%d domains, %.1f MiB on disk)",
		elapsed.Round(time.Millisecond), mib(peak)-mib(before), mib(after)-mib(before),
		kept, float64(len(blob))/1024/1024)

	if restored == nil || !restored.Has("www.qq.com") {
		t.Fatal("the compiled set does not answer for a domain the category contains")
	}
}
