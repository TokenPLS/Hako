package hako

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/hub/executor"
)

// What a rule set costs is its peak, not what it leaves behind.
//
// A text rule set holds four representations of the same table at once while it is being
// built -- the raw file, a pointer trie, a full copy of its domains, and the succinct set
// being written from them -- and only the last survives. The two probes around Initial
// sample the footprint at the boundaries, so they price the residue: measured on device,
// a 616 KB table left 3.9 MiB behind and touched 23.7 MiB on the way. Ranking rule sets
// by the residue puts the reader's list in the wrong order, and the entry that has to go
// is not the one at the top of it.
//
// So the window between the two probes gets sampled, and the high-water mark travels on
// the closing line. The cost of asking is measured: 689ns per sample and, more to the
// point in a process this size, zero allocations -- the sampler cannot itself become part
// of what it measures.

// fakeFootprintCurve drives the sampler with a known shape and reports how many times it
// was asked, so a test that samples nothing fails loudly instead of quietly passing.
type fakeFootprintCurve struct {
	values []int64
	calls  atomic.Int64
	served chan struct{}
	once   atomic.Bool
}

func (c *fakeFootprintCurve) next() int64 {
	n := c.calls.Add(1)
	if int(n) >= len(c.values) && c.once.CompareAndSwap(false, true) {
		close(c.served)
	}
	index := int(n) - 1
	if index >= len(c.values) {
		index = len(c.values) - 1
	}
	return c.values[index]
}

func installFootprintCurve(t *testing.T, values ...int64) *fakeFootprintCurve {
	t.Helper()
	curve := &fakeFootprintCurve{values: values, served: make(chan struct{})}
	previous := footprintForSampling
	footprintForSampling = curve.next
	t.Cleanup(func() { footprintForSampling = previous })
	return curve
}

func phaseTraceTail(from int) []string {
	phaseMu.Lock()
	defer phaseMu.Unlock()
	if from > len(phaseTrace) {
		return nil
	}
	return append([]string(nil), phaseTrace[from:]...)
}

func phaseTraceLength() int {
	phaseMu.Lock()
	defer phaseMu.Unlock()
	return len(phaseTrace)
}

func TestTheProvidersPeakTravelsOnItsClosingLine(t *testing.T) {
	breadcrumbHome(t)
	setStartupBreadcrumbRecording(true)
	t.Cleanup(func() { setStartupBreadcrumbRecording(false) })
	// A build that climbs to 48 MiB and falls back to 26: the shape a text rule set makes
	// when the trie and the string copy are both alive and then are not.
	curve := installFootprintCurve(t,
		20<<20, 31<<20, 44<<20, 48<<20, 33<<20, 26<<20)
	t.Cleanup(armStartupProbes())

	start := phaseTraceLength()
	executor.StartupProbe("rule-provider-begin:reject")

	// Wait for the curve to be walked rather than sleeping a guessed interval: if the
	// sampler never runs, this deadline fails the test instead of letting a zero peak
	// look like a measurement.
	select {
	case <-curve.served:
	case <-time.After(3 * time.Second):
		t.Fatalf("the sampler asked for the footprint %d time(s) in three seconds; it is not sampling", curve.calls.Load())
	}
	executor.StartupProbe("rule-provider:reject")

	var closing string
	for _, line := range phaseTraceTail(start) {
		if strings.Contains(line, "apply:rule-provider:reject") {
			closing = line
		}
	}
	if closing == "" {
		t.Fatal("no closing line for the provider")
	}
	if !strings.Contains(closing, "peak=48.0MiB") {
		t.Fatalf("the closing line does not carry the build's high-water mark: %q", closing)
	}
}

// The opening line must not carry a peak: nothing has been built yet, and a number there
// would be read as this provider's cost.
func TestTheOpeningLineCarriesNoPeak(t *testing.T) {
	breadcrumbHome(t)
	installFootprintCurve(t, 20<<20, 21<<20)
	t.Cleanup(armStartupProbes())

	start := phaseTraceLength()
	executor.StartupProbe("rule-provider-begin:reject")

	for _, line := range phaseTraceTail(start) {
		if strings.Contains(line, "rule-provider-begin:reject") && strings.Contains(line, "peak=") {
			t.Fatalf("the opening line claims a peak before anything was built: %q", line)
		}
	}
}

// A provider that never returns leaves no sampler running: the process that survives it
// must not keep a goroutine asking the kernel for a footprint forever.
func TestDisarmingStopsASamplerThatNeverGotItsClosingProbe(t *testing.T) {
	breadcrumbHome(t)
	curve := installFootprintCurve(t, 20<<20, 21<<20, 22<<20)

	disarm := armStartupProbes()
	executor.StartupProbe("rule-provider-begin:direct")
	select {
	case <-curve.served:
	case <-time.After(3 * time.Second):
		t.Fatal("sampler never ran")
	}
	disarm()

	settled := curve.calls.Load()
	time.Sleep(50 * time.Millisecond)
	if grew := curve.calls.Load() - settled; grew > 1 {
		t.Fatalf("the sampler kept running after disarm: %d more samples", grew)
	}
}
