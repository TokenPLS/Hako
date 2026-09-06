package hako

import (
	"sync"
	"sync/atomic"
	"time"
)

// The high-water footprint across one provider's build.
//
// The pair of probes around Initial samples the boundaries, which prices what a rule set
// leaves behind. That is not what ends the process. A text rule set holds the raw file, a
// pointer trie, a full copy of its domains and the succinct set being written from them
// all at once, and three of the four are gone by the time the closing probe fires:
// measured on a device, a 616 KB table left 3.9 MiB behind after touching 23.7 MiB, a
// ratio the boundaries cannot show. A bill built from the residue ranks the reader's rule
// sets in the wrong order, and the entry they have to switch off is not the one at the top.
//
// So the window between the probes is sampled and the maximum travels on the closing
// line. What this costs was measured before it was written, because the process being
// measured is the one with fifty megabytes to live in: one sample is 689ns and, more to
// the point, **zero allocations** -- the sampler cannot become part of what it measures.
// A three-second build at this interval spends 2.1ms of CPU, against the 212us a single
// breadcrumb write already costs.
//
// Deliberately NOT runtime.ReadMemStats: 26.6us and it stops the world, which would pause
// the goroutine building the trie -- an instrument that changes what it measures.
// Deliberately not runtime/metrics either, though it is cheaper at 258ns: it reports the
// Go heap, and the quantity that ends this process is phys_footprint.

const providerPeakSampleInterval = time.Millisecond

// footprintForSampling is the quantity jetsam measures. A variable so a test can drive
// the sampler along a known curve; production reads the task's phys_footprint.
var footprintForSampling = MemoryFootprint

type providerPeakSampler struct {
	name string
	peak atomic.Int64
	stop chan struct{}
	done chan struct{}
}

var (
	providerPeakMu     sync.Mutex
	providerPeakActive *providerPeakSampler
)

// startProviderPeakSampling opens the window for one provider. A sampler already running
// -- a provider whose closing probe never arrived because it was still building when the
// last one was abandoned -- is stopped first, so only one goroutine is ever asking.
func startProviderPeakSampling(name string) {
	providerPeakMu.Lock()
	defer providerPeakMu.Unlock()
	stopActiveProviderPeakLocked()

	sampler := &providerPeakSampler{
		name: name,
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
	// Seeded with the footprint at the boundary so the peak can never come back lower
	// than the line the reader can see next to it.
	sampler.peak.Store(footprintForSampling())
	providerPeakActive = sampler

	go func() {
		defer close(sampler.done)
		ticker := time.NewTicker(providerPeakSampleInterval)
		defer ticker.Stop()
		for {
			select {
			case <-sampler.stop:
				return
			case <-ticker.C:
				if current := footprintForSampling(); current > sampler.peak.Load() {
					sampler.peak.Store(current)
				}
			}
		}
	}()
}

// stopProviderPeakSampling closes the window and reports the high-water mark, or 0 when
// this provider was never opened -- an older core's probe stream, or a step that is not
// about a provider at all. Zero means "not measured" and is omitted by the caller rather
// than printed as a measurement of nothing.
func stopProviderPeakSampling(name string) int64 {
	providerPeakMu.Lock()
	sampler := providerPeakActive
	if sampler == nil || sampler.name != name {
		providerPeakMu.Unlock()
		return 0
	}
	providerPeakActive = nil
	providerPeakMu.Unlock()

	close(sampler.stop)
	<-sampler.done
	// The closing boundary counts too: the build may still have been at its top when the
	// probe fired, between two ticks.
	peak := sampler.peak.Load()
	if final := footprintForSampling(); final > peak {
		peak = final
	}
	return peak
}

// stopAnyProviderPeakSampling is the disarm path: a provider that never returned leaves a
// goroutine asking the kernel for a footprint on a process that has moved on.
func stopAnyProviderPeakSampling() {
	providerPeakMu.Lock()
	defer providerPeakMu.Unlock()
	stopActiveProviderPeakLocked()
}

func stopActiveProviderPeakLocked() {
	if providerPeakActive == nil {
		return
	}
	sampler := providerPeakActive
	providerPeakActive = nil
	close(sampler.stop)
	<-sampler.done
}
