package hako

import (
	"runtime"
	"runtime/debug"
	runtimemetrics "runtime/metrics"
	"sync/atomic"

	"github.com/TokenPLS/Hako/log"
)

type runtimeMemorySnapshot struct {
	availableBytes          int64
	physicalBytes           int64
	goResidentBytes         uint64
	nonGoPhysicalEstimate   int64
	heapAllocBytes          uint64
	heapInuseBytes          uint64
	stackInuseBytes         uint64
	gcCount                 uint32
	gcPauseTotalNanoseconds uint64
}

var memoryPressureEventCount atomic.Uint64

// armMemoryPressureMonitorForRuntime keeps the Darwin pressure signal independent from
// the optional Go memory budget. macOS Network Extensions intentionally run without the
// iOS jetsam-derived MemoryLimit, and sing-box agrees: resolvePolicyMode reaches for its
// 50 MiB Network Extension regime only under C.IsIos, so a macOS provider -- in either
// packaging shape -- lands on available-system-memory thresholds instead.
//
// Arming it is still worth it there: the response is to release pages and record
// evidence, which is useful on any machine. Containing-App preflight never owns live Core
// connections and must not arm a process-lifetime dispatch source.
func armMemoryPressureMonitorForRuntime(profile runtimeProfile, appOnly bool, arm func()) {
	if appOnly || profile == runtimeProfileMacOSApplication {
		return
	}
	arm()
}

// currentRuntimeMemorySnapshot separates Apple's jetsam-relevant physical
// footprint from Go-managed resident memory. Go's recommended resident proxy
// is /memory/classes/total:bytes - /memory/classes/heap/released:bytes; unlike
// MemStats.Sys it excludes pages returned to the OS. The remainder is only an
// estimate of non-Go physical memory because allocator/accounting boundaries
// are not perfectly synchronous.
func currentRuntimeMemorySnapshot() runtimeMemorySnapshot {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	samples := []runtimemetrics.Sample{
		{Name: "/memory/classes/total:bytes"},
		{Name: "/memory/classes/heap/released:bytes"},
	}
	runtimemetrics.Read(samples)
	var total, released uint64
	if samples[0].Value.Kind() == runtimemetrics.KindUint64 {
		total = samples[0].Value.Uint64()
	}
	if samples[1].Value.Kind() == runtimemetrics.KindUint64 {
		released = samples[1].Value.Uint64()
	}
	resident := total
	if released <= total {
		resident = total - released
	}
	physical := MemoryFootprint()
	nonGo := int64(-1)
	if physical >= 0 {
		nonGo = physical
		if resident <= uint64(physical) {
			nonGo = physical - int64(resident)
		} else {
			nonGo = 0
		}
	}
	return runtimeMemorySnapshot{
		availableBytes:          availableMemory(),
		physicalBytes:           physical,
		goResidentBytes:         resident,
		nonGoPhysicalEstimate:   nonGo,
		heapAllocBytes:          stats.HeapAlloc,
		heapInuseBytes:          stats.HeapInuse,
		stackInuseBytes:         stats.StackInuse,
		gcCount:                 stats.NumGC,
		gcPauseTotalNanoseconds: stats.PauseTotalNs,
	}
}

// handleMemoryPressure is the response to a critical memory-pressure event: count it,
// record evidence, release pages. It does NOT close connections, and that is the whole
// point of this function's shape.
//
// A critical pressure event says the DEVICE is short of memory; it says nothing about who
// is holding it. Answering one by closing every tracked connection killed every app's live
// session through the tunnel, and at a typical Extension footprint of ~18 MiB against
// ~50 MiB it freed almost nothing. Each app-side recovery then pays a fresh TCP connect and
// a full TLS handshake, and on Apple platforms every handshake is an XPC round trip to
// trustd -- so the teardown multiplied a separate defect.
//
// The teardown was first narrowed to fire only near the configured budget, then removed
// entirely. That removal was right, but the reason recorded for it was not, and the
// correction matters because it points at work still to do.
//
// What sing-box actually does splits in two. Its XNU pressure callback -- the direct
// counterpart of this function -- logs, writes a throttled OOM draft, and notifies a timer
// (service/oomkiller/service_darwin.go). It does NOT close connections there, which is the
// part that justifies this function not doing it either: a device-wide notification says
// nothing about who is holding the memory.
//
// But sing-box does shed, from a different trigger. Its adaptive timer polls memory on its
// own schedule, runs a three-state hysteresis machine, and when it crosses into the
// triggered state it calls NetworkManager.ResetNetwork -- whose first statement is
// connectionManager.CloseAll (route/network.go). So the upstream design is not "never shed";
// it is "never shed in response to the OS notification, and shed only when your own measured
// threshold says memory is genuinely critical".
//
// An earlier version of this comment said sing-box never closes connections in any policy
// mode. That was read from the callback path alone and is wrong.
//
// We have the first half and not the second: no threshold machine exists here yet, so
// nothing sheds at all. That gap in MACOS-UPSTREAM-PARITY-TODO.md.
//
// The evidence-write throttle stays at one hour, which is also what sing-box uses
// (oomDraftMinInterval).
//
// Not matched, and recorded rather than quietly skipped: sing-box drives its response
// through a three-state hysteresis machine (normal/armed/triggered, separate resume
// threshold) on an adaptive interval that backs off. We act on each notification. That is a
// mechanism we lack, not a constraint we impose, so it is a port rather than a correction.
func handleMemoryPressure() {
	handleMemoryPressureWith(MemoryFootprint(), runtimeSetupSnapshot().softMemoryLimit)
}

// handleMemoryPressureWith is handleMemoryPressure with its two diagnostic inputs supplied,
// so the response can be exercised on any platform. Both values are logged only; neither
// selects behaviour any more, which is exactly the property the tests pin.
func handleMemoryPressureWith(footprint, softLimit int64) {
	memoryPressureEventCount.Add(1)
	// The record exists to explain a kill, and pressure is the kill's antechamber -- yet
	// stages write only at their boundaries, so the record was sleeping through the very
	// spend it exists to explain. One rewrite with the pressure-moment footprint; a no-op
	// when startup has completed and the record is already gone.
	refreshStartupBreadcrumbFootprint()
	if err := RecordMemoryPressureEvidence(); err != nil {
		log.Warnln("[Memory] persist pressure evidence: %v", err)
	}
	log.Warnln(
		"[Memory] critical pressure: releasing memory (footprint=%d softLimit=%d); "+
			"the notification never closes connections — the threshold machine decides that",
		footprint, softLimit)

	// Upstream's notifyPressure: wake the threshold machine into fast polling with a fresh
	// growth baseline, then let it decide. The notification is a hint about the machine, not
	// evidence about us.
	notifyPressureThreshold()

	debug.FreeOSMemory()
}
