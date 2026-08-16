//go:build darwin && cgo

package hako

/*
#include <dispatch/dispatch.h>
#include <limits.h>
#include <mach/mach.h>
#include <dlfcn.h>
#include <TargetConditionals.h>
#if TARGET_OS_IPHONE
#include <os/proc.h>
#endif

// hako_phys_footprint returns this task's phys_footprint — the exact number
// iOS jetsam uses to decide killing the NE. -1 on failure.
static long long hako_phys_footprint() {
	task_vm_info_data_t info;
	mach_msg_type_number_t count = TASK_VM_INFO_COUNT;
	kern_return_t kr = task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&info, &count);
	if (kr != KERN_SUCCESS) return -1;
	return (long long)info.phys_footprint;
}

// os_proc_available_memory is iOS-only. It is a point-in-time advisory
// snapshot and must be queried for every low-frequency diagnostic sample.
// Keep the macOS gomobile slice linkable by returning -1 there.
// os_proc_available_memory is declared in the SDK headers under TARGET_OS_IPHONE, but the
// SYMBOL exists in libSystem on macOS too. Gating on the compile-time macro therefore returned
// -1 on every macOS build, which made resolveThresholdMode pick "none" and left the whole
// memory threshold machine inert on the platform it was ported for.
//
// Upstream resolves it at runtime instead (sing's common/memory/memory_darwin.go uses
// dlsym(RTLD_DEFAULT, "os_proc_available_memory") and reports separately whether it resolved),
// which is both the portable answer and the reason macOS works there. Copied.
//
// The quantity is this PROCESS's remaining headroom, not the machine's free memory. That
// matters for reading the thresholds: upstream's available-mode margins are scaled off our own
// footprint precisely because both sides of the comparison are per-process.
typedef size_t (*hako_proc_available_memory_func)(void);
static int hako_available_memory_resolved = 0;
static hako_proc_available_memory_func hako_available_memory_fn = NULL;

static void hako_resolve_available_memory() {
	if (!hako_available_memory_resolved) {
		hako_available_memory_fn =
			(hako_proc_available_memory_func)dlsym(RTLD_DEFAULT, "os_proc_available_memory");
		hako_available_memory_resolved = 1;
	}
}

static long long hako_available_memory() {
	hako_resolve_available_memory();
	if (!hako_available_memory_fn) {
		return -1;
	}
	size_t available = hako_available_memory_fn();
	if (available > LLONG_MAX) return LLONG_MAX;
	return (long long)available;
}

extern void hakoMemoryPressureCallback(unsigned long status);

static dispatch_source_t hakoMemoryPressureSource;

static void hakoStartMemoryPressureMonitor() {
	if (hakoMemoryPressureSource) {
		return;
	}
	hakoMemoryPressureSource = dispatch_source_create(
		DISPATCH_SOURCE_TYPE_MEMORYPRESSURE,
		0,
		DISPATCH_MEMORYPRESSURE_CRITICAL,
		dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0)
	);
	dispatch_source_set_event_handler(hakoMemoryPressureSource, ^{
		unsigned long status = dispatch_source_get_data(hakoMemoryPressureSource);
		hakoMemoryPressureCallback(status);
	});
	dispatch_activate(hakoMemoryPressureSource);
}
*/
import "C"

import "sync"

var memoryPressureOnce sync.Once

// startMemoryPressureMonitor arms a GCD DISPATCH_SOURCE_TYPE_MEMORYPRESSURE
// source at the CRITICAL level. Inside the NE there are no UIKit memory
// warnings, so this dispatch source is the only reliable pre-jetsam signal
// . Idempotent.
func startMemoryPressureMonitor() {
	memoryPressureOnce.Do(func() {
		C.hakoStartMemoryPressureMonitor()
	})
}

//export hakoMemoryPressureCallback
func hakoMemoryPressureCallback(_ C.ulong) {
	handleMemoryPressure()
}

// physFootprint returns the task's phys_footprint in bytes (-1 on failure).
func physFootprint() int64 {
	return int64(C.hako_phys_footprint())
}

// availableMemory returns Apple's current dirty-memory headroom in bytes.
// The result is deliberately never cached. It is -1 outside iOS and may be 0
// when the OS cannot provide a usable app-process limit.
// availableMemory returns this process's remaining memory headroom in bytes, or a
// non-positive value when there is none to report.
//
// ZERO IS NOT "no memory left". os_proc_available_memory() returns 0 for a process that has no
// memory limit, which is every ordinary macOS process -- the symbol resolves there, it just has
// nothing to say. Treating that 0 as a reading would make the threshold machine compare 0 against
// a 32 MiB trigger and fire permanently, and with shedding enabled it would close every
// connection on a loop. Callers must therefore test for > 0, not >= 0.
func availableMemory() int64 {
	return int64(C.hako_available_memory())
}
