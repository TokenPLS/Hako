//go:build darwin && cgo

package hako

/*
#include <sys/resource.h>

// hako_process_cpu_time_ns returns cumulative user + system CPU time for this
// process. RUSAGE_SELF covers every thread in the Network Extension process,
// including Go, cgo and Swift work. It intentionally excludes child processes.
static long long hako_process_cpu_time_ns() {
	struct rusage usage;
	if (getrusage(RUSAGE_SELF, &usage) != 0) {
		return -1;
	}
	return ((long long)usage.ru_utime.tv_sec + (long long)usage.ru_stime.tv_sec) * 1000000000LL
		+ ((long long)usage.ru_utime.tv_usec + (long long)usage.ru_stime.tv_usec) * 1000LL;
}
*/
import "C"

// processCPUTimeNanoseconds returns cumulative whole-process CPU time. The
// value is monotonic for one process and may grow faster than wall time when
// multiple cores execute concurrently. -1 means the platform call failed.
func processCPUTimeNanoseconds() int64 {
	return int64(C.hako_process_cpu_time_ns())
}
