package hako

import (
	"runtime/debug"

	"github.com/TokenPLS/Hako/adapter"

	"github.com/TokenPLS/Hako/log"
)

// neJetsamBudgetBytes is the ~50 MiB budget iOS jetsam enforces on a
// Network Extension. Two different knobs derive from it and they must not
// be conflated, because they measure different memories:
//
//   - the GC pacing limit (GOMEMLIMIT) is 3/4 of the budget — it bounds
//     Go-managed memory, and the quarter left over is for cgo and ObjC
//     allocations the Go runtime cannot see;
//   - the threshold machine's limit is the FULL budget — its samples are
//     the process footprint, the number jetsam actually counts, and its
//     margins (trigger one 5 MiB margin below the limit) are calibrated
//     upstream against the real budget. Feeding it the 3/4 pacing value
//     moves the trigger to 32.5 MiB, below this workload's measured 42 MiB
//     resident steady state — a machine that is born triggered sheds every
//     activation once and can never resume.
const neJetsamBudgetBytes = 50 * 1024 * 1024

const nePacingSoftLimitBytes = neJetsamBudgetBytes * 3 / 4

// machineBudgetForPacing inverts the 3/4 derivation: a caller who hands us a
// GC pacing value (ReloadSetupOptions.SoftMemoryLimit) is describing a
// budget whose pacing that is, and the threshold machine must be armed with
// the budget, never the pacing value -- the pacing value's trigger sits
// below a heavy workload's resident steady state.
func machineBudgetForPacing(pacing int64) int64 {
	return pacing * 4 / 3
}

// pacingBudgetedPlatform is the build-tag verdict, injectable for tests
// (host tests build without the "ios" tag).
var pacingBudgetedPlatform = buildIsNEBudgetedPlatform

// nePacingSoftLimit decides whether NewService should arm a default
// GOMEMLIMIT, and returns 0 when it should not.
//
// History, because this looks like a re-litigation and is not: the memory
// budget that used to arrive through SetupOptions.MemoryLimit was removed on
// the client side because its ceiling refused readers their configurations.
// That removal also silently took two things that refuse nothing and only
// tune collection: SetGCPercent(10), which the client noticed and restored
// through ReloadSetupOptions, and SetMemoryLimit, which nothing restored.
// Three rounds of on-device evidence showed the cost of the second loss: a
// resident footprint idling one safety margin under the budget, and a
// sub-second allocation burst outrunning collection into a jetsam kill. A
// GOMEMLIMIT is pure garbage-collector pacing — it rejects no configuration
// and closes nothing — so restoring it restores the lost half of that
// ruling's intent, not the ceiling it removed.
//
// The gate is the platform's, not a guess about the user: only the iOS
// family (iPhone, iPad, Apple TV) runs Network Extensions under the ~50 MiB
// jetsam wall — macOS providers deliberately keep Go runtime defaults — and
// an explicit limit, Setup's or a later ReloadSetupOptions', always wins.
// The family is identified by the build tag, not GOOS: the tvOS slices
// build with GOOS=darwin.
func nePacingSoftLimit(budgetedPlatform, underNetworkExtension bool, existing int64) int64 {
	if existing > 0 || !underNetworkExtension || !budgetedPlatform {
		return 0
	}
	return nePacingSoftLimitBytes
}

// armNEPacingForService runs in NewService, after the platform log redirect,
// so its lines land where a device log reader can find them. (The Setup-time
// monitor arming logs before any redirect exists; three rounds of device
// logs held trigger lines but never an armed line, because the armed line
// had been written into the void.)
func armNEPacingForService(platform PlatformInterface) {
	setupMu.Lock()
	existing := currentRuntimeSetup.softMemoryLimit
	if currentRuntimeSetup.softMemoryLimitIsPacingDefault {
		// A value this function derived earlier is not an explicit limit;
		// re-derive rather than mistake our own default for configuration.
		existing = 0
	}
	limit := nePacingSoftLimit(pacingBudgetedPlatform, platform.UnderNetworkExtension(), existing)
	if limit > 0 {
		debug.SetMemoryLimit(limit)
		currentRuntimeSetup.softMemoryLimit = limit
		currentRuntimeSetup.softMemoryLimitIsPacingDefault = true
	}
	// Re-arm the threshold monitor either way: replacing the machine is what a
	// re-Setup wants, and this re-arm is the one whose armed line is visible.
	// When the NE default armed, the machine gets the full jetsam budget, not
	// the pacing value — see neJetsamBudgetBytes for why the two differ. The
	// snapshot, the pacing write and the re-arm stay under setupMu as one
	// transaction (setupMu before pressureThresholdMu is the established
	// order, Setup does the same), so a concurrent Setup or Reload cannot
	// interleave and leave the machine armed from a stale generation.
	machineLimit := int64(0)
	if soft := currentRuntimeSetup.softMemoryLimit; soft > 0 {
		// Whatever wrote the soft limit — Setup, Reload, or the pacing
		// default above — it is a pacing value, and the machine always gets
		// the budget that pacing describes.
		machineLimit = machineBudgetForPacing(soft)
	}
	if limit > 0 {
		log.Infoln("[Memory] GC pacing armed: GOMEMLIMIT=%d (NE budget default; no explicit limit was configured)", limit)
	}
	startPressureThresholdMonitor(machineLimit, pressureThresholdShedEnabled.Load())
	setupMu.Unlock()

	// The probe admission pacer guards the same jetsam wall and arms
	// under the same platform verdict, but independently of any explicit soft
	// limit: an operator raising GOMEMLIMIT does not move the wall.
	if probeAdmissionShouldArm(pacingBudgetedPlatform, platform.UnderNetworkExtension()) {
		armProbeAdmission()
		log.Infoln("[Memory] probe admission pacing armed: ceiling=%d step=%d", probeAdmissionCeilingBytes, probeAdmissionStepBytes)
	} else {
		// Symmetric teardown: a Service armed outside the NE must not keep a
		// stale gate on the shared adapter choke point.
		adapter.SetURLTestAdmission(nil)
	}
}
