package hako

import (
	"errors"
	"fmt"
	"runtime/debug"
)

const (
	minReloadSoftMemoryLimit = int64(16 << 20)
	maxReloadSoftMemoryLimit = int64(256 << 20)
	minReloadGCPercent       = 10
	maxReloadGCPercent       = 200
	minReloadLogMaxLines     = 100
	maxReloadLogMaxLines     = 5000
)

// RuntimeSetupOptions contains only process policy that may be requested at
// runtime. Zero means "leave unchanged" for the three mutable fields.
//
// The restart-only fields are deliberately present at the mobile boundary so
// callers get an explicit requires-restart error instead of a silent no-op.
// Hako never rewires paths, the App Group Unix socket, timezone, GOMAXPROCS,
// link MTU or core identity underneath a live Network Extension.
type RuntimeSetupOptions struct {
	SoftMemoryLimit int64
	GCPercent       int
	LogMaxLines     int

	BasePath           string
	WorkingPath        string
	TempPath           string
	TimeZone           string
	MaxProcs           int
	TunMTU             int
	ClashAPISocketPath string
	CoreIdentity       string
}

type runtimeSetupState struct {
	softMemoryLimit int64
	// softMemoryLimitIsPacingDefault marks a softMemoryLimit that was derived
	// by the service-time NE pacing default rather than configured. The
	// distinction keeps a hypothetical second NewService without an
	// intervening Setup from treating the derived value as an explicit one
	// and feeding it to the threshold machine as its limit -- the unit error
	// this batch fixed. Today the Swift call order (Setup, then NewService)
	// makes that unreachable; this keeps the guard on our side of the bridge.
	softMemoryLimitIsPacingDefault bool
	gcPercent                      int
	logMaxLines                    int
}

var currentRuntimeSetup = runtimeSetupState{
	logMaxLines: defaultLogMaxLines,
}

// ReloadSetupOptions applies the safe live subset of SetupOptions. Validation
// is completed before any runtime global is changed, so every error preserves
// the previous memory, GC and diagnostic-retention policy.
func ReloadSetupOptions(options *RuntimeSetupOptions) error {
	setupMu.Lock()
	defer setupMu.Unlock()

	if !setupDone {
		return bridgeSafeError(errors.New("hako: ReloadSetupOptions before Setup"))
	}
	if options == nil {
		return bridgeSafeError(errors.New("hako: ReloadSetupOptions called with nil options"))
	}
	if err := validateRuntimeSetupOptions(options); err != nil {
		return bridgeSafeError(err)
	}

	if options.SoftMemoryLimit != 0 {
		debug.SetMemoryLimit(options.SoftMemoryLimit)
		currentRuntimeSetup.softMemoryLimit = options.SoftMemoryLimit
		currentRuntimeSetup.softMemoryLimitIsPacingDefault = false
		// An explicit limit re-arms the threshold machine too; without this
		// the machine would keep judging against the previous limit until the
		// next Setup or NewService. The machine gets the budget the pacing
		// value describes, not the pacing value itself -- see
		// machineBudgetForPacing.
		startPressureThresholdMonitor(machineBudgetForPacing(options.SoftMemoryLimit), pressureThresholdShedEnabled.Load())
	}
	if options.GCPercent != 0 {
		debug.SetGCPercent(options.GCPercent)
		currentRuntimeSetup.gcPercent = options.GCPercent
	}
	if options.LogMaxLines != 0 {
		recentLogs.setMax(options.LogMaxLines)
		currentRuntimeSetup.logMaxLines = options.LogMaxLines
	}
	return nil
}

func validateRuntimeSetupOptions(options *RuntimeSetupOptions) error {
	restartFields := []struct {
		name    string
		changed bool
	}{
		{"BasePath", options.BasePath != ""},
		{"WorkingPath", options.WorkingPath != ""},
		{"TempPath", options.TempPath != ""},
		{"TimeZone", options.TimeZone != ""},
		{"MaxProcs", options.MaxProcs != 0},
		{"TunMTU", options.TunMTU != 0},
		{"ClashAPISocketPath", options.ClashAPISocketPath != ""},
		{"CoreIdentity", options.CoreIdentity != ""},
	}
	for _, field := range restartFields {
		if field.changed {
			return fmt.Errorf("hako: changing %s requires restart", field.name)
		}
	}
	if value := options.SoftMemoryLimit; value != 0 &&
		(value < minReloadSoftMemoryLimit || value > maxReloadSoftMemoryLimit) {
		return fmt.Errorf(
			"hako: SoftMemoryLimit must be 0 (unchanged) or %d...%d bytes",
			minReloadSoftMemoryLimit,
			maxReloadSoftMemoryLimit,
		)
	}
	if value := options.GCPercent; value != 0 &&
		(value < minReloadGCPercent || value > maxReloadGCPercent) {
		return fmt.Errorf(
			"hako: GCPercent must be 0 (unchanged) or %d...%d",
			minReloadGCPercent,
			maxReloadGCPercent,
		)
	}
	if value := options.LogMaxLines; value != 0 &&
		(value < minReloadLogMaxLines || value > maxReloadLogMaxLines) {
		return fmt.Errorf(
			"hako: LogMaxLines must be 0 (unchanged) or %d...%d",
			minReloadLogMaxLines,
			maxReloadLogMaxLines,
		)
	}
	return nil
}

func runtimeSetupSnapshot() runtimeSetupState {
	setupMu.Lock()
	defer setupMu.Unlock()
	return currentRuntimeSetup
}
