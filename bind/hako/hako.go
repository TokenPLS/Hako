package hako

import (
	"errors"
	"fmt"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/TokenPLS/Hako/constant"
	"github.com/TokenPLS/Hako/constant/features"
)

// CommandSchemaVersion is Hako's App↔Extension command contract version. It is
// intentionally independent from both mihomo's product version and libbox's
// gRPC schema. Increment it only for an incompatible wire change.
const CommandSchemaVersion int32 = 1

// CommandSchemaMinVersion is the oldest command contract this build accepts.
const CommandSchemaMinVersion int32 = 1

// CheckCommandSchema rejects a peer before streams/actions start when the two
// supported version ranges do not overlap.
func CheckCommandSchema(peerMin, peerCurrent int32) error {
	if peerMin <= 0 || peerCurrent < peerMin {
		return bridgeSafeError(errors.New("hako: invalid peer command schema range"))
	}
	if peerCurrent < CommandSchemaMinVersion || peerMin > CommandSchemaVersion {
		return bridgeSafeError(fmt.Errorf(
			"hako: incompatible command schema: local=%d...%d peer=%d...%d",
			CommandSchemaMinVersion, CommandSchemaVersion, peerMin, peerCurrent,
		))
	}
	return nil
}

// Version returns the mihomo core version. constant.Version is a placeholder
// in source; the real value (e.g. "1.19.28") is injected at bind time via
// -ldflags -X by cmd/build_libbox.
func Version() string {
	return bridgeSafeString(constant.Version)
}

// GoVersion reports the bound runtime and target, matching libbox's diagnostic
// helper without exposing build-system details through the core version.
func GoVersion() string {
	return bridgeSafeString(runtime.Version() + ", " + runtime.GOOS + "/" + runtime.GOARCH)
}

// FreeMemory returns as much Go heap memory to the OS as possible.
// Exposed for the NE process to call on memory pressure.
func FreeMemory() {
	debug.FreeOSMemory()
}

// MemoryFootprint returns the process phys_footprint in bytes — the exact
// value iOS jetsam meters against the NE budget. -1 off darwin.
// More accurate than the RSS estimate; use this for the memory gate.
func MemoryFootprint() int64 {
	return physFootprint()
}

// LowMemoryBuild reports whether the with_low_memory build tag is active
// (halved relay/UDP buffers). Lets Swift/tests confirm the iOS slice was
// built with the memory-constrained recipe; the macOS slice is
// expected to report false.
func LowMemoryBuild() bool {
	return features.WithLowMemory
}

// TZProbe reports Hako's configured presentation location. It intentionally
// does not read or mutate time.Local, which is unsafe to rewrite after a
// gomobile process has started timers.
func TZProbe() string {
	now := hakoLocalTime(time.Now())
	return bridgeSafeString(fmt.Sprintf("loc=%s offset=%s now=%s",
		now.Location().String(),
		now.Format("-07:00"),
		now.Format("2006-01-02 15:04:05")))
}
