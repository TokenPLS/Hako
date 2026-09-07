package hako

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TokenPLS/Hako/config"
	"github.com/TokenPLS/Hako/hub/executor"
)

// startupPhase appends one line per stage of Start, with the phys_footprint
// at that moment.
//
// The process this explains is killed inside Start by jetsam's per-process
// limit, so nothing can be collected and reported afterwards: the line has to
// be on disk before the next stage begins. The path comes from Setup and
// points into the caller's own container, beside the sampler's curve, because
// the App Group is not reliably readable over a cable.
//
// A failure here is never allowed to affect Start. This is a diagnostic.
var startupPhaseFailure string

// StartupPhaseDiagnostic reports the path the phase log is using and why it
// is empty, if it is. Read through the sampler's curve, which is the one
// channel already proven to reach a cable from this process.
func StartupPhaseDiagnostic() string {
	phaseMu.Lock()
	diagnostic := "path=" + setupStartupPhaseLogPath + " err=" + startupPhaseFailure
	phaseMu.Unlock()
	return bridgeSafeString(diagnostic)
}

// StartupPhaseTrace returns every stage recorded so far, one per line. The
// file the stages are also written to has never appeared on a cable, so the
// caller reads them from memory instead — the process survives long enough to
// be asked, because Start returns before jetsam acts on the footprint.
// startupProbing is true only between a Start's first statement and its
// return. Bind-side pipeline stages consult it so that the app process --
// which runs the same parse for its editor preflight -- never writes a line.
var startupProbing atomic.Bool

func startupStage(name string) {
	startupStageNaming(name, "")
}

// startupStageNaming is startupStage for a step that already knows the reader's resource
// it is about to build, so the breadcrumb records both in one write.
func startupStageNaming(name string, resource string) {
	startupStageNamingPeak(name, resource, 0)
}

// startupStageNamingPeak additionally carries the high-water footprint measured across
// the step that just ended. Zero means not measured and prints nothing: a bill that shows
// "peak=0.0MiB" for a provider it did not watch reads as a provider that cost nothing.
func startupStageNamingPeak(name string, resource string, peakBytes int64) {
	if startupProbing.Load() {
		startupPhaseWithPeak(name, peakBytes)
	}
	// The probe is a developer's tool and off in the field; the breadcrumb is for the
	// reader whose tunnel was killed, so it is written whenever a packet tunnel is
	// starting. Same stage names, two audiences.
	if breadcrumbRecording.Load() {
		recordStartupStageNaming(name, resource)
	}
}

// providerStepKind maps an executor step onto the reader-facing name of the provider it
// is about, and says which side of Initial it is on. Four step shapes are about a
// provider: the probe before Initial and the one after it, for each kind.
func providerStepKind(step string) (resource string, begin bool, ok bool) {
	for _, candidate := range []struct {
		prefix string
		kind   string
		begin  bool
	}{
		{"rule-provider-begin:", "rule-provider:", true},
		{"proxy-provider-begin:", "proxy-provider:", true},
		{"rule-provider:", "rule-provider:", false},
		{"proxy-provider:", "proxy-provider:", false},
	} {
		if rest, matched := strings.CutPrefix(step, candidate.prefix); matched {
			return candidate.kind + rest, candidate.begin, true
		}
	}
	return "", false, false
}

// armStartupProbes wires the parse and apply probes for one Start and returns the
// disarm. Extracted from Start so a test can drive the seam the tunnel actually
// installs: every earlier test of this reporting wrote its own stage name and
// asserted on that, which proved a property of the literal rather than of the
// program -- and the two call sites below were reporting to the phase log alone
// while the client's explanation branched on stages it could therefore never see.
func armStartupProbes() func() {
	// The section probes are armed only while this Start is on the clock. The
	// same parse pipeline serves the app's editor preflight, and an app-side
	// parse must not write NE startup telemetry.
	startupProbing.Store(true)
	config.StartupProbe = func(section string) { startupStage("parse:" + section) }
	executor.StartupProbe = func(step string) {
		// A provider's name is something the reader wrote, so a kill during its build
		// should name it the way a geo resource is named. Both probes around Initial
		// report the same resource; the first is the only one a process that dies
		// inside Initial can leave behind.
		resource, begin, isProvider := providerStepKind(step)
		switch {
		case isProvider && begin:
			// Written before the window opens, so this record's own cost -- a footprint
			// read, a marshal and an atomic file replace -- is not billed to the build.
			startupStageNaming("apply:"+step, resource)
			startProviderPeakSampling(resource)
		case isProvider:
			// Closed before the record is written, for the same reason in reverse.
			peak := stopProviderPeakSampling(resource)
			startupStageNamingPeak("apply:"+step, resource, peak)
		default:
			startupStage("apply:" + step)
		}
	}
	// Per-provider footprint deltas are only attributable when nothing else allocates in
	// the window, so provider loads run one at a time exactly while a phase log is being
	// collected -- the same opt-in that makes the lines exist at all.
	executor.SerializeProviderLoads = func() bool {
		return startupPhaseLogPath() != ""
	}
	return func() {
		startupProbing.Store(false)
		config.StartupProbe = nil
		executor.StartupProbe = nil
		// A provider that never returned still has its window open.
		stopAnyProviderPeakSampling()
	}
}

// breadcrumbRecording is set for a packet tunnel, where a kill leaves no other account.
var breadcrumbRecording atomic.Bool

// setStartupBreadcrumbRecording turns the on-disk record on for this process.
func setStartupBreadcrumbRecording(on bool) { breadcrumbRecording.Store(on) }

func StartupPhaseTrace() string {
	phaseMu.Lock()
	defer phaseMu.Unlock()
	return bridgeSafeString(strings.Join(phaseTrace, "\n"))
}

var (
	phaseMu                 sync.Mutex
	phaseTrace              []string
	phaseEpoch              = newStartupPhaseEpoch()
	phaseLogGeneration      uint64
	phaseDiagnosticRevision int64
	phaseFailureSequence    int64
)

func startupPhase(name string) {
	startupPhaseWithPeak(name, 0)
}

func startupPhaseWithPeak(name string, peakBytes int64) {
	// The timestamp is half the answer. A footprint says what a stage cost
	// in memory; only the clock says what it cost in the four hundred
	// milliseconds a reader waits for the tunnel.
	line := fmt.Sprintf("%s  go-phase=%-24s fp=%.1fMiB",
		time.Now().Format("15:04:05.000"),
		name, float64(MemoryFootprint())/(1024*1024))
	// Appended, never inserted: the client parses these lines, and a field that only
	// appears where it was measured is additive for a reader that does not know it yet.
	if peakBytes > 0 {
		line += fmt.Sprintf(" peak=%.1fMiB", float64(peakBytes)/(1024*1024))
	}
	phaseMu.Lock()
	phaseTrace = append(phaseTrace, line)
	sequence := int64(len(phaseTrace))
	path := setupStartupPhaseLogPath
	generation := phaseLogGeneration
	phaseMu.Unlock()
	if path == "" {
		return
	}
	// The line already carries its own clock; stamping it again here printed
	// every phase twice over.
	stamped := line + "\n"
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		// Say so where the curve is read. A diagnostic that fails silently
		// costs a whole device round-trip to notice.
		recordStartupPhaseFailure(generation, sequence, fmt.Errorf("open: %w", err))
		return
	}
	if err := writeStartupPhaseRecord(file, stamped); err != nil {
		recordStartupPhaseFailure(generation, sequence, err)
	}
}

// startupPhaseLogPath shares the diagnostic lock with Setup's path publication.
func startupPhaseLogPath() string {
	phaseMu.Lock()
	defer phaseMu.Unlock()
	return setupStartupPhaseLogPath
}

func configureStartupPhaseLogPath(path string) {
	phaseMu.Lock()
	defer phaseMu.Unlock()
	phaseLogGeneration++
	setupStartupPhaseLogPath = path
	startupPhaseFailure = ""
	phaseFailureSequence = 0
	phaseDiagnosticRevision++
}

func recordStartupPhaseFailure(generation uint64, sequence int64, err error) {
	phaseMu.Lock()
	defer phaseMu.Unlock()
	if generation != phaseLogGeneration {
		return
	}
	startupPhaseFailure = err.Error()
	phaseFailureSequence = sequence
	phaseDiagnosticRevision++
}

// Always close a successfully opened file, including after a short write.
// No retry is attempted: partial bytes are diagnostic evidence, not a receipt.
func writeStartupPhaseRecord(file io.WriteCloser, line string) error {
	written, err := io.WriteString(file, line)
	if err == nil && written != len(line) {
		err = io.ErrShortWrite
	}
	closeErr := file.Close()
	if err != nil {
		if closeErr != nil {
			return fmt.Errorf("write: %v; close: %w", err, closeErr)
		}
		return fmt.Errorf("write: %w", err)
	}
	if closeErr != nil {
		return fmt.Errorf("close: %w", closeErr)
	}
	return nil
}
