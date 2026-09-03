package hako

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TokenPLS/Hako/tunnel/statistic"
	tun "github.com/metacubex/sing-tun"
)

const (
	// Bumped to 2 when the gVisor receive-occupancy fields were added. Bumping costs
	// one stale record across an app update -- ConsumeOOMEvidence rejects a version it
	// does not recognise -- and that is the right trade: a v1 file decoded by this build
	// would report occupancy 0, which reads as "the stack held nothing" when the truth is
	// "not recorded". An instrumentation change made to stop a report lying must not
	// introduce a new way for it to lie.
	// Bumped to 3 when the reload fields were added (see beginReloadEvidence): a v2 record
	// carries no reload phase, and "not recorded" must not decode as "not reloading".
	oomEvidenceSchemaVersion = 3
	oomEvidenceFileName      = "hako-oom-evidence.json"
	oomEvidenceMaxBytes      = 4 << 10
	oomEvidenceMinInterval   = time.Hour
)

// oomEvidence is intentionally numeric and fixed-shape. It must never grow
// connection, log, config, hostname, address or credential fields: this file
// is written at critical pressure and read from the shared App Group.
type oomEvidence struct {
	SchemaVersion       int    `json:"schemaVersion"`
	RecordedAtUnix      int64  `json:"recordedAtUnix"`
	PressureLevel       string `json:"pressureLevel"`
	ProcessIdentifier   int    `json:"processIdentifier"`
	PossibleSystemKill  bool   `json:"possibleSystemKill"`
	PhysicalMemoryBytes int64  `json:"physicalMemoryBytes"`
	// Absent, not zero, when nothing set one: iOS carries no ceiling of ours by ruling,
	// and a diagnosis reconstructed from this file must not read a limit into it.
	SoftMemoryLimit   int64  `json:"softMemoryLimit,omitempty"`
	GCPercent         int    `json:"gcPercent"`
	CoreState         string `json:"coreState"`
	CoreStartTimeUnix int64  `json:"coreStartTimeUnix"`
	InboundCount      int32  `json:"inboundCount"`
	OutboundCount     int32  `json:"outboundCount"`
	ConnectionCount   int32  `json:"connectionCount"`
	GoroutineCount    int    `json:"goroutineCount"`
	HeapAllocBytes    uint64 `json:"heapAllocBytes"`
	HeapInuseBytes    uint64 `json:"heapInuseBytes"`
	StackInuseBytes   uint64 `json:"stackInuseBytes"`
	NumGC             uint32 `json:"numGC"`
	// The gVisor receive-occupancy distribution is already computed in release
	// builds for RuntimeDiagnosticsJSON, so recording it here costs nothing and
	// answers the first question anyone asks of a pressure event: was the stack
	// holding queued data, or was the footprint elsewhere. Payload bytes, not
	// memory -- see GVisorTCPWindowReport for why those differ.
	//
	// SegmentQueueDropped is the one to trust for "backpressure reached the cap".
	// NearReceiveMax compares payload against a memory-enforced limit and reads 0
	// even at saturation; it is recorded only because the schema already has it.
	GVisorReceiveOccupancyP50Bytes int    `json:"gvisorReceiveOccupancyP50Bytes"`
	GVisorReceiveOccupancyP95Bytes int    `json:"gvisorReceiveOccupancyP95Bytes"`
	GVisorReceiveOccupancyMaxBytes int    `json:"gvisorReceiveOccupancyMaxBytes"`
	GVisorSegmentQueueDropped      uint64 `json:"gvisorSegmentQueueDropped"`
	// What a reload was doing when this was written, if one was running: the phase it was
	// in, when it began, and what the memory judge computed before letting it start. Absent
	// when no reload was in flight. On a marker (PressureLevel "reload") these are the
	// point; on a pressure record they are the attribution.
	ReloadPhase          string `json:"reloadPhase,omitempty"`
	ReloadStartedUnix    int64  `json:"reloadStartedUnix,omitempty"`
	ReloadNeededBytes    int64  `json:"reloadNeededBytes,omitempty"`
	ReloadAvailableBytes int64  `json:"reloadAvailableBytes,omitempty"`
}

var (
	oomEvidenceMu        sync.Mutex
	oomEvidenceLastWrite atomic.Int64
	oomCoreRunning       atomic.Bool
	oomCoreStartTimeUnix atomic.Int64
	oomCoreInboundCount  atomic.Int32
	oomCoreOutboundCount atomic.Int32

	// oomEvidenceWrites counts pressure records written by this process, under oomEvidenceMu.
	// It is what the reload marker's ownership is judged against -- a sequence, not a clock:
	// a clock can step backwards, and the question is only "was a pressure record written
	// after the marker".
	oomEvidenceWrites uint64

	// The reload in flight, if any, under oomEvidenceMu. ticket tells a late caller apart
	// from the current reload; markerWritten with markerAtWrite says whether the file on disk
	// is this reload's own marker (see beginReloadEvidence for when it is not).
	reloadEvidence struct {
		ticket            uint64
		phase             string
		startedUnix       int64
		needed, available int64
		footprint         int64
		markerWritten     bool
		markerAtWrite     uint64 // oomEvidenceWrites when the marker was written
	}
)

const (
	reloadPhaseParse = "parse"
	reloadPhaseApply = "apply"
)

func setOOMEvidenceCoreState(running bool, startTimeUnix int64, inboundCount, outboundCount int32) {
	oomCoreStartTimeUnix.Store(startTimeUnix)
	oomCoreInboundCount.Store(inboundCount)
	oomCoreOutboundCount.Store(outboundCount)
	oomCoreRunning.Store(running)
}

// RecordMemoryPressureEvidence persists one bounded critical-pressure
// snapshot. It is exported so an Apple host with its own pressure source can
// use the same reporter; Hako's built-in GCD source calls it automatically.
func RecordMemoryPressureEvidence() error {
	oomEvidenceMu.Lock()
	defer oomEvidenceMu.Unlock()

	now := time.Now()
	if lastNanos := oomEvidenceLastWrite.Load(); lastNanos != 0 {
		if now.Sub(time.Unix(0, lastNanos)) < oomEvidenceMinInterval {
			return nil
		}
	}

	path, runtimeSetup, err := oomEvidenceRuntimeState()
	if err != nil {
		return bridgeSafeError(err)
	}
	report := currentOOMEvidenceLocked(now, "critical", physFootprint(), runtimeSetup)
	if err := writeOOMEvidenceAt(path, report, os.Rename); err != nil {
		return bridgeSafeError(err)
	}
	oomEvidenceLastWrite.Store(now.UnixNano())
	oomEvidenceWrites++
	return nil
}

// currentOOMEvidenceLocked builds a record of the process as it is now, at the given pressure
// level and with the given footprint reading. Caller holds oomEvidenceMu.
func currentOOMEvidenceLocked(now time.Time, level string, footprint int64, runtimeSetup runtimeSetupState) oomEvidence {
	var connectionCount int32
	statistic.DefaultManager.Range(func(statistic.Tracker) bool {
		connectionCount++
		return true
	})
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	coreState := "stopped"
	if oomCoreRunning.Load() {
		coreState = "running"
	}
	report := oomEvidence{
		SchemaVersion:        oomEvidenceSchemaVersion,
		RecordedAtUnix:       now.Unix(),
		PressureLevel:        level,
		ProcessIdentifier:    os.Getpid(),
		PossibleSystemKill:   true,
		PhysicalMemoryBytes:  footprint,
		SoftMemoryLimit:      runtimeSetup.softMemoryLimit,
		GCPercent:            runtimeSetup.gcPercent,
		CoreState:            coreState,
		CoreStartTimeUnix:    oomCoreStartTimeUnix.Load(),
		InboundCount:         oomCoreInboundCount.Load(),
		OutboundCount:        oomCoreOutboundCount.Load(),
		ConnectionCount:      connectionCount,
		GoroutineCount:       runtime.NumGoroutine(),
		HeapAllocBytes:       memory.HeapAlloc,
		HeapInuseBytes:       memory.HeapInuse,
		StackInuseBytes:      memory.StackInuse,
		NumGC:                memory.NumGC,
		ReloadPhase:          reloadEvidence.phase,
		ReloadStartedUnix:    reloadEvidence.startedUnix,
		ReloadNeededBytes:    reloadEvidence.needed,
		ReloadAvailableBytes: reloadEvidence.available,
	}
	if snapshot := tun.GVisorTCPWindowSnapshot; snapshot != nil {
		window := snapshot()
		report.GVisorReceiveOccupancyP50Bytes = window.ReceiveOccupancyP50Bytes
		report.GVisorReceiveOccupancyP95Bytes = window.ReceiveOccupancyP95Bytes
		report.GVisorReceiveOccupancyMaxBytes = window.ReceiveOccupancyMaxBytes
		report.GVisorSegmentQueueDropped = window.SegmentQueueDroppedTotal
	}
	return report
}

// beginReloadEvidence records that a reload is starting to build its second core, and leaves
// a marker in the OOM evidence file saying so.
//
// The pressure callback that normally writes that file cannot help here: a process killed
// 116 ms into a reload gets no callback, no crash report and no shutdown line, so nothing on
// disk says a reload was running -- and the App reads the death as a stalled extension. The
// marker is written before the parse and taken back by endReloadEvidence when the reload
// finishes, well or badly; if the process is gone, the marker is what the next start reads.
// It carries the judge's numbers so an accepted reload that still died is the estimator's
// feedback: that is the case in which reloadBuildCostSafetyFactor is too low.
//
// A file already on disk is worth more than the marker -- a pressure record the App has not
// consumed, or a previous reload's death -- so the marker never overwrites it, and the
// bookkeeping remembers that the file is not this reload's to remove. Marker writes do not
// touch oomEvidenceLastWrite: that is the pressure record's rate limit, not the marker's.
// Returns the ticket the other two calls need.
func beginReloadEvidence(verdict reloadMemoryVerdict) uint64 {
	oomEvidenceMu.Lock()
	defer oomEvidenceMu.Unlock()
	reloadEvidence.ticket++
	reloadEvidence.phase = reloadPhaseParse
	reloadEvidence.startedUnix = time.Now().Unix()
	reloadEvidence.needed = verdict.NeededBytes
	reloadEvidence.available = verdict.AvailableBytes
	reloadEvidence.footprint = verdict.FootprintBytes
	reloadEvidence.markerWritten = false
	path, runtimeSetup, err := oomEvidenceRuntimeState()
	if err != nil {
		return reloadEvidence.ticket
	}
	if _, statErr := os.Stat(path); statErr == nil || !os.IsNotExist(statErr) {
		return reloadEvidence.ticket
	}
	if err := writeOOMEvidenceAt(path, currentOOMEvidenceLocked(time.Now(), "reload", verdict.FootprintBytes, runtimeSetup), os.Rename); err == nil {
		reloadEvidence.markerWritten = true
		reloadEvidence.markerAtWrite = oomEvidenceWrites
	}
	return reloadEvidence.ticket
}

// reloadEvidenceOwnsFileLocked says whether the file on disk is still this reload's marker: it
// was written, and no pressure record has been written since -- judged by the write sequence,
// which cannot step backwards the way a clock can. Caller holds oomEvidenceMu.
func reloadEvidenceOwnsFileLocked() bool {
	return reloadEvidence.markerWritten && oomEvidenceWrites == reloadEvidence.markerAtWrite
}

// advanceReloadEvidence moves the reload to its next phase, and rewrites the marker if the
// file is still ours.
func advanceReloadEvidence(ticket uint64, phase string) {
	oomEvidenceMu.Lock()
	defer oomEvidenceMu.Unlock()
	if ticket != reloadEvidence.ticket {
		return
	}
	reloadEvidence.phase = phase
	if !reloadEvidenceOwnsFileLocked() {
		return
	}
	path, runtimeSetup, err := oomEvidenceRuntimeState()
	if err != nil {
		return
	}
	_ = writeOOMEvidenceAt(path, currentOOMEvidenceLocked(time.Now(), "reload", reloadEvidence.footprint, runtimeSetup), os.Rename)
}

// endReloadEvidence takes the marker back and forgets the reload. A pressure record written
// meanwhile is left where it is: it is not ours, and it says more than the marker did.
func endReloadEvidence(ticket uint64) {
	oomEvidenceMu.Lock()
	defer oomEvidenceMu.Unlock()
	if ticket != reloadEvidence.ticket {
		return
	}
	if reloadEvidenceOwnsFileLocked() {
		if path, _, err := oomEvidenceRuntimeState(); err == nil {
			_ = os.Remove(path)
		}
	}
	reloadEvidence.phase = ""
	reloadEvidence.startedUnix, reloadEvidence.needed, reloadEvidence.available, reloadEvidence.footprint = 0, 0, 0, 0
	reloadEvidence.markerWritten = false
}

func oomEvidenceRuntimeState() (string, runtimeSetupState, error) {
	setupMu.Lock()
	defer setupMu.Unlock()
	if !setupDone || setupOOMEvidencePath == "" {
		return "", runtimeSetupState{}, errors.New("hako: OOM evidence before Setup")
	}
	return setupOOMEvidencePath, currentRuntimeSetup, nil
}

func writeOOMEvidenceAt(path string, report oomEvidence, rename func(string, string) error) error {
	data, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("hako: encode OOM evidence: %w", err)
	}
	if len(data) > oomEvidenceMaxBytes {
		return fmt.Errorf("hako: OOM evidence is %d bytes; limit is %d", len(data), oomEvidenceMaxBytes)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("hako: create OOM evidence directory: %w", err)
	}
	temporary := path + ".tmp"
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("hako: create OOM evidence temporary file: %w", err)
	}
	cleanup := true
	defer func() {
		_ = file.Close()
		if cleanup {
			_ = os.Remove(temporary)
		}
	}()
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("hako: write OOM evidence: %w", err)
	}
	if err := rename(temporary, path); err != nil {
		return fmt.Errorf("hako: commit OOM evidence: %w", err)
	}
	cleanup = false
	if directory, err := os.Open(filepath.Dir(path)); err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return nil
}

// ConsumeOOMEvidence returns the validated report and removes it only after
// successful decoding. A corrupt or oversized file is removed with an error
// so it cannot create an infinite startup-error loop.
func ConsumeOOMEvidence() (*StringBox, error) {
	oomEvidenceMu.Lock()
	defer oomEvidenceMu.Unlock()
	path, _, err := oomEvidenceRuntimeState()
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	// A live reload's own marker is working state, not evidence: it only means something if
	// the process dies with it, and consuming it now would report a death that has not
	// happened while stripping the tombstone from a build that may yet be the thing that
	// kills the process. To the caller this is "no evidence" -- the same answer as no file.
	if reloadEvidenceOwnsFileLocked() {
		return nil, bridgeSafeError(os.ErrNotExist)
	}
	data, err := readBoundedFile(path, oomEvidenceMaxBytes)
	if err != nil {
		if !os.IsNotExist(err) {
			_ = os.Remove(path)
		}
		return nil, bridgeSafeError(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var report oomEvidence
	if err := decoder.Decode(&report); err != nil {
		_ = os.Remove(path)
		return nil, bridgeSafeError(fmt.Errorf("hako: invalid OOM evidence: %w", err))
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		_ = os.Remove(path)
		return nil, bridgeSafeError(errors.New("hako: invalid OOM evidence trailing data"))
	}
	if report.SchemaVersion != oomEvidenceSchemaVersion ||
		(report.PressureLevel != "critical" && report.PressureLevel != "reload") || !report.PossibleSystemKill {
		_ = os.Remove(path)
		return nil, bridgeSafeError(errors.New("hako: invalid OOM evidence schema or pressure state"))
	}
	normalized, err := json.Marshal(report)
	if err != nil {
		return nil, bridgeSafeError(fmt.Errorf("hako: normalize OOM evidence: %w", err))
	}
	if err := os.Remove(path); err != nil {
		return nil, bridgeSafeError(fmt.Errorf("hako: consume OOM evidence: %w", err))
	}
	return WrapString(string(normalized)), nil
}

func readBoundedFile(path string, maximum int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("hako: stat OOM evidence: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("hako: OOM evidence is not a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, fmt.Errorf("hako: read OOM evidence: %w", err)
	}
	if int64(len(data)) > maximum {
		return nil, fmt.Errorf("hako: OOM evidence exceeds %d bytes", maximum)
	}
	return data, nil
}

// abandonReloadEvidenceStateForTest clears the in-process reload bookkeeping WITHOUT touching
// the file, which is what a process death does: the marker stays on disk and the next launch
// starts with no reload in flight. Tests only.
func abandonReloadEvidenceStateForTest() {
	oomEvidenceMu.Lock()
	defer oomEvidenceMu.Unlock()
	reloadEvidence.ticket++
	reloadEvidence.phase = ""
	reloadEvidence.startedUnix, reloadEvidence.needed, reloadEvidence.available, reloadEvidence.footprint = 0, 0, 0, 0
	reloadEvidence.markerWritten = false
}
