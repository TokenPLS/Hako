package hako

// What a tunnel killed for memory can still say.
//
// When jetsam reclaims a packet tunnel, stopTunnel is never called. No handler runs,
// nothing is logged, no reason code is delivered -- the process simply stops existing. All
// the reader gets is the system's own sentence, "the VPN tunnel stopped unexpectedly",
// which names neither what happened nor anything they could change about it. Readers have
// been reporting that sentence for as long as the product has existed, and it has never
// carried information.
//
// The only thing that survives a kill is what was already on disk. So the tunnel writes
// where it has got to and what it is costing as it starts, and the next launch reads it:
// the stage names a resource from the reader's own configuration, and the footprint sits
// next to the budget it was measured against.
//
// Deliberately NOT a prediction. Estimating a configuration's peak before running it was
// tried and abandoned: the same configuration measured 61.9 MiB and 50.2 MiB on
// consecutive runs of the same machine, because the peak is as much GC pacing as it is
// data. A number that unstable cannot be the basis of a warning. This reports what
// actually happened instead, which needs no coefficient and cannot be wrong.
//
// No fsync. Jetsam is not a power cut -- the process dies, the page cache does not -- so a
// plain write is durable enough for exactly this failure, and paying a sync per stage on
// the startup path would be spending the reader's time to survive a case that does not
// apply.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/TokenPLS/Hako/component/geodata"
	C "github.com/TokenPLS/Hako/constant"
)

const breadcrumbFileName = "startup-breadcrumb.json"

// breadcrumbDirectory is where the record lives. A variable so tests can point it
// somewhere temporary; in a tunnel it is the working directory the App shares.
var breadcrumbDirectory string

var breadcrumbMutex sync.Mutex

type startupBreadcrumb struct {
	// Stage is Core's own marker for which step was running: bind:normalized,
	// bind:providers-staged. It is deliberately internal and NOT for a reader --
	// "the tunnel stopped at bind:apple-validate-in" reads like an error they caused.
	Stage string `json:"stage"`
	// Resource is the reader-facing half, and only exists when there is one: the geosite
	// category, the GeoIP country. Empty is honest -- most steps are not about a resource
	// -- and it lets the client say "while loading geosite:cn" only when that is true.
	//
	// Split from Stage after the client found that every production call site passed an
	// internal name while the doc comment and the test both claimed otherwise. The test
	// wrote its own "geosite:…" and asserted on it, so the property it proved belonged to
	// that literal rather than to the program.
	Resource string `json:"resource"`
	// Completed is false while startup is in flight. A record still saying false at the
	// next launch is the whole signal: nothing cleared it, so nothing finished.
	Completed      bool  `json:"completed"`
	FootprintBytes int64 `json:"footprintBytes"`
	// BudgetBytes is absent, not zero, when there is no ceiling to state.
	//
	// iOS carries none of ours by ruling: the 50 MiB this project used to set was its
	// own invention, the 40 MiB later measured is not the number either, and the real
	// limit is computed by the system per device and per moment. So MemoryLimit is left
	// unset, the branch deriving a soft limit never runs, and this stays at its zero
	// value.
	//
	// Shipping that zero in a field named for a budget states something false in the
	// worst direction: `footprint >= budget*0.8` holds for every footprint when the
	// budget is zero, so a crash at three megabytes reads as running out of memory and
	// sends the reader to delete a configuration that was never the problem. One
	// `> 0` test on the client is all that stands in the way, in a branch whose own
	// comments record three earlier versions of it being wrong.
	//
	// omitempty makes the absence structural: there is nothing to multiply. A ruling
	// about the product may remove a ceiling; it may not make the record claim the
	// ceiling is zero.
	BudgetBytes int64 `json:"budgetBytes,omitempty"`
	// StartedAt lets the App tell a tunnel that is mid-start from one that died: the two
	// look identical on disk otherwise, and they are separate processes.
	StartedAt string `json:"startedAt"`
	UpdatedAt string `json:"updatedAt"`
	// Install identifies the app installation that wrote this record. Without it a death
	// from a previous install is indistinguishable from one this install produced -- and it
	// greeted a fresh install on its first launch, over a start that had never happened
	// there. See currentInstallIdentity for why Core derives this rather than being told.
	Install string `json:"install"`
	// FailureReason is why Start RETURNED an error, for the death that is not a
	// kill: the process lived long enough to say why, and until this field the
	// reason drowned in NEVPNConnectionErrorDomain code=12 -- the reader saw
	// "the VPN tunnel failed" naming nothing they could change, while the text
	// that named it (a phantom geosite category, a refused proxy) died with the
	// process. Error text may quote the reader's own configuration (names,
	// servers); this file lives in the App Group beside that configuration
	// and leaves the device only through the
	// App's export paths, which redact.
	FailureReason string `json:"failureReason"`
}

func breadcrumbPath() string {
	directory := breadcrumbDirectory
	if directory == "" {
		directory = homeDirectoryForBreadcrumb()
	}
	if directory == "" {
		return ""
	}
	return filepath.Join(directory, breadcrumbFileName)
}

// recordStartupStage notes that startup has reached a named point, with what it costs
// there. Called as the tunnel walks its configuration; cheap enough to call per resource.
func recordStartupStage(stage string) {
	recordStartupStageNaming(stage, "")
}

// recordStartupStageNaming is recordStartupStage for the steps that already know which
// of the reader's resources they are about to build. Both halves in one record because
// each write is an atomic replace -- a temporary file and a rename, measured at 177us of
// the 212us a step costs -- and a step that wrote its stage and then its resource paid
// that twice to describe one moment. The pair is not free to double: it is on the path a
// reader waits on, and the same startup path has had 94ms argued over.
func recordStartupStageNaming(stage string, resource string) {
	breadcrumbMutex.Lock()
	defer breadcrumbMutex.Unlock()

	path := breadcrumbPath()
	if path == "" {
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	record := startupBreadcrumb{
		Stage:          stage,
		Resource:       resource,
		Completed:      false,
		FootprintBytes: MemoryFootprint(),
		BudgetBytes:    runtimeSetupSnapshot().softMemoryLimit,
		StartedAt:      now,
		UpdatedAt:      now,
		Install:        currentInstallIdentity(),
	}
	// Keep the original start time across stages, so the App can judge how long the dead
	// run had been going. A resource is NOT carried from the previous step: a new step is
	// not about the step before it, and carrying it would have the client say the tunnel
	// died loading something it had already finished.
	if existing, err := readBreadcrumb(path); err == nil && !existing.Completed && existing.StartedAt != "" {
		record.StartedAt = existing.StartedAt
	}
	writeBreadcrumb(path, record)
}

// recordStartupResource names the resource now being built, keeping the step that is
// building it. Called from the geodata seam, where the name comes from the configuration.
func recordStartupResource(resource string) {
	breadcrumbMutex.Lock()
	defer breadcrumbMutex.Unlock()

	path := breadcrumbPath()
	if path == "" {
		return
	}
	record := currentRecord(path)
	record.Install = currentInstallIdentity()
	record.Resource = resource
	record.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	record.FootprintBytes = MemoryFootprint()
	record.BudgetBytes = runtimeSetupSnapshot().softMemoryLimit
	writeBreadcrumb(path, record)
}

// recordStartupFailure stamps the in-flight record with why Start is about to
// return an error. No-op outside the recording window (an App-process caller,
// or a failure before the tunnel began recording) and on nil. Keeps stage and
// resource: "failed at bind:providers-staged while geosite:https" is the whole
// sentence the reader never got.
func recordStartupFailure(startErr error) {
	if startErr == nil || !breadcrumbRecording.Load() {
		return
	}
	breadcrumbMutex.Lock()
	defer breadcrumbMutex.Unlock()

	path := breadcrumbPath()
	if path == "" {
		return
	}
	record := currentRecord(path)
	record.Install = currentInstallIdentity()
	record.FailureReason = startErr.Error()
	record.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	record.FootprintBytes = MemoryFootprint()
	record.BudgetBytes = runtimeSetupSnapshot().softMemoryLimit
	writeBreadcrumb(path, record)
}

// refreshStartupBreadcrumbFootprint rewrites the in-flight record with the footprint of
// this moment, keeping stage and resource. Called from the memory-pressure handler: a
// record whose footprint is from the last stage boundary understates the spend that is
// about to kill the process. Does nothing when no start is being recorded.
func refreshStartupBreadcrumbFootprint() {
	if !breadcrumbRecording.Load() {
		return
	}
	breadcrumbMutex.Lock()
	defer breadcrumbMutex.Unlock()
	path := breadcrumbPath()
	if path == "" {
		return
	}
	existing, err := readBreadcrumb(path)
	if err != nil || existing.Completed {
		return
	}
	existing.FootprintBytes = MemoryFootprint()
	existing.BudgetBytes = runtimeSetupSnapshot().softMemoryLimit
	existing.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	writeBreadcrumb(path, existing)
}

// currentRecord reads what is there, or starts a fresh one.
func currentRecord(path string) startupBreadcrumb {
	now := time.Now().UTC().Format(time.RFC3339)
	if existing, err := readBreadcrumb(path); err == nil && !existing.Completed {
		return existing
	}
	return startupBreadcrumb{StartedAt: now, UpdatedAt: now}
}

// markStartupComplete ends the recording window: the record is dropped, the recorder is
// disarmed, and the geodata seam is uninstalled.
//
// Without this the record is never cleared, so EVERY launch after a normal start reads
// completed:false and reports a death that did not happen -- which is worse than the
// system sentence it replaces, because it is confidently wrong. Disarming also guarantees
// that nothing on the per-connection matching path can reach the recorder afterwards,
// however the seam is wired later.
func markStartupComplete() {
	setStartupBreadcrumbRecording(false)
	geodata.SetGeodataProgressReporter(nil)
	recordStartupComplete()
}

// recordStartupComplete clears the record. A tunnel that started is a tunnel with nothing
// to apologise for at the next launch.
func recordStartupComplete() {
	breadcrumbMutex.Lock()
	defer breadcrumbMutex.Unlock()

	if path := breadcrumbPath(); path != "" {
		_ = os.Remove(path)
	}
}

// ExplainLastStartup returns the record a previous run left behind, as JSON, or an empty
// string when there is nothing to explain.
//
// This and ClearLastStartupExplanation are the ONLY two the client calls. Everything else
// in this file is wiring inside the binding package and is unexported, so it never reaches
// the generated header -- a consumer should not be shown a recorder it must not drive.
//
// Empty is a distinct answer from an explanation and the client must be able to tell them
// apart without reading prose, which is why this returns "" rather than a JSON object with
// a nothing-happened field.
func ExplainLastStartup() string {
	breadcrumbMutex.Lock()
	defer breadcrumbMutex.Unlock()

	path := breadcrumbPath()
	if path == "" {
		return ""
	}
	record, err := readBreadcrumb(path)
	if err != nil {
		return ""
	}
	// A record this install did not write explains nothing about it. Empty is the same
	// distinct answer already used for "nothing to explain", so the client needs no new
	// branch: a missing Install can only predate this field, and by now the useful lifetime
	// of any such record has passed.
	if record.Install == "" || record.Install != currentInstallIdentity() {
		return ""
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return ""
	}
	return string(encoded)
}

// ClearLastStartupExplanation drops the record once the App has shown it, so the same
// death is not reported at every launch afterwards.
func ClearLastStartupExplanation() {
	recordStartupComplete()
}

func readBreadcrumb(path string) (startupBreadcrumb, error) {
	var record startupBreadcrumb
	content, err := os.ReadFile(path)
	if err != nil {
		return record, err
	}
	if err := json.Unmarshal(content, &record); err != nil {
		return record, err
	}
	return record, nil
}

func writeBreadcrumb(path string, record startupBreadcrumb) {
	encoded, err := json.Marshal(record)
	if err != nil {
		return
	}
	// Written whole and replaced by rename, so a reader at the next launch never sees a
	// half-written record -- which would be indistinguishable from a corrupt one and would
	// cost the explanation this exists to give.
	//
	// A UNIQUE temporary name, not path+".writing". breadcrumbMutex covers writers inside
	// one process, and nothing covers the App and the tunnel -- they are separate processes
	// sharing a container. Only the tunnel writes today, so a fixed name is latent rather
	// than live, but the cost of not relying on that is one function call.
	temporary, err := os.CreateTemp(filepath.Dir(path), ".breadcrumb-*")
	if err != nil {
		return
	}
	defer os.Remove(temporary.Name())
	if _, err := temporary.Write(encoded); err != nil {
		temporary.Close()
		return
	}
	if err := temporary.Close(); err != nil {
		return
	}
	_ = os.Rename(temporary.Name(), path)
}

// homeDirectoryForBreadcrumb resolves where the record belongs when nothing has set it
// explicitly: the working directory the App and the tunnel share, which is the only place
// a tunnel can write that outlives it.
func homeDirectoryForBreadcrumb() string {
	return C.Path.HomeDir()
}

// Test seams for the reporter, so a test can assert the wiring without geodata exporting
// its own state.
func progressReporterInstalled() func(string) { return geodata.GeodataProgressReporter() }

func restoreProgressReporter(report func(string)) { geodata.SetGeodataProgressReporter(report) }

// currentInstallIdentity names the app installation this process belongs to.
//
// The problem it solves: iOS keeps the App Group container across a reinstall, and every
// path Core is given points into it, so a record written before the reinstall survives and
// reads exactly like one this install produced. A reader on a fresh install was shown an
// account of a start that had never happened to them.
//
// Core derives it rather than taking it from the App, for two reasons. Nothing the App can
// offer has the property: CFBundleVersion is stable across launches, which is right, but two
// installs of the same build share it -- and delete-then-reinstall-the-same-build is exactly
// the case that was reported. And a new SetupOptions field is a field with no caller until
// somebody wires it, which this session has already shipped twice.
//
// The bundle container has the property. On iOS an app lives at
// /private/var/containers/Bundle/Application/<UUID>/Hako.app, that UUID is minted per
// installation, and the App and its extension share it because the appex is inside the same
// .app -- so the two processes agree without being told.
//
// Two limits, stated rather than discovered later:
//   - An app UPDATE also mints a new bundle container, so an update discards a pending
//     record. That is the conservative direction: a death recorded by the previous build may
//     not describe this one.
//   - On macOS the bundle sits at a stable path, so a reinstall there is NOT detected. The
//     fallback below still distinguishes different install locations, which is all a stable
//     path can support.
//
// Hashed, never raw: this reaches a reader's exported log, and a raw path carries their home
// directory name on macOS.
func currentInstallIdentity() string {
	executable, err := os.Executable()
	if err != nil || executable == "" {
		// No identity is worse than a wrong one only if it lets a stale record through, so
		// this returns a constant that no stored record will match after the first write.
		return "unknown-install"
	}
	if resolved, err := filepath.EvalSymlinks(executable); err == nil {
		executable = resolved
	}

	source := filepath.Dir(executable)
	// The bundle container segment, when the path has one.
	if index := strings.Index(executable, bundleContainerMarker); index >= 0 {
		rest := executable[index+len(bundleContainerMarker):]
		if end := strings.IndexByte(rest, filepath.Separator); end > 0 {
			source = rest[:end]
		} else if rest != "" {
			source = rest
		}
	}
	sum := sha256.Sum256([]byte(source))
	return hex.EncodeToString(sum[:6])
}

// The path segment iOS mints per installation. Written as a constant so the shape this
// depends on is visible rather than buried in an expression.
const bundleContainerMarker = "/Bundle/Application/"
