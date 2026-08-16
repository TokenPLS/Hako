package hako

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/TokenPLS/Hako/component/geodata"
	C "github.com/TokenPLS/Hako/constant"
)

// A tunnel killed for memory never gets to explain itself: jetsam does not call
// stopTunnel, so no handler runs, nothing is logged, and the reader is left with the
// system's own sentence -- "the VPN tunnel stopped unexpectedly" -- which names neither
// what happened nor anything they could change.
//
// The only thing that survives is what was already on disk. So the tunnel writes where it
// is and what it costs as it starts, and the next launch reads it.

func breadcrumbHome(t *testing.T) string {
	t.Helper()
	// Set up the way a tunnel is, so the budget the record carries is the real one:
	// setup.go:227 derives the soft limit as three quarters of MemoryLimit, and a record
	// whose budget is zero gives the footprint nothing to be judged against.
	options := testOptions(t)
	options.MemoryLimit = 50 << 20
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	previous := breadcrumbDirectory
	breadcrumbDirectory = home
	t.Cleanup(func() { breadcrumbDirectory = previous })
	return home
}

func TestBreadcrumbSurvivesAProcessThatNeverStopped(t *testing.T) {
	home := breadcrumbHome(t)

	// A start that gets partway and is then killed: no clean stop, no handler.
	recordStartupStage("parse")
	recordStartupStage("geosite:cn")

	// Next launch, a different process, reading what the dead one left.
	explanation := ExplainLastStartup()
	if explanation == "" {
		t.Fatal("a tunnel that died mid-startup left nothing to explain")
	}
	var report map[string]any
	if err := json.Unmarshal([]byte(explanation), &report); err != nil {
		t.Fatalf("explanation is not JSON: %s", explanation)
	}
	if report["completed"] != false {
		t.Fatalf("a tunnel killed mid-startup was reported as completed: %v", report)
	}
	if report["stage"] != "geosite:cn" {
		t.Fatalf("the last stage reached was %v, not the one it died in", report["stage"])
	}
	if _, err := os.Stat(filepath.Join(home, breadcrumbFileName)); err != nil {
		t.Fatalf("breadcrumb is not on disk, so it could not survive a kill: %v", err)
	}
}

// A tunnel that started cleanly must not have the next launch apologising for it.
func TestBreadcrumbIsClearedByAStartThatSucceeds(t *testing.T) {
	breadcrumbHome(t)

	recordStartupStage("parse")
	recordStartupComplete()

	explanation := ExplainLastStartup()
	if explanation != "" {
		t.Fatalf("a clean start left an explanation behind: %s", explanation)
	}
}

// The footprint at the moment of death is the whole point: it is what separates "your
// configuration is too large for the tunnel" from "something else went wrong", and the
// reader cannot tell those apart from the outside.
func TestBreadcrumbCarriesTheFootprintAndTheBudget(t *testing.T) {
	breadcrumbHome(t)

	recordStartupStage("geoip:us")

	var report map[string]any
	if err := json.Unmarshal([]byte(ExplainLastStartup()), &report); err != nil {
		t.Fatal(err)
	}
	footprint, _ := report["footprintBytes"].(float64)
	if footprint <= 0 {
		t.Fatalf("no footprint recorded: %v", report)
	}
	budget, _ := report["budgetBytes"].(float64)
	if budget <= 0 {
		t.Fatalf("no budget recorded, so the footprint has nothing to be judged against: %v", report)
	}
}

// Nothing to explain is a different answer from an explanation, and the client has to be
// able to tell them apart without parsing prose.
func TestExplainLastStartupIsEmptyWhenNothingHappened(t *testing.T) {
	breadcrumbHome(t)
	if explanation := ExplainLastStartup(); explanation != "" {
		t.Fatalf("invented an explanation with no breadcrumb: %s", explanation)
	}
}

// A breadcrumb from a run that is still going must not be read as a death: the App and the
// tunnel are separate processes, and the App asks this question while the tunnel may be
// mid-start.
func TestBreadcrumbDistinguishesRunningFromDead(t *testing.T) {
	breadcrumbHome(t)
	recordStartupStage("parse")

	var report map[string]any
	if err := json.Unmarshal([]byte(ExplainLastStartup()), &report); err != nil {
		t.Fatal(err)
	}
	if _, ok := report["startedAt"]; !ok {
		t.Fatalf("no start time, so a live run cannot be told from a dead one: %v", report)
	}
}

// The seam has to be wired, or the breadcrumb is a file nobody writes.
//
// Both PrepareGeoIPCache and this were built and left with zero callers in one session,
// and one of them shipped that way. So this asserts the WIRING, not the API.
//
// What it asserts is the guarantee the feature makes: a tunnel parse leaves a record
// naming the last stage it reached, with the footprint beside the budget. It deliberately
// does NOT assert a particular geo resource -- when matchers get built depends on
// geodata-mode, which hub/executor sets at apply time (executor.go:471) rather than parse
// time, so asserting one here would be asserting a coincidence. The per-resource seam is
// tested directly below, where it fires.
func TestParsingUnderTheTunnelRecordsWhereItGotTo(t *testing.T) {
	options := testOptions(t)
	if err := os.MkdirAll(options.WorkingPath, 0o755); err != nil {
		t.Fatal(err)
	}
	options.MemoryLimit = 50 << 20
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	C.SetHomeDir(options.WorkingPath)
	previousDir := breadcrumbDirectory
	breadcrumbDirectory = options.WorkingPath
	t.Cleanup(func() {
		breadcrumbDirectory = previousDir
		setStartupBreadcrumbRecording(false)
	})

	config := `mode: rule
proxies: []
dns:
  enable: true
  nameserver:
    - 223.5.5.5
rules:
  - MATCH,DIRECT
`
	if _, err := parseConfigForIOS(config, true); err != nil {
		t.Logf("parse stopped with: %v (a failure is still a recorded stage)", err)
	}

	explanation := ExplainLastStartup()
	if explanation == "" {
		t.Fatal("a tunnel parse recorded nothing: the reporter is not wired, and a kill " +
			"during this parse would leave the reader with the system sentence and no more")
	}
	var report map[string]any
	if err := json.Unmarshal([]byte(explanation), &report); err != nil {
		t.Fatal(err)
	}
	if stage, _ := report["stage"].(string); !strings.HasPrefix(stage, "bind:") {
		t.Fatalf("the record does not name a startup stage: %q", stage)
	}
	if footprint, _ := report["footprintBytes"].(float64); footprint <= 0 {
		t.Fatalf("no footprint, so the record cannot say whether memory was the reason: %v", report)
	}
	if budget, _ := report["budgetBytes"].(float64); budget <= 0 {
		t.Fatalf("no budget, so the footprint has nothing to be judged against: %v", report)
	}
}

// The per-resource seam, tested where it actually fires: building a matcher.
func TestBuildingAGeoResourceRecordsWhichOne(t *testing.T) {
	breadcrumbHome(t)
	previous := progressReporterInstalled()
	restoreProgressReporter(recordStartupStage)
	t.Cleanup(func() { restoreProgressReporter(previous) })

	// Failure is fine: the announcement happens BEFORE the work, which is the whole point
	// of a record that has to survive the process doing it.
	_, _ = geodata.LoadGeoIPMatcher("cn")

	if explanation := ExplainLastStartup(); !strings.Contains(explanation, "geoip:cn") {
		t.Fatalf("building a matcher recorded nothing about which one: %s", explanation)
	}
}

// The contract is about what the REST of the program passes, so the test must not supply
// it. TestStageNamesAreThingsTheReaderWrote did exactly that -- wrote "geosite:…" and then
// asserted "geosite:" was there -- which made it a property of one literal.
//
// Third time in this family, and the class is worth stating: a test that supplies its own
// input cannot check a contract about what the rest of the program supplies. So this one
// runs a real startup and asserts against the configuration, which it did not write into
// the record.
func TestResourceNamesComeFromTheConfigurationAndNotFromTheTest(t *testing.T) {
	options := testOptions(t)
	if err := os.MkdirAll(options.WorkingPath, 0o755); err != nil {
		t.Fatal(err)
	}
	stageBundledGeodata(t, options.WorkingPath)
	options.MemoryLimit = 50 << 20
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	C.SetHomeDir(options.WorkingPath)
	previousDir := breadcrumbDirectory
	breadcrumbDirectory = options.WorkingPath
	t.Cleanup(func() {
		breadcrumbDirectory = previousDir
		setStartupBreadcrumbRecording(false)
		geodata.ClearGeoSiteCache()
	})

	// The name is never written by this test. GeoSiteCategoriesIn is production code
	// reading the reader's configuration; the loader is production code announcing what it
	// builds; the record is production code storing it. The test supplies a configuration
	// and checks the far end -- which is the correction, because the old version supplied
	// the value it then asserted.
	config := `mode: rule
proxies: []
dns:
  enable: true
  nameserver:
    - 223.5.5.5
  nameserver-policy:
    "geosite:private": [223.5.5.5]
rules:
  - MATCH,DIRECT
`
	named := GeoSiteCategoriesIn(config)
	if len(named) == 0 {
		t.Fatal("the configuration names no category, so this test would prove nothing")
	}

	// The parse installs the production reporter; nothing here replaces it.
	if _, err := parseConfigForIOS(config, true); err != nil {
		t.Fatalf("parse failed, so nothing below was measured: %v", err)
	}
	geodata.ClearGeoSiteCache()
	if _, err := geodata.LoadGeoSiteMatcher(named[0]); err != nil {
		t.Fatalf("loading a category the configuration named: %v", err)
	}

	var report map[string]any
	if err := json.Unmarshal([]byte(ExplainLastStartup()), &report); err != nil {
		t.Fatal(err)
	}
	resource, _ := report["resource"].(string)
	if resource == "" {
		t.Fatal("building a category the configuration named recorded no resource: the " +
			"client has nothing reader-facing to show, which is the whole finding")
	}
	// Compared against the EXTRACTED names, not against the raw YAML. strings.Contains on
	// the document accepts any substring of it, so a recorded "geosite:e" or "geosite:dns"
	// would have passed -- an assertion that cannot fail for a whole class of wrong answers
	// is not an assertion.
	bare := strings.TrimPrefix(strings.TrimPrefix(resource, "geosite:"), "geoip:")
	if !slices.Contains(named, bare) {
		t.Fatalf("recorded resource %q is not one of the categories the configuration "+
			"names (%v), so it is not something the reader wrote", resource, named)
	}
}

// stage stays internal and that is fine -- but it must not be mistaken for the reader
// facing one, so a step that is not about a resource must leave resource empty rather
// than carrying the previous one.
func TestAStepThatIsNotAboutAResourceClearsIt(t *testing.T) {
	breadcrumbHome(t)
	t.Cleanup(func() { setStartupBreadcrumbRecording(false) })

	recordStartupResource("geosite:cn")
	recordStartupStage("bind:providers-staged")

	var report map[string]any
	if err := json.Unmarshal([]byte(ExplainLastStartup()), &report); err != nil {
		t.Fatal(err)
	}
	if report["resource"] != "" && report["resource"] != nil {
		t.Fatalf("a later step still carries the previous resource, so the client would "+
			"say the tunnel died loading something it had already finished: %v", report)
	}
	if report["stage"] != "bind:providers-staged" {
		t.Fatalf("the internal stage was lost: %v", report)
	}
}

// The seam must fire when a matcher is BUILT, not when one is asked for.
//
// GEOSITE.MatchDomain (rules/common/geosite.go:34) and GEOIP.Match
// (rules/common/geoip.go:62,109,135) call the loaders on EVERY match -- upstream keeps the
// work behind singleflight precisely so a repeat call is a map lookup. A seam placed
// outside that singleflight turns every connection that evaluates a geo rule into a mutex,
// a file read, a cgo task_info, a JSON marshal, a file write and a rename, inside a
// process with 50 MiB.
//
// This is the test that was missing when it shipped.
func TestTheSeamDoesNotFireOnEveryMatch(t *testing.T) {
	home := breadcrumbHome(t)
	previous := progressReporterInstalled()
	fired := 0
	restoreProgressReporter(func(resource string) {
		fired++
		recordStartupResource(resource)
	})
	t.Cleanup(func() { restoreProgressReporter(previous) })

	geodata.ClearGeoIPCache()
	for i := 0; i < 5; i++ {
		_, _ = geodata.LoadGeoIPMatcher("cn")
	}
	if fired > 1 {
		t.Fatalf("the seam fired %d times for %d loads of one country: it sits outside the "+
			"singleflight, so it runs on every rule match rather than once per build", fired, 5)
	}
	_ = home
}

// A start that completes must leave nothing behind, or every launch after a NORMAL start
// reports a death that did not happen -- which is worse than the system sentence it
// replaces, because it is confidently wrong.
func TestASuccessfulStartLeavesNoDeathReport(t *testing.T) {
	breadcrumbHome(t)
	t.Cleanup(func() { setStartupBreadcrumbRecording(false) })

	recordStartupStage("bind:unmarshalled")
	recordStartupResource("geosite:cn")
	markStartupComplete()

	if explanation := ExplainLastStartup(); explanation != "" {
		t.Fatalf("a completed start still reports a death: %s", explanation)
	}
}

// A reinstall must not be greeted by the previous install's death.
//
// iOS keeps the App Group container across a reinstall -- that is the property profiles and
// provider payloads rely on -- and every path Core is given is built by the host from that
// container's URL, so all of them point inside it. A record written before the reinstall is
// therefore still there, still says completed:false, and reads exactly like one this install
// produced. A reader on a fresh install saw an account of a start that had never
// happened to them, which is the moment they are least equipped to disbelieve it.
func TestARecordFromAnotherInstallIsNotExplained(t *testing.T) {
	home := breadcrumbHome(t)

	recordStartupStage("bind:normalized")
	if ExplainLastStartup() == "" {
		t.Fatal("this install's own record was not returned")
	}

	// Rewrite it as some other install's, leaving every other field untouched -- the only
	// difference is the one thing that is supposed to matter.
	path := filepath.Join(home, breadcrumbFileName)
	var stored map[string]any
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(content, &stored); err != nil {
		t.Fatal(err)
	}
	if stored["install"] == nil || stored["install"] == "" {
		t.Fatal("the record carries no install identity, so nothing can tell installs apart")
	}
	stored["install"] = "some-other-install"
	rewritten, err := json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, rewritten, 0o644); err != nil {
		t.Fatal(err)
	}

	if explanation := ExplainLastStartup(); explanation != "" {
		t.Fatalf("explained a record another install wrote: %s", explanation)
	}
}

// A record with no install field can only predate this change, and by the time it ships the
// useful lifetime of any such record has passed.
func TestALegacyRecordWithoutAnInstallIsNotExplained(t *testing.T) {
	home := breadcrumbHome(t)
	legacy := `{"stage":"bind:normalized","resource":"","completed":false,` +
		`"footprintBytes":1,"budgetBytes":2,"startedAt":"x","updatedAt":"x"}`
	if err := os.WriteFile(filepath.Join(home, breadcrumbFileName), []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	if explanation := ExplainLastStartup(); explanation != "" {
		t.Fatalf("explained a record written before installs were identified: %s", explanation)
	}
}

// The identity reaches a reader's exported log, so it must not carry a filesystem path --
// on macOS that would be their home directory name.
func TestTheInstallIdentityIsNotAPath(t *testing.T) {
	identity := currentInstallIdentity()
	if identity == "" {
		t.Fatal("no install identity")
	}
	if strings.ContainsAny(identity, `/\`) || strings.Contains(identity, "..") {
		t.Fatalf("the install identity looks like a path: %q", identity)
	}
	if identity != currentInstallIdentity() {
		t.Fatal("the install identity changed between calls, so every launch would look like a reinstall")
	}
}

// Pressure is the kill's antechamber, and the record was sleeping through it: stages write
// only at their boundaries, so a kill mid-stage carried the footprint of the last boundary
// rather than the spend that killed. The pressure handler now rewrites the record once.
func TestCriticalPressureRefreshesTheRecordFootprint(t *testing.T) {
	breadcrumbHome(t)
	setStartupBreadcrumbRecording(true)
	t.Cleanup(func() { setStartupBreadcrumbRecording(false) })

	recordStartupStage("bind:providers-staged")
	// Age the stored footprint so a refresh is distinguishable from the original write.
	path := breadcrumbPath()
	stale, err := readBreadcrumb(path)
	if err != nil {
		t.Fatal(err)
	}
	stale.FootprintBytes = 1
	writeBreadcrumb(path, stale)

	refreshStartupBreadcrumbFootprint()

	refreshed, err := readBreadcrumb(path)
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.FootprintBytes <= 1 {
		t.Fatal("critical pressure did not refresh the record's footprint")
	}
	if refreshed.Stage != "bind:providers-staged" {
		t.Fatalf("the refresh lost the stage: %q", refreshed.Stage)
	}

	// And once startup has completed there is nothing to refresh -- the record is gone and
	// pressure must not resurrect it.
	markStartupComplete()
	refreshStartupBreadcrumbFootprint()
	if explanation := ExplainLastStartup(); explanation != "" {
		t.Fatalf("pressure after a completed start resurrected a record: %s", explanation)
	}
}

// A start that RETURNS an error is a different death from a kill: the process
// survives long enough to say why, and until now it said it to nobody -- the
// error went into NEVPNConnectionErrorDomain code=12 and the reader got "the
// VPN tunnel failed", naming nothing they could change. The record already on
// disk is the one place the reason survives, so the failing return stamps it
// there. Found via a real report: a phantom geosite category killed the
// extension before its first log line, and the reader had no way to learn
// which category or why.
func TestAFailingStartLeavesItsReasonInTheBreadcrumb(t *testing.T) {
	home := t.TempDir()
	previous := breadcrumbDirectory
	breadcrumbDirectory = home
	t.Cleanup(func() { breadcrumbDirectory = previous })
	setStartupBreadcrumbRecording(true)
	t.Cleanup(func() { setStartupBreadcrumbRecording(false) })

	recordStartupStage("bind:test-stage")
	recordStartupFailure(errAsIfFromStart("decode geodata file: list https not found"))

	explained := ExplainLastStartup()
	if explained == "" {
		t.Fatal("a failed start explains nothing")
	}
	var record struct {
		Completed     bool   `json:"completed"`
		FailureReason string `json:"failureReason"`
		Stage         string `json:"stage"`
	}
	if err := json.Unmarshal([]byte(explained), &record); err != nil {
		t.Fatalf("explanation does not decode: %v", err)
	}
	if record.Completed {
		t.Fatal("a failed start must not read as completed")
	}
	if !strings.Contains(record.FailureReason, "list https not found") {
		t.Fatalf("the reason did not survive: %q", record.FailureReason)
	}
	if record.Stage != "bind:test-stage" {
		t.Fatalf("the failure must keep the stage it happened in, got %q", record.Stage)
	}
}

// The wire itself: a real Start that fails must stamp the record without any
// caller remembering to. The defer covers every return path, which is the
// point -- the next failure mode will not be this one, and it must not need
// its own call site.
func TestStartWiresTheFailureIntoTheBreadcrumb(t *testing.T) {
	home := t.TempDir()
	previous := breadcrumbDirectory
	breadcrumbDirectory = home
	t.Cleanup(func() { breadcrumbDirectory = previous })
	// NOT pre-armed by the test: the pipeline arms recording itself when the
	// platform says packet tunnel (config_pipeline.go, normalize). That is the
	// wire under test -- a failure after arming must stamp without anyone
	// remembering to. The cleanup disarms because a failing Start leaves the
	// recorder on (in production that process is about to die; tests share one).
	t.Cleanup(func() { setStartupBreadcrumbRecording(false) })

	options := testOptions(t)
	if err := Setup(options); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	platform := newRecordingPlatform()
	platform.underNetworkExtension = true
	service, err := NewService(platform)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	t.Cleanup(func() { _ = service.Close() })

	startErr := service.Start("proxies:\n  - {name: A, type: not-a-real-protocol, server: e.test, port: 1}\n")
	if startErr == nil {
		t.Fatal("a config the kernel refuses must fail Start")
	}
	explained := ExplainLastStartup()
	if explained == "" {
		t.Fatal("the failing Start left no explanation")
	}
	var record struct {
		FailureReason string `json:"failureReason"`
	}
	if err := json.Unmarshal([]byte(explained), &record); err != nil {
		t.Fatalf("explanation does not decode: %v", err)
	}
	if record.FailureReason == "" {
		t.Fatal("the failing Start left an empty reason")
	}
	if !strings.Contains(startErr.Error(), record.FailureReason) &&
		!strings.Contains(record.FailureReason, "not-a-real-protocol") {
		t.Fatalf("the recorded reason %q does not correspond to the returned error %q",
			record.FailureReason, startErr)
	}
}

// errAsIfFromStart keeps the test honest about what it feeds: a plain error,
// exactly what Start returns.
func errAsIfFromStart(text string) error { return errors.New(text) }
