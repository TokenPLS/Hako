package hako

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/sirupsen/logrus"
)

func readEvidenceFile(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read evidence: %v", err)
	}
	var record map[string]any
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatalf("decode evidence %s: %v", raw, err)
	}
	return record
}

// A reload that dies leaves nothing behind: the pressure callback that writes the OOM
// evidence never fires when the process is killed 116 ms into building the second core. So
// the reload writes its own line into that same file before it parses -- phase, when it
// started, what the judge computed -- and takes the line back when it finishes. If the
// process is gone at the next start, the App reads what it was doing when it died, and the
// judge's estimate gets its one piece of feedback: an accepted reload that still died.
func TestReloadEvidenceMarkerLifecycle(t *testing.T) {
	path := setupOOMEvidenceTest(t)
	verdict := reloadMemoryVerdict{Reason: reloadAccepted, NeededBytes: 9 * testMiB, AvailableBytes: 36 * testMiB, FootprintBytes: 14 * testMiB}

	ticket := beginReloadEvidence(verdict)
	record := readEvidenceFile(t, path)
	if record["schemaVersion"] != float64(3) {
		t.Fatalf("schemaVersion = %v, want 3", record["schemaVersion"])
	}
	if record["pressureLevel"] != "reload" || record["possibleSystemKill"] != true {
		t.Fatalf("a marker is a possible-kill record at level reload, got %v / %v", record["pressureLevel"], record["possibleSystemKill"])
	}
	if record["reloadPhase"] != "parse" {
		t.Fatalf("reloadPhase = %v, want parse", record["reloadPhase"])
	}
	if started, _ := record["reloadStartedUnix"].(float64); started <= 0 {
		t.Fatalf("reloadStartedUnix = %v, want a timestamp", record["reloadStartedUnix"])
	}
	if record["reloadNeededBytes"] != float64(9*testMiB) || record["reloadAvailableBytes"] != float64(36*testMiB) {
		t.Fatalf("the marker must carry the judge's numbers, got %v / %v", record["reloadNeededBytes"], record["reloadAvailableBytes"])
	}
	if physical, _ := record["physicalMemoryBytes"].(float64); physical != float64(14*testMiB) {
		t.Fatalf("physicalMemoryBytes = %v, want the footprint the judge saw", record["physicalMemoryBytes"])
	}

	advanceReloadEvidence(ticket, reloadPhaseApply)
	if record := readEvidenceFile(t, path); record["reloadPhase"] != "apply" {
		t.Fatalf("after advancing, reloadPhase = %v, want apply", record["reloadPhase"])
	}

	endReloadEvidence(ticket)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("a finished reload must take its marker back, stat err = %v", err)
	}
}

// Evidence already on disk is worth more than a marker: it is either a pressure record the App
// has not consumed yet or a previous reload's death. The marker never overwrites it, and
// finishing does not remove it.
func TestReloadEvidenceMarkerNeverOverwritesEvidenceAlreadyOnDisk(t *testing.T) {
	path := setupOOMEvidenceTest(t)
	if err := RecordMemoryPressureEvidence(); err != nil {
		t.Fatal(err)
	}
	ticket := beginReloadEvidence(reloadMemoryVerdict{Reason: reloadAccepted, NeededBytes: 1, AvailableBytes: 2})
	if record := readEvidenceFile(t, path); record["pressureLevel"] != "critical" {
		t.Fatalf("the marker overwrote a pressure record: %v", record)
	}
	endReloadEvidence(ticket)
	if record := readEvidenceFile(t, path); record["pressureLevel"] != "critical" {
		t.Fatalf("finishing removed a pressure record it did not write: %v", record)
	}
}

// A pressure record written while a reload is running wins, and it says what the reload was
// doing -- that is the attribution the callback could give when it does fire.
func TestReloadEvidenceMarkerYieldsToAPressureRecordWrittenMeanwhile(t *testing.T) {
	path := setupOOMEvidenceTest(t)
	ticket := beginReloadEvidence(reloadMemoryVerdict{Reason: reloadAccepted, NeededBytes: 5 * testMiB, AvailableBytes: 30 * testMiB})
	advanceReloadEvidence(ticket, reloadPhaseApply)
	if err := RecordMemoryPressureEvidence(); err != nil {
		t.Fatal(err)
	}
	record := readEvidenceFile(t, path)
	if record["pressureLevel"] != "critical" {
		t.Fatalf("a pressure record must replace the marker, got %v", record["pressureLevel"])
	}
	if record["reloadPhase"] != "apply" || record["reloadNeededBytes"] != float64(5*testMiB) {
		t.Fatalf("a pressure record during a reload must say what the reload was doing, got %v", record)
	}
	endReloadEvidence(ticket)
	if record := readEvidenceFile(t, path); record["pressureLevel"] != "critical" {
		t.Fatalf("finishing must leave the pressure record alone, got %v", record)
	}
}

// The App consumes the marker through the same door as a pressure record -- but only a DEAD
// reload's marker is evidence. On the launch after a kill the new process has no reload in
// flight, so the marker on disk is consumable; abandonReloadEvidenceStateForTest models that
// next launch. While the reload that wrote it is still alive in this process, the marker is
// working state, not evidence: consuming it would tell the App a previous extension died while
// the reload is right here running, and would strip the tombstone from a build that may yet be
// the thing that kills the process (adversarial review, round 2).
func TestConsumeOOMEvidenceAcceptsAReloadMarkerOnlyOnceItsReloadIsDead(t *testing.T) {
	path := setupOOMEvidenceTest(t)
	beginReloadEvidence(reloadMemoryVerdict{Reason: reloadAccepted, NeededBytes: 1, AvailableBytes: 2})

	// Alive: the marker is not evidence yet, and stays where it is.
	if consumed, err := ConsumeOOMEvidence(); err == nil {
		t.Fatalf("a live reload's marker must not be consumable, got %s", consumed.Value)
	} else if !os.IsNotExist(err) {
		t.Fatalf("a live marker must read as no-evidence (IsNotExist), got %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the live marker must still be on disk, stat err = %v", err)
	}

	// Dead: the next launch (fresh in-process state) consumes it through the same door.
	abandonReloadEvidenceStateForTest()
	consumed, err := ConsumeOOMEvidence()
	if err != nil {
		t.Fatalf("ConsumeOOMEvidence: %v", err)
	}
	var record map[string]any
	if err := json.Unmarshal([]byte(consumed.Value), &record); err != nil {
		t.Fatal(err)
	}
	if record["pressureLevel"] != "reload" || record["reloadPhase"] != "parse" {
		t.Fatalf("consumed marker = %v", record)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("consuming must remove the file, stat err = %v", err)
	}
}

// markerWatchingPlatform snapshots whether the marker is on disk at the moment the reload asks
// the platform about its environment -- which happens after the judge and before the parse.
type markerWatchingPlatform struct {
	*recordingPlatform
	path        string
	markerAtAsk bool
	askedForNE  int
	phaseAtAsk  string
}

func (p *markerWatchingPlatform) UnderNetworkExtension() bool {
	p.askedForNE++
	if raw, err := os.ReadFile(p.path); err == nil {
		p.markerAtAsk = true
		var record map[string]any
		_ = json.Unmarshal(raw, &record)
		p.phaseAtAsk, _ = record["reloadPhase"].(string)
	}
	return p.recordingPlatform.UnderNetworkExtension()
}

// The service-level shape: while a reload runs its marker is on disk, and once it has
// finished -- well or badly -- the marker is gone.
func TestReloadKeepsItsMarkerOnDiskOnlyWhileItRuns(t *testing.T) {
	t.Cleanup(func() { logrus.SetOutput(os.Stdout) })
	path := setupOOMEvidenceTest(t)
	platform := &markerWatchingPlatform{recordingPlatform: newRecordingPlatform(), path: path}
	svc, err := NewService(platform)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	if err := svc.Start(helloYAML); err != nil {
		t.Fatalf("Start: %v", err)
	}
	platform.markerAtAsk, platform.askedForNE = false, 0

	if err := svc.Reload(helloYAML + "\n"); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if platform.askedForNE == 0 {
		t.Fatal("the probe never fired; the reload did not ask the platform about its environment")
	}
	if !platform.markerAtAsk || platform.phaseAtAsk != "parse" {
		t.Fatalf("the marker must be on disk, in phase parse, when the reload starts building; saw marker=%v phase=%q", platform.markerAtAsk, platform.phaseAtAsk)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("after a successful reload the marker must be gone, stat err = %v", err)
	}

	// A reload that fails after the judge -- unparsable YAML -- takes its marker back too.
	platform.markerAtAsk = false
	if err := svc.Reload("mode: [broken"); err == nil {
		t.Fatal("broken YAML must fail")
	}
	if !platform.markerAtAsk {
		t.Fatal("the marker must be on disk before the parse even when the parse fails")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("after a failed reload the marker must be gone, stat err = %v", err)
	}
}
