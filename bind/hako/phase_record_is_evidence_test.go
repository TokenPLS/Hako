package hako

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A phase marker must mean what a reader will take it to mean.
//
// On 2026-08-28 the macOS lane read a device record ending in
//
//	pre-config-parse → config-parsed
//	[mem] after parsing the configuration: 12.0 MiB
//
// and concluded the configuration had parsed. So did I. Both lines sit
// BEFORE the error branch and are emitted unconditionally, so their presence
// says only that the call returned -- not how. A whole round of device testing
// was attributed on that reading, and the attribution was wrong.
//
// The fix is not a comment. A phase whose name states an OUTCOME
// ("config-parsed") has to be emitted where that outcome is known, which means
// the failing side of the same decision needs its own marker -- otherwise the
// record has one word for two endings and a reader cannot tell which happened.
//
// This checks the pairing exists. It cannot check that a name is honest, which
// is why the list is written out: adding an outcome-shaped phase is a decision
// someone makes on purpose, and they have to name its counterpart here.
var outcomePhases = map[string]string{
	// outcome marker -> the marker its failing counterpart must carry
	"config-parsed": "config-refused",
}

func TestEveryOutcomePhaseHasAFailingCounterpart(t *testing.T) {
	source, err := os.ReadFile("service.go")
	if err != nil {
		t.Fatalf("cannot read service.go: %v", err)
	}
	body := string(source)

	emitted := map[string]bool{}
	for _, match := range regexp.MustCompile(`startupPhase\("([^"]+)"\)`).FindAllStringSubmatch(body, -1) {
		emitted[match[1]] = true
	}
	if len(emitted) == 0 {
		t.Fatal("found no startupPhase calls; the scan is broken, not the code")
	}

	for outcome, counterpart := range outcomePhases {
		if !emitted[outcome] {
			t.Errorf("phase %q is declared here as outcome-shaped but service.go no longer emits it; "+
				"drop the entry or rename it with its counterpart", outcome)
			continue
		}
		if !emitted[counterpart] {
			t.Errorf("phase %q says an outcome was reached, and nothing marks the other outcome. A record "+
				"ending at %q then reads as success to whoever finds it -- which is how a device round was "+
				"attributed wrongly. Emit %q where the failure is known.", outcome, outcome, counterpart)
		}
	}

	// The counterpart has to sit inside the failing branch, not merely exist.
	// A marker emitted beside its partner would restore the ambiguity while
	// looking like the fix.
	for outcome, counterpart := range outcomePhases {
		lines := strings.Split(body, "\n")
		for index, line := range lines {
			if !strings.Contains(line, `startupPhase("`+counterpart+`")`) {
				continue
			}
			// Skip back over comments and blank lines to the statement that
			// actually encloses this one. A fixed lookback of a few lines said
			// the marker was unguarded while it sat under fourteen lines of
			// comment inside the branch -- the gate crying wolf about correct
			// code, which is how gates get weakened until they stop working.
			guarded := false
			for back := index - 1; back >= 0; back-- {
				text := strings.TrimSpace(lines[back])
				if text == "" || strings.HasPrefix(text, "//") {
					continue
				}
				guarded = strings.Contains(text, "if err != nil")
				break
			}
			if !guarded {
				t.Errorf("service.go:%d emits %q outside a failure branch; it must mark the ending %q does "+
					"not, or the record is ambiguous again", index+1, counterpart, outcome)
			}
		}
	}
}

// The phase actually reaches the file a reader opens.
//
// The gate above pins that config-refused EXISTS beside config-parsed and sits
// inside the failure branch. That is a statement about the source. Whether the
// marker then arrives in hako-core-phases.log is a different question, and it
// took three wrong sinks to find the right one: ExplainLastStartup reads the
// breadcrumb, recordStartupStage writes the breadcrumb, and startupPhase writes
// setupStartupPhaseLogPath -- a third file. Asserting through the wrong one
// returned "not present" twice for a marker that was working.
//
// So this drives a real refusal and reads the file the device lane reads.
func TestARefusalReachesThePhaseLog(t *testing.T) {
	setupConfigPipelineTest(t)
	phaseLog := filepath.Join(t.TempDir(), "phases.log")
	previous := setupStartupPhaseLogPath
	setupStartupPhaseLogPath = phaseLog
	t.Cleanup(func() { setupStartupPhaseLogPath = previous })

	service, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	defer func() { _ = service.Close() }()

	if err := service.Start("proxies:\n  - {name: [unclosed\n"); err == nil {
		t.Fatal("Start accepted a document that is not yaml")
	}

	body, err := os.ReadFile(phaseLog)
	if err != nil {
		t.Fatalf("the phase log was never written: %v", err)
	}
	record := string(body)
	// The positive control first: if config-parsed is missing too, the phase
	// log is not being written at all and the absence below means nothing.
	if !strings.Contains(record, "config-parsed") {
		t.Fatalf("no phase reached the log, so this test measures nothing:\n%s", record)
	}
	if !strings.Contains(record, "config-refused") {
		t.Fatalf("a refused configuration left config-parsed in the record and nothing else, which is "+
			"exactly the reading that cost two lanes a night:\n%s", record)
	}
}
