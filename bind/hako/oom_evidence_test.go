package hako

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setupOOMEvidenceTest(t *testing.T) string {
	t.Helper()
	opts := testOptions(t)
	opts.MemoryLimit = 50 << 20
	if err := Setup(opts); err != nil {
		t.Fatal(err)
	}
	oomEvidenceLastWrite.Store(0)
	t.Cleanup(func() { oomEvidenceLastWrite.Store(0) })
	// The 50 MiB Setup armed a real monitor over the real test process, whose
	// footprint dwarfs that budget; with shedding the default it would close
	// trackers other tests register. Park it.
	t.Cleanup(func() { startPressureThresholdMonitor(0, pressureThresholdShedEnabled.Load()) })
	startPressureThresholdMonitor(0, pressureThresholdShedEnabled.Load())
	return filepath.Join(opts.BasePath, oomEvidenceFileName)
}

func TestOOMEvidenceRecordConsumeIsBoundedAndPrivate(t *testing.T) {
	path := setupOOMEvidenceTest(t)
	service, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	if err := service.Start(helloYAML); err != nil {
		t.Fatal(err)
	}
	if err := RecordMemoryPressureEvidence(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() <= 0 || info.Size() > oomEvidenceMaxBytes {
		t.Fatalf("evidence size = %d, limit %d", info.Size(), oomEvidenceMaxBytes)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("evidence mode = %o, want 600", info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"config", "domain", "hostname", "source", "destination", "address",
		"credential", "password", "secret", "log", "rule", "proxy", "outboundName",
	} {
		if strings.Contains(strings.ToLower(string(raw)), strings.ToLower(forbidden)) {
			t.Fatalf("evidence contains forbidden field/content %q: %s", forbidden, raw)
		}
	}

	box, err := ConsumeOOMEvidence()
	if err != nil {
		t.Fatal(err)
	}
	var report oomEvidence
	if err := json.Unmarshal([]byte(box.Value), &report); err != nil {
		t.Fatal(err)
	}
	if report.SchemaVersion != oomEvidenceSchemaVersion || report.PressureLevel != "critical" || !report.PossibleSystemKill {
		t.Fatalf("invalid consumed evidence: %#v", report)
	}
	if report.CoreState != "running" || report.CoreStartTimeUnix <= 0 || report.OutboundCount <= 0 {
		t.Fatalf("missing non-sensitive core state: %#v", report)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("consumed evidence still exists: %v", err)
	}
}

func TestOOMEvidenceConsumeRejectsAndRemovesCorruptOrOversizedFiles(t *testing.T) {
	path := setupOOMEvidenceTest(t)
	tests := [][]byte{
		[]byte("not-json"),
		[]byte(`{"schemaVersion":1,"pressureLevel":"critical","possibleSystemKill":true} trailing`),
		bytes.Repeat([]byte("x"), oomEvidenceMaxBytes+1),
	}
	for index, content := range tests {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ConsumeOOMEvidence(); err == nil {
			t.Fatalf("corrupt case %d succeeded", index)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("corrupt case %d was not removed: %v", index, err)
		}
	}
}

func TestOOMEvidenceAtomicFailurePreservesPreviousReport(t *testing.T) {
	path := setupOOMEvidenceTest(t)
	previous := []byte("previous-valid-sentinel")
	if err := os.WriteFile(path, previous, 0o600); err != nil {
		t.Fatal(err)
	}
	report := oomEvidence{
		SchemaVersion:      oomEvidenceSchemaVersion,
		PressureLevel:      "critical",
		PossibleSystemKill: true,
	}
	wantErr := errors.New("injected rename failure")
	err := writeOOMEvidenceAt(path, report, func(string, string) error { return wantErr })
	if !errors.Is(err, wantErr) {
		t.Fatalf("write error = %v, want injected failure", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, previous) {
		t.Fatalf("failed atomic write replaced previous evidence: %q", got)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temporary evidence leaked: %v", err)
	}
}

func TestOOMEvidenceCriticalWritesAreRateLimited(t *testing.T) {
	path := setupOOMEvidenceTest(t)
	if err := RecordMemoryPressureEvidence(); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := RecordMemoryPressureEvidence(); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("rate-limited pressure callback rewrote evidence")
	}
}
