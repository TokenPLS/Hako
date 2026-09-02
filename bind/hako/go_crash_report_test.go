package hako

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A Go panic or fatal throw inside the Network Extension currently leaves nothing to
// read afterwards, which is why nothing in the audit that produced this file can be
// confirmed or refuted from the field.
//
// The measured chain: gomobile builds Apple targets as a c-archive, so
// runtime.tracebackCrash is set and fatalpanic does reach crash() -> SIGABRT, and an
// .ips report IS produced. But Apple's frame-pointer unwinder cannot walk Go stacks:
// in a real report every thread terminates at runtime.asmcgocall.abi0, the string
// "panic" appears nowhere, and the only thing it says is that the Go runtime called
// raise(). Meanwhile the traceback itself goes to fd 2, and fd 2 in a
// system-launched app extension is /dev/null -- measured on three of them on this
// machine, one with 21 KB written into the void. So the comment at setup.go claiming
// "Darwin crash reports/OSLog remain authoritative for hard faults" is false for
// faults raised in Go code.
//
// debug.SetCrashOutput gives the runtime a second destination. Coverage is broader
// than panics: fatalthrow routes through the same crash path, so concurrent map
// writes, out-of-memory throws and slice-bounds faults land there too. Two things it
// cannot catch, deliberately not claimed anywhere: jetsam (SIGKILL, already covered
// by oom_evidence.go) and "all goroutines are asleep" (checkdead early-returns in
// archive builds).

func TestGoCrashOutputArchivesThePreviousRunBeforeTruncating(t *testing.T) {
	base := t.TempDir()
	live := filepath.Join(base, goCrashReportFileName)
	previous := filepath.Join(base, goCrashReportPreviousFileName)

	// A traceback left behind by a run that died.
	const traceback = "panic: hako internal diagnostics: intentional Go crash\n\ngoroutine 42 [running]:\n"
	if err := os.WriteFile(live, []byte(traceback), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := armGoCrashOutputAt(base); err != nil {
		t.Fatalf("armGoCrashOutputAt: %v", err)
	}
	t.Cleanup(func() { _ = disarmGoCrashOutput() })

	archived, err := os.ReadFile(previous)
	if err != nil {
		t.Fatalf("the previous run's traceback must be archived, not truncated: %v", err)
	}
	if string(archived) != traceback {
		t.Fatalf("archived traceback = %q, want it byte-identical", string(archived))
	}
	info, err := os.Stat(live)
	if err != nil {
		t.Fatalf("the live crash file must exist so the runtime has somewhere to write: %v", err)
	}
	if info.Size() != 0 {
		t.Fatalf("live crash file is %d bytes; it must start empty or a later reader cannot tell runs apart", info.Size())
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("live crash file mode = %o, want 600: a traceback carries file paths and function names", mode)
	}
}

func TestGoCrashOutputWithNoPreviousRunLeavesNoArchive(t *testing.T) {
	base := t.TempDir()

	if err := armGoCrashOutputAt(base); err != nil {
		t.Fatalf("armGoCrashOutputAt on a clean directory: %v", err)
	}
	t.Cleanup(func() { _ = disarmGoCrashOutput() })

	if _, err := os.Stat(filepath.Join(base, goCrashReportPreviousFileName)); !os.IsNotExist(err) {
		t.Fatalf("a clean first run must not leave an empty archive behind (err=%v)", err)
	}
}

// TestConsumeGoCrashReportReturnsAndRemoves mirrors ConsumeOOMEvidence: the report is
// handed over once and then deleted, so a corrupt or stale file cannot produce an
// endless startup loop and a traceback does not linger on the device forever.
func TestConsumeGoCrashReportReturnsAndRemoves(t *testing.T) {
	base := t.TempDir()
	previous := filepath.Join(base, goCrashReportPreviousFileName)
	const traceback = "panic: concurrent map writes\n\ngoroutine 7 [running]:\n"
	if err := os.WriteFile(previous, []byte(traceback), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := consumeGoCrashReportAt(base)
	if err != nil {
		t.Fatalf("consumeGoCrashReportAt: %v", err)
	}
	if report != traceback {
		t.Fatalf("report = %q, want %q", report, traceback)
	}
	if _, err := os.Stat(previous); !os.IsNotExist(err) {
		t.Fatal("the report must be removed once handed over")
	}

	if _, err := consumeGoCrashReportAt(base); !os.IsNotExist(err) {
		t.Fatalf("a second consume must report absence, got %v", err)
	}
}

// TestConsumeGoCrashReportTruncatesInsteadOfFailing is the difference from
// ConsumeOOMEvidence, and it is deliberate. OOM evidence is a fixed-shape JSON
// document, so oversize means corrupt and erroring is right. A traceback has no bound
// -- SetTraceback("all") dumps every goroutine -- and the panicking goroutine comes
// FIRST, so the head of an oversized file is the most valuable part of it. Refusing to
// read would throw away the answer to keep a rule.
func TestConsumeGoCrashReportTruncatesInsteadOfFailing(t *testing.T) {
	base := t.TempDir()
	previous := filepath.Join(base, goCrashReportPreviousFileName)

	head := "panic: runtime error: index out of range [5] with length 3\n\ngoroutine 1 [running]:\n"
	oversized := head + strings.Repeat("goroutine noise\n", goCrashReportMaxBytes)
	if err := os.WriteFile(previous, []byte(oversized), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := consumeGoCrashReportAt(base)
	if err != nil {
		t.Fatalf("an oversized traceback must be truncated, not rejected: %v", err)
	}
	if !strings.HasPrefix(report, head) {
		t.Fatal("the panicking goroutine comes first and must survive truncation")
	}
	if len(report) > goCrashReportMaxBytes+len(goCrashReportTruncationNotice) {
		t.Fatalf("report is %d bytes, want at most %d plus the notice",
			len(report), goCrashReportMaxBytes)
	}
	if !strings.HasSuffix(report, goCrashReportTruncationNotice) {
		t.Fatal("a truncated report must say so, or a reader will think the traceback ended there")
	}
	if _, err := os.Stat(previous); !os.IsNotExist(err) {
		t.Fatal("an oversized report must still be removed after being handed over")
	}
}

// TestRealPanicLandsInTheCrashFile is the assertion the other three cannot make: that
// the runtime actually writes there. It panics for real in a subprocess whose fd 2 is
// /dev/null -- exactly what a system-launched app extension has -- and reads the file
// back. If SetCrashOutput were not wired up, the traceback would be gone and this fails.
//
// The child exits 2 here rather than 134 because a test binary is not a c-archive, so
// runtime.tracebackCrash is unset and fatalpanic does not raise SIGABRT. The shipped
// xcframework IS a c-archive and does raise it. The capture works in both shapes, which
// is the point: it does not depend on which exit path the build happens to take.
func TestRealPanicLandsInTheCrashFile(t *testing.T) {
	if base := os.Getenv(crashProbeEnvironmentKey); base != "" {
		if err := armGoCrashOutputAt(base); err != nil {
			os.Exit(3)
		}
		panic(crashProbePanicMessage)
	}

	base := t.TempDir()
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()

	command := exec.Command(os.Args[0], "-test.run=TestRealPanicLandsInTheCrashFile")
	command.Env = append(os.Environ(), crashProbeEnvironmentKey+"="+base)
	command.Stdout = devNull
	command.Stderr = devNull
	if err := command.Run(); err == nil {
		t.Fatal("the child must have died; a surviving child proves nothing about crash capture")
	}

	data, err := os.ReadFile(filepath.Join(base, goCrashReportFileName))
	if err != nil {
		t.Fatalf("no crash file after a real panic with fd 2 discarded: %v", err)
	}
	report := string(data)
	for _, want := range []string{
		"panic: " + crashProbePanicMessage,
		"goroutine",
		"TestRealPanicLandsInTheCrashFile",
	} {
		if !strings.Contains(report, want) {
			t.Fatalf("crash file does not contain %q", want)
		}
	}
}

const (
	crashProbeEnvironmentKey = "HAKO_CRASH_PROBE_BASE"
	crashProbePanicMessage   = "hako crash probe: deliberate panic"
)
