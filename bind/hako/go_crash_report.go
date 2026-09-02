package hako

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"sync"
)

const (
	goCrashReportFileName         = "go-crash.log"
	goCrashReportPreviousFileName = "go-crash.previous.log"

	// goCrashReportMaxBytes bounds what is handed to the client, not what the
	// runtime writes -- the runtime writes without asking. 128 KiB is far more than
	// the panicking goroutine and its creator need, and the head of the file is the
	// part that matters, so oversize is truncated rather than rejected.
	goCrashReportMaxBytes = 128 << 10

	goCrashReportTruncationNotice = "\n[hako: traceback truncated]\n"
)

var goCrashReportMu sync.Mutex

// armGoCrashOutputAt points the Go runtime's crash output at a file under basePath,
// after moving any traceback the previous run left there out of the way.
//
// Why this is needed at all: the runtime writes its traceback to fd 2, and fd 2 in a
// system-launched app extension is /dev/null -- measured, not assumed. An .ips report
// IS still produced, because gomobile builds Apple targets as a c-archive and so
// fatalpanic reaches crash(), but Apple's frame-pointer unwinder cannot walk Go
// stacks: every thread in the report terminates at runtime.asmcgocall.abi0 and the
// word "panic" does not appear. The .ips tells you the Go runtime called raise() and
// nothing else.
//
// The file is 0600 and stays inside the App Group. A traceback carries source paths
// and function names, and a panic value can carry whatever was passed to panic(), so
// it is diagnostic material the user shares deliberately -- never something to send
// anywhere on its own initiative.
//
// Closing the file immediately after SetCrashOutput is safe and intentional:
// SetCrashOutput dups the descriptor, so the runtime keeps its own and this process
// does not hold an extra open handle for the lifetime of the extension.
func armGoCrashOutputAt(basePath string) error {
	goCrashReportMu.Lock()
	defer goCrashReportMu.Unlock()

	if basePath == "" {
		return errors.New("hako: Go crash output needs a base path")
	}
	if err := os.MkdirAll(basePath, 0o755); err != nil {
		return fmt.Errorf("hako: create Go crash output directory: %w", err)
	}

	live := filepath.Join(basePath, goCrashReportFileName)
	previous := filepath.Join(basePath, goCrashReportPreviousFileName)

	// Archive before truncating. Without this the act of arming would destroy the
	// evidence from the run that actually crashed, which is the only run anyone
	// wants to read about. A missing live file is the normal first-launch case.
	if info, err := os.Stat(live); err == nil && info.Size() > 0 {
		if err := os.Rename(live, previous); err != nil {
			return fmt.Errorf("hako: archive previous Go crash output: %w", err)
		}
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("hako: stat Go crash output: %w", err)
	} else if err == nil {
		// Present but empty: the previous run exited without crashing. Nothing to
		// keep, and leaving an empty archive behind would look like a crash report.
		_ = os.Remove(live)
	}

	file, err := os.OpenFile(live, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("hako: open Go crash output: %w", err)
	}
	defer file.Close()

	if err := debug.SetCrashOutput(file, debug.CrashOptions{}); err != nil {
		return fmt.Errorf("hako: set Go crash output: %w", err)
	}
	return nil
}

// disarmGoCrashOutput detaches the runtime from the file. Used by tests so one test's
// crash file cannot outlive its temporary directory; the extension never calls it.
func disarmGoCrashOutput() error {
	goCrashReportMu.Lock()
	defer goCrashReportMu.Unlock()
	return debug.SetCrashOutput(nil, debug.CrashOptions{})
}

// consumeGoCrashReportAt returns the traceback left by the previous run and removes it,
// so it is handed over exactly once. Same contract as ConsumeOOMEvidence, with one
// deliberate difference: an oversized file is truncated rather than rejected. OOM
// evidence is a fixed-shape JSON document where oversize means corrupt, but a traceback
// has no bound -- SetTraceback("all") dumps every goroutine -- and the panicking
// goroutine is written first, so the head of an oversized file is the answer. Refusing
// to read it would discard the answer in order to keep a rule.
func consumeGoCrashReportAt(basePath string) (string, error) {
	goCrashReportMu.Lock()
	defer goCrashReportMu.Unlock()

	if basePath == "" {
		return "", errors.New("hako: Go crash report needs a base path")
	}
	path := filepath.Join(basePath, goCrashReportPreviousFileName)

	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	info, statErr := file.Stat()
	if statErr == nil && !info.Mode().IsRegular() {
		_ = file.Close()
		_ = os.Remove(path)
		return "", errors.New("hako: Go crash report is not a regular file")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, goCrashReportMaxBytes+1))
	_ = file.Close()

	// Removed whatever happened next: a file that cannot be read is a file that would
	// otherwise be retried forever.
	if removeErr := os.Remove(path); removeErr != nil && readErr == nil {
		return "", fmt.Errorf("hako: remove Go crash report: %w", removeErr)
	}
	if readErr != nil {
		return "", fmt.Errorf("hako: read Go crash report: %w", readErr)
	}

	if len(data) > goCrashReportMaxBytes {
		return string(data[:goCrashReportMaxBytes]) + goCrashReportTruncationNotice, nil
	}
	return string(data), nil
}

// ConsumeGoCrashReport hands the previous run's Go traceback to the client once, or
// reports that there was none. Exported for the Extension/App boundary, mirroring
// ConsumeOOMEvidence.
func ConsumeGoCrashReport() (*StringBox, error) {
	basePath, err := goCrashReportBasePath()
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	report, err := consumeGoCrashReportAt(basePath)
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return WrapString(report), nil
}

func goCrashReportBasePath() (string, error) {
	setupMu.Lock()
	defer setupMu.Unlock()
	if !setupDone || setupGoCrashReportBasePath == "" {
		return "", errors.New("hako: Go crash report before Setup")
	}
	return setupGoCrashReportBasePath, nil
}
