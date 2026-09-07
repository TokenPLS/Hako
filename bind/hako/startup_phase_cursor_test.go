package hako

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type phasePageEvidence struct {
	SchemaVersion int    `json:"schemaVersion"`
	Status        string `json:"status"`
	Epoch         string `json:"epoch"`
	From          int64  `json:"from"`
	Next          int64  `json:"next"`
	Head          int64  `json:"head"`
	BeginCursor   string `json:"beginCursor"`
	NextCursor    string `json:"nextCursor"`
	HeadCursor    string `json:"headCursor"`
	Records       []struct {
		Sequence int64  `json:"sequence"`
		Line     string `json:"line"`
	} `json:"records"`
	Diagnostic struct {
		Revision       int64  `json:"revision"`
		Path           string `json:"path"`
		Error          string `json:"error"`
		RecordSequence int64  `json:"recordSequence"`
	} `json:"diagnostic"`
}

func readPhasePage(t testing.TB, cursor string, budget int64) phasePageEvidence {
	t.Helper()
	var page phasePageEvidence
	if err := json.Unmarshal([]byte(StartupPhaseTracePage(cursor, "", budget)), &page); err != nil {
		t.Fatal(err)
	}
	if page.SchemaVersion != 1 {
		t.Fatalf("schema = %d", page.SchemaVersion)
	}
	return page
}

func isolatePhaseCursor(t testing.TB) {
	t.Helper()
	phaseMu.Lock()
	saved := append([]string(nil), phaseTrace...)
	phaseTrace = nil
	oldPath := setupStartupPhaseLogPath
	phaseMu.Unlock()
	configureStartupPhaseLogPath("")
	t.Cleanup(func() {
		phaseMu.Lock()
		phaseTrace = saved
		phaseMu.Unlock()
		configureStartupPhaseLogPath(oldPath)
	})
}

func appendPhaseCursorFixture(lines ...string) {
	phaseMu.Lock()
	phaseTrace = append(phaseTrace, lines...)
	phaseMu.Unlock()
}

func TestStartupPhasePageIndependentConsumersAndRecordIdentity(t *testing.T) {
	isolatePhaseCursor(t)
	start := readPhasePage(t, "", 0)
	appendPhaseCursorFixture("same\nlogical event", "same\nlogical event")
	first := readPhasePage(t, start.NextCursor, 65536)
	second := readPhasePage(t, start.NextCursor, 65536)
	if first.Status != "ok" || first.Next != 2 || len(first.Records) != 2 {
		t.Fatalf("first = %+v", first)
	}
	if first.Records[0].Sequence != 1 || first.Records[1].Sequence != 2 || first.Records[0].Line != first.Records[1].Line {
		t.Fatal("record identity was derived from text or line count")
	}
	if first.NextCursor != second.NextCursor || len(second.Records) != 2 {
		t.Fatal("reader consumed another reader's history")
	}
	if StartupPhaseTrace() != "same\nlogical event\nsame\nlogical event" {
		t.Fatal("legacy trace changed")
	}
	empty := readPhasePage(t, first.NextCursor, 65536)
	if empty.Status != "ok" || len(empty.Records) != 0 || empty.NextCursor != first.NextCursor {
		t.Fatalf("empty = %+v", empty)
	}
}

func TestStartupPhasePageCaptureBeforeSetupBoundary(t *testing.T) {
	isolatePhaseCursor(t)
	appendPhaseCursorFixture("earlier launch")
	start := readPhasePage(t, "", 65536)
	if start.Next != 1 || len(start.Records) != 0 {
		t.Fatal("empty cursor must capture tail only")
	}
	startupPhase("setup:before-path")
	configureStartupPhaseLogPath(filepath.Join(t.TempDir(), "phase.log"))
	startupPhase("setup:after-path")
	page := readPhasePage(t, start.NextCursor, 65536)
	if page.Epoch != start.Epoch || page.Next != 3 || len(page.Records) != 2 {
		t.Fatalf("page = %+v", page)
	}
	if !strings.Contains(page.Records[0].Line, "setup:before-path") {
		t.Fatal("lost pre-path phase")
	}
	restarted := readPhasePage(t, "", 0)
	startupPhase("next launch")
	next := readPhasePage(t, restarted.NextCursor, 65536)
	if len(next.Records) != 1 || next.Records[0].Sequence != 4 {
		t.Fatalf("restart replay = %+v", next)
	}
	all := readPhasePage(t, start.BeginCursor, 65536)
	if len(all.Records) != 4 {
		t.Fatal("legacy history was reset")
	}
}

func TestStartupPhasePageRejectsInvalidCursorsAndBudgets(t *testing.T) {
	isolatePhaseCursor(t)
	head := readPhasePage(t, "", 0)
	for _, tc := range []struct {
		cursor string
		budget int64
		status string
	}{
		{"broken", 1024, "invalidCursor"},
		{head.Epoch + ":-1", 1024, "invalidCursor"},
		{head.Epoch + ":01", 1024, "invalidCursor"},
		{head.Epoch + ":18446744073709551616", 1024, "invalidCursor"},
		{strings.Repeat("0", 32) + ":0", 1024, "epochMismatch"},
		{head.Epoch + ":1", 1024, "cursorAhead"},
		{head.NextCursor, -1, "invalidBudget"},
	} {
		t.Run(tc.status+"/"+tc.cursor, func(t *testing.T) {
			page := readPhasePage(t, tc.cursor, tc.budget)
			if page.Status != tc.status || len(page.Records) != 0 {
				t.Fatalf("got %+v", page)
			}
		})
	}
}

func TestStartupPhasePageJSONBudgetAndOversizeDoNotSkip(t *testing.T) {
	isolatePhaseCursor(t)
	start := readPhasePage(t, "", 0)
	appendPhaseCursorFixture(strings.Repeat("\"\\\n", 150), strings.Repeat("tail", 100))
	small := readPhasePage(t, start.NextCursor, 1024)
	if small.Status != "recordTooLarge" || small.NextCursor != start.NextCursor || len(small.Records) != 0 {
		t.Fatalf("small = %+v", small)
	}
	page := readPhasePage(t, start.NextCursor, 1536)
	bytes, _ := json.Marshal(page.Records)
	if len(bytes) > 1536 || len(page.Records) != 1 || page.Next != 1 {
		t.Fatalf("budget = %d, page=%+v", len(bytes), page)
	}
	rest := readPhasePage(t, page.NextCursor, 1536)
	if len(rest.Records) != 1 || rest.Records[0].Line != strings.Repeat("tail", 100) {
		t.Fatalf("tail = %+v", rest)
	}
	meta := readPhasePage(t, start.NextCursor, 0)
	if len(meta.Records) != 0 || meta.NextCursor != start.NextCursor || meta.Head != 2 {
		t.Fatalf("metadata advanced = %+v", meta)
	}
}

func TestStartupPhasePageLimitsRecordsAndFixedHead(t *testing.T) {
	isolatePhaseCursor(t)
	start := readPhasePage(t, "", 0)
	for i := 0; i < 300; i++ {
		appendPhaseCursorFixture(fmt.Sprint(i))
	}
	first := readPhasePage(t, start.NextCursor, 1<<30)
	if len(first.Records) != 256 || first.Head != 300 || first.Next != 256 {
		t.Fatalf("first = %+v", first)
	}
	appendPhaseCursorFixture("later")
	second := readPhasePage(t, first.NextCursor, 65536)
	if len(second.Records) != 45 || second.Head != 301 || second.Records[43].Sequence != 300 {
		t.Fatal("cannot finish against captured head")
	}
	if first.HeadCursor != start.Epoch+":300" {
		t.Fatal("head did not identify fixed tail")
	}
}

func TestStartupPhasePageReportsWriteFailureAndPathRevision(t *testing.T) {
	isolatePhaseCursor(t)
	before := readPhasePage(t, "", 0)
	bad := filepath.Join(t.TempDir(), "missing", "phase.log")
	configureStartupPhaseLogPath(bad)
	startupPhase("cannot-write")
	failed := readPhasePage(t, before.NextCursor, 65536)
	if failed.Status != "ok" || len(failed.Records) != 1 || failed.Diagnostic.Error == "" || failed.Diagnostic.RecordSequence != 1 || failed.Diagnostic.Revision <= before.Diagnostic.Revision {
		t.Fatalf("missing failure = %+v", failed)
	}
	if !strings.Contains(StartupPhaseDiagnostic(), failed.Diagnostic.Error) {
		t.Fatal("legacy diagnostic lost error")
	}
	good := filepath.Join(t.TempDir(), "phase.log")
	configureStartupPhaseLogPath(good)
	startupPhase("written")
	goodPage := readPhasePage(t, failed.NextCursor, 65536)
	if goodPage.Diagnostic.Path != good || goodPage.Diagnostic.Error != "" || goodPage.Diagnostic.Revision <= failed.Diagnostic.Revision {
		t.Fatalf("path change = %+v", goodPage)
	}
	body, err := os.ReadFile(good)
	if err != nil || !strings.Contains(string(body), "go-phase=written") {
		t.Fatalf("real sink = %q, %v", body, err)
	}
}

func TestStartupPhasePageConcurrentDiagnosticsAndProduction(t *testing.T) {
	isolatePhaseCursor(t)
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			cursor := ""
			for i := 0; i < 100; i++ {
				switch worker {
				case 0:
					startupPhase("parallel")
				case 1:
					configureStartupPhaseLogPath("")
				case 2:
					_ = StartupPhaseDiagnostic()
				case 3:
					var page phasePageEvidence
					if err := json.Unmarshal([]byte(StartupPhaseTracePage(cursor, "", 1024)), &page); err != nil {
						t.Error(err)
						return
					}
					if page.Status != "ok" {
						t.Errorf("status=%s", page.Status)
						return
					}
					cursor = page.NextCursor
				}
			}
		}(worker)
	}
	wg.Wait()
}

func BenchmarkStartupPhasePageEmptyTail(b *testing.B) {
	for _, size := range []int{0, 50000} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			isolatePhaseCursor(b)
			for i := 0; i < size; i++ {
				appendPhaseCursorFixture(strings.Repeat("phase", 40))
			}
			cursor := readPhasePage(b, "", 0).NextCursor
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = StartupPhaseTracePage(cursor, "", 65536)
			}
		})
	}
}

func TestStartupPhasePageFixedThroughExcludesNewProduction(t *testing.T) {
	isolatePhaseCursor(t)
	start := readPhasePage(t, "", 0)
	appendPhaseCursorFixture("a", "b")
	bound := readPhasePage(t, "", 0).HeadCursor
	appendPhaseCursorFixture("new launch")
	var page phasePageEvidence
	if err := json.Unmarshal([]byte(StartupPhaseTracePage(start.NextCursor, bound, 65536)), &page); err != nil {
		t.Fatal(err)
	}
	if page.Status != "ok" || page.Next != 2 || len(page.Records) != 2 {
		t.Fatalf("crossed through: %+v", page)
	}
	for _, tc := range []struct{ from, through, status string }{
		{bound, start.NextCursor, "invalidRange"},
		{start.NextCursor, start.Epoch + ":4", "cursorAhead"},
		{start.NextCursor, strings.Repeat("0", 32) + ":0", "epochMismatch"},
	} {
		if err := json.Unmarshal([]byte(StartupPhaseTracePage(tc.from, tc.through, 65536)), &page); err != nil {
			t.Fatal(err)
		}
		if page.Status != tc.status {
			t.Fatalf("range status: %+v", page)
		}
	}
}

func TestStartupPhasePageTotalEncodedBudget(t *testing.T) {
	isolatePhaseCursor(t)
	start := readPhasePage(t, "", 0)
	for i := 0; i < 100; i++ {
		appendPhaseCursorFixture(strings.Repeat("\t\n<>&", 40))
	}
	cursor := start.NextCursor
	seen := 0
	for seen < 100 {
		body := StartupPhaseTracePage(cursor, "", 1536)
		if len(body) > 1536 {
			t.Fatalf("response bytes=%d", len(body))
		}
		var page phasePageEvidence
		if err := json.Unmarshal([]byte(body), &page); err != nil {
			t.Fatal(err)
		}
		if page.Status != "ok" || len(page.Records) == 0 {
			t.Fatalf("no progress: %+v", page)
		}
		seen += len(page.Records)
		cursor = page.NextCursor
	}
	configureStartupPhaseLogPath(strings.Repeat("x", 10000))
	body := StartupPhaseTracePage(cursor, "", 1024)
	if len(body) > 1024 || !strings.Contains(body, "metadataTooLarge") {
		t.Fatal("unbounded diagnostic metadata")
	}
}

type phaseWriteFault struct {
	written  int
	writeErr error
	closeErr error
	closes   int
}

func (w *phaseWriteFault) Write(p []byte) (int, error) { return w.written, w.writeErr }
func (w *phaseWriteFault) Close() error                { w.closes++; return w.closeErr }

func TestStartupPhaseFileFailuresAreReportedWithoutRetry(t *testing.T) {
	for _, tc := range []struct {
		name               string
		count              int
		writeErr, closeErr error
		want               string
	}{
		{"success", 4, nil, nil, ""},
		{"short", 2, nil, nil, "short write"},
		{"write", 0, fmt.Errorf("write fault"), nil, "write fault"},
		{"close", 4, nil, fmt.Errorf("close fault"), "close fault"},
		{"both", 2, fmt.Errorf("write fault"), fmt.Errorf("close fault"), "write: write fault; close: close fault"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sink := &phaseWriteFault{written: tc.count, writeErr: tc.writeErr, closeErr: tc.closeErr}
			err := writeStartupPhaseRecord(sink, "abc\n")
			if sink.closes != 1 {
				t.Fatalf("closes=%d", sink.closes)
			}
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v, want %s", err, tc.want)
			}
		})
	}
}

func TestStartupPhaseLateFileFailureCannotReplaceNewPathDiagnostic(t *testing.T) {
	isolatePhaseCursor(t)
	configureStartupPhaseLogPath("same path")
	phaseMu.Lock()
	retired := phaseLogGeneration
	phaseMu.Unlock()
	configureStartupPhaseLogPath("same path")
	before := readPhasePage(t, "", 0)
	recordStartupPhaseFailure(retired, 1, fmt.Errorf("retired write"))
	after := readPhasePage(t, "", 0)
	if after.Diagnostic.Revision != before.Diagnostic.Revision || after.Diagnostic.Error != "" {
		t.Fatalf("retired error adopted: %+v", after)
	}
}

func TestStartupPhasePageRejectsUnboundedInputWithoutEcho(t *testing.T) {
	isolatePhaseCursor(t)
	huge := strings.Repeat("cursor", 100000)
	body := StartupPhaseTracePage(huge, "", 1024)
	if len(body) > 1024 || !strings.Contains(body, "invalidCursor") {
		t.Fatal("invalid input was echoed")
	}
	body = StartupPhaseTracePage("", "", 1)
	if len(body) > 1024 || !strings.Contains(body, "invalidBudget") {
		t.Fatal("invalid budget was accepted")
	}
}

func TestStartupPhasePageRepairsLongInvalidUTF8BeforeSizing(t *testing.T) {
	isolatePhaseCursor(t)
	start := readPhasePage(t, "", 0)
	raw := strings.Repeat(string([]byte{0xff}), 65570) + "tail"
	appendPhaseCursorFixture(raw)
	page := readPhasePage(t, start.NextCursor, 1024)
	if page.Status != "ok" || page.Next != 1 || len(page.Records) != 1 {
		t.Fatalf("repairable record blocked cursor: %+v", page)
	}
	if page.Records[0].Line != bridgeSafeString(raw) {
		t.Fatal("encoding repair changed valid content")
	}
}

func TestStartupPhasePageRepairsBoundedMetadata(t *testing.T) {
	isolatePhaseCursor(t)
	raw := strings.Repeat(string([]byte{0xff}), 65570)
	configureStartupPhaseLogPath(raw)
	page := readPhasePage(t, "", 1024)
	if page.Status != "ok" || page.Diagnostic.Path != bridgeSafeString(raw) {
		t.Fatalf("repairable metadata rejected: %+v", page)
	}
}
