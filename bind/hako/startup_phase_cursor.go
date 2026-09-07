package hako

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"unicode/utf8"
)

const startupPhasePageByteLimit = 64 * 1024
const startupPhasePageMinimumBytes = 1024
const startupPhasePageRecordLimit = 256

type startupPhasePageDiagnostic struct {
	Revision       int64  `json:"revision"`
	Path           string `json:"path"`
	Error          string `json:"error"`
	RecordSequence int64  `json:"recordSequence"`
}

type startupPhasePage struct {
	SchemaVersion      int                         `json:"schemaVersion"`
	Status             string                      `json:"status"`
	Epoch              string                      `json:"epoch"`
	From               int64                       `json:"from"`
	Next               int64                       `json:"next"`
	Head               int64                       `json:"head"`
	Through            int64                       `json:"through"`
	BeginCursor        string                      `json:"beginCursor"`
	NextCursor         string                      `json:"nextCursor"`
	HeadCursor         string                      `json:"headCursor"`
	ThroughCursor      string                      `json:"throughCursor"`
	Records            []json.RawMessage           `json:"records"`
	DiagnosticRevision int64                       `json:"diagnosticRevision"`
	Diagnostic         *startupPhasePageDiagnostic `json:"diagnostic,omitempty"`
}

type startupPhasePageRecord struct {
	Sequence int64  `json:"sequence"`
	Line     string `json:"line"`
}

func newStartupPhaseEpoch() string {
	var epoch [16]byte
	// crypto/rand.Read terminates the process if secure randomness is unavailable.
	_, _ = rand.Read(epoch[:])
	return hex.EncodeToString(epoch[:])
}

func parseStartupPhaseCursor(cursor string) (string, int64, bool) {
	if len(cursor) > 64 {
		return "", 0, false
	}
	epoch, number, found := strings.Cut(cursor, ":")
	sequence, err := strconv.ParseInt(number, 10, 64)
	if !found || len(epoch) != 32 || err != nil || sequence < 0 || strconv.FormatInt(sequence, 10) != number {
		return "", 0, false
	}
	if _, err := hex.DecodeString(epoch); err != nil {
		return "", 0, false
	}
	return epoch, sequence, true
}

// StartupPhaseTracePage returns a versioned JSON page of whole startup records.
// An empty cursor and throughCursor capture the current tail without replaying
// history; capture before Setup to include early stages. The beginCursor permits
// explicit replay. A supplied throughCursor fixes an inclusive upper boundary;
// empty throughCursor captures the current head for this page. Reuse the returned
// throughCursor to finish a fixed window without reading later production.
// Cursors identify process events and do not acknowledge consumer file writes.
//
// Zero maxBytes reads metadata without advancing a supplied cursor. Positive
// values must be at least 1024 and are capped at 65536; the entire encoded JSON
// response, including repaired text and metadata, fits that effective budget.
// Pages also contain at most 256 events. A recordTooLarge or metadataTooLarge
// status leaves the cursor unchanged; oversized metadata is omitted from the
// error response, and the legacy diagnostic getter remains available explicitly.
// Invalid parameters produce a small error envelope, never echoing unbounded
// input. Existing process history and legacy getters remain unchanged.
func StartupPhaseTracePage(cursor string, throughCursor string, maxBytes int64) string {
	page := startupPhaseTracePageSnapshot(cursor, throughCursor, maxBytes)
	result, _ := json.Marshal(page)
	return bridgeSafeString(string(result))
}

func startupPhaseTracePageSnapshot(cursor string, throughCursor string, maxBytes int64) startupPhasePage {
	phaseMu.Lock()
	locked := true
	defer func() {
		if locked {
			phaseMu.Unlock()
		}
	}()
	head := int64(len(phaseTrace))
	makeCursor := func(sequence int64) string { return phaseEpoch + ":" + strconv.FormatInt(sequence, 10) }
	page := startupPhasePage{
		SchemaVersion: 1, Status: "ok", Epoch: phaseEpoch,
		From: head, Next: head, Head: head, Through: head,
		BeginCursor: makeCursor(0), NextCursor: makeCursor(head), HeadCursor: makeCursor(head), ThroughCursor: makeCursor(head),
		Records: make([]json.RawMessage, 0), DiagnosticRevision: phaseDiagnosticRevision,
		Diagnostic: &startupPhasePageDiagnostic{
			Revision: phaseDiagnosticRevision, Path: setupStartupPhaseLogPath,
			Error: startupPhaseFailure, RecordSequence: phaseFailureSequence,
		},
	}
	fail := func(status string) startupPhasePage {
		page.Status = status
		page.Diagnostic = nil
		return page
	}
	if maxBytes < 0 || (maxBytes > 0 && maxBytes < startupPhasePageMinimumBytes) {
		page.From = -1
		page.Next = -1
		page.NextCursor = ""
		return fail("invalidBudget")
	}
	budget := int64(startupPhasePageByteLimit)
	if maxBytes > 0 {
		budget = min(maxBytes, budget)
	}
	if cursor == "" && throughCursor != "" {
		page.From = -1
		page.Next = -1
		page.NextCursor = ""
		return fail("invalidRange")
	}
	if cursor != "" {
		page.From = -1
		page.Next = -1
		page.NextCursor = ""
		epoch, sequence, valid := parseStartupPhaseCursor(cursor)
		if !valid {
			return fail("invalidCursor")
		}
		if epoch != phaseEpoch {
			return fail("epochMismatch")
		}
		page.From = sequence
		page.Next = sequence
		page.NextCursor = cursor
		if sequence > head {
			return fail("cursorAhead")
		}
		if throughCursor != "" {
			throughEpoch, through, valid := parseStartupPhaseCursor(throughCursor)
			if !valid {
				return fail("invalidCursor")
			}
			if throughEpoch != phaseEpoch {
				return fail("epochMismatch")
			}
			if through > head {
				return fail("cursorAhead")
			}
			if sequence > through {
				return fail("invalidRange")
			}
			page.Through = through
			page.ThroughCursor = throughCursor
		}
	}
	// Snapshot only immutable string headers while holding the history lock.
	// Encoding and even rejecting adversarial text must not stall the producer.
	var lines []string
	if cursor != "" && maxBytes > 0 {
		end := page.From + min(page.Through-page.From, int64(startupPhasePageRecordLimit))
		lines = append([]string(nil), phaseTrace[page.From:end]...)
	}
	phaseMu.Unlock()
	locked = false
	var fits bool
	page.Diagnostic.Path, fits = boundedStartupPhaseText(page.Diagnostic.Path, int(budget))
	if !fits {
		return fail("metadataTooLarge")
	}
	page.Diagnostic.Error, fits = boundedStartupPhaseText(page.Diagnostic.Error, int(budget)-len(page.Diagnostic.Path))
	if !fits {
		return fail("metadataTooLarge")
	}
	base, _ := json.Marshal(page)
	if int64(len(base)) > budget {
		return fail("metadataTooLarge")
	}
	if cursor == "" || maxBytes == 0 {
		return page
	}
	used := int64(len(base))
	for index, raw := range lines {
		next := page.From + int64(index)
		line, fits := boundedStartupPhaseText(raw, int(budget))
		if !fits {
			if len(page.Records) == 0 {
				return fail("recordTooLarge")
			}
			break
		}
		encoded, _ := json.Marshal(startupPhasePageRecord{Sequence: next + 1, Line: line})
		cost := int64(len(encoded))
		if len(page.Records) > 0 {
			cost++
		}
		// next appears both as a JSON number and inside its ASCII cursor.
		growth := len(strconv.FormatInt(next+1, 10)) - len(strconv.FormatInt(page.Next, 10))
		cost += int64(2 * growth)
		if used+cost > budget {
			if len(page.Records) == 0 {
				return fail("recordTooLarge")
			}
			break
		}
		page.Records = append(page.Records, encoded)
		used += cost
		page.Next = next + 1
	}
	page.NextCursor = makeCursor(page.Next)
	return page
}

// boundedStartupPhaseText has bridgeSafeString's exact repair semantics:
// each run of invalid UTF-8 becomes one replacement rune. Raw byte length is
// not a lower bound on repaired length. Stop only after repaired output exceeds
// the budget; valid oversized input is rejected without scanning its full tail.
// A long invalid run can require a long scan, but happens outside phaseMu and
// never allocates a copy proportional to that raw run.
func boundedStartupPhaseText(value string, limit int) (string, bool) {
	if len(value) <= limit && utf8.ValidString(value) {
		return value, true
	}
	var out strings.Builder
	out.Grow(min(max(limit, 0), 256))
	invalidRun := false
	for len(value) > 0 {
		r, size := utf8.DecodeRuneInString(value)
		if r == utf8.RuneError && size == 1 {
			if !invalidRun {
				if out.Len()+len("�") > limit {
					return "", false
				}
				out.WriteString("�")
				invalidRun = true
			}
		} else {
			if out.Len()+size > limit {
				return "", false
			}
			out.WriteString(value[:size])
			invalidRun = false
		}
		value = value[size:]
	}
	return out.String(), true
}
