package hako

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"

	"github.com/metacubex/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/log"
)

// the false all-clear.
//
// On a device, Start published four rows for the reader's file; a later parse of a document
// that already carried the forced values published zero; the endpoint served the zero --
// correct for that document -- and the client rendered "every field in your file was
// honoured". Nothing had red: no gate compared what was served with what was published, no
// gate ran two publishes in a row, and a zero-row publish logged nothing, so it left no trace.
//
// This is that gate, without a device. Two documents through the real runtime entry point,
// and after each one three things must hold: the endpoint serves exactly the rows that were
// published, the served report names the document it describes (length and SHA-256, the two
// numbers the client can compute over the text it handed over), and the publish is in the
// log -- rows or no rows.
type servedDeviationReport struct {
	SchemaVersion int                        `json:"schemaVersion"`
	Sequence      uint64                     `json:"sequence"`
	Entry         string                     `json:"entry"`
	Document      *deviationDocumentIdentity `json:"document"`
	Deviations    []configDeviation          `json:"deviations"`
}

func serveDeviationsNow(t *testing.T) servedDeviationReport {
	t.Helper()
	recorder := httptest.NewRecorder()
	serveConfigDeviations(recorder, httptest.NewRequest("GET", "/hako/v1/deviations", nil))
	if recorder.Code != 200 {
		t.Fatalf("status = %d", recorder.Code)
	}
	var served servedDeviationReport
	if err := json.Unmarshal(recorder.Body.Bytes(), &served); err != nil {
		t.Fatalf("response is not JSON: %s", recorder.Body.String())
	}
	return served
}

func sha256Hex(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

func TestTheServedReportIsThePublishedOneAndNamesItsDocument(t *testing.T) {
	previous := publishedDeviations.Load()
	t.Cleanup(func() { publishedDeviations.Store(previous) })
	publishedDeviations.Store(nil)

	subscription := log.Subscribe()
	t.Cleanup(func() { log.UnSubscribe(subscription) })

	// A: the reader's file. Written values the profile forces elsewhere, and a rule kind it
	// cannot execute -- rows of more than one category.
	const readersFile = "tun:\n  enable: true\n  mtu: 1500\n  auto-route: true\nrules:\n  - PROCESS-NAME,curl,DIRECT\n  - MATCH,DIRECT\nproxies: []\n"
	if _, _, err := parseConfigForIOSRuntime(readersFile, true, deviationEntryStart); err != nil {
		t.Fatalf("start parse: %v", err)
	}
	first := serveDeviationsNow(t)
	if len(first.Deviations) == 0 {
		t.Fatalf("positive control failed: the reader's file produced no rows, so nothing below tests anything")
	}
	publishedRows, _ := json.Marshal(loadPublishedDeviations())
	servedRows, _ := json.Marshal(first.Deviations)
	if string(publishedRows) != string(servedRows) {
		t.Fatalf("served rows differ from published rows:\n served: %s\n published: %s", servedRows, publishedRows)
	}
	if first.Entry != deviationEntryStart || first.Sequence == 0 {
		t.Fatalf("served report does not say which publish it is: entry=%q seq=%d", first.Entry, first.Sequence)
	}
	if first.Document == nil || first.Document.Bytes != len(readersFile) || first.Document.SHA256 != sha256Hex(readersFile) {
		t.Fatalf("served report does not name the reader's file: %+v (want %dB %s)", first.Document, len(readersFile), sha256Hex(readersFile))
	}

	// B: a document that already says what the guards would write. Zero rows is the truth
	// about B -- and the report must say it is about B, not leave the reader to assume it is
	// still about A.
	const alreadyForced = "dns:\n  enable: true\nprofile:\n  store-fake-ip: true\nfind-process-mode: 'off'\nunified-delay: true\nproxies: []\nrules:\n  - MATCH,DIRECT\n"
	if _, _, err := parseConfigForIOSRuntime(alreadyForced, true, deviationEntryReload); err != nil {
		t.Fatalf("reload parse: %v", err)
	}
	second := serveDeviationsNow(t)
	if len(second.Deviations) != 0 {
		t.Fatalf("positive control failed: the already-forced document was meant to publish zero rows, got %v", fieldsOf(second.Deviations))
	}
	if second.Sequence != first.Sequence+1 || second.Entry != deviationEntryReload {
		t.Fatalf("the second publish is not numbered after the first: first=%d second=%d entry=%q", first.Sequence, second.Sequence, second.Entry)
	}
	if second.Document == nil || second.Document.SHA256 != sha256Hex(alreadyForced) || second.Document.SHA256 == first.Document.SHA256 {
		t.Fatalf("the zero-row report does not name the document it is about: %+v", second.Document)
	}

	// Both publishes are in the log, the zero-row one included. The log is asynchronous to the
	// caller, so collect until both lines have arrived or the deadline passes.
	wantFirst := "entry=start seq=" + strconv.FormatUint(first.Sequence, 10) + " "
	wantSecond := "entry=reload seq=" + strconv.FormatUint(second.Sequence, 10) + " "
	var sawFirst, sawSecond string
	deadline := time.After(5 * time.Second)
	for sawFirst == "" || sawSecond == "" {
		select {
		case event, open := <-subscription:
			if !open {
				t.Fatalf("log subscription closed; saw first=%q second=%q", sawFirst, sawSecond)
			}
			if !strings.Contains(event.Payload, "[Apple] deviations published:") {
				continue
			}
			if strings.Contains(event.Payload, wantFirst) {
				sawFirst = event.Payload
			}
			if strings.Contains(event.Payload, wantSecond) {
				sawSecond = event.Payload
			}
		case <-deadline:
			t.Fatalf("publish summary lines did not both reach the log within 5s; first=%q second=%q", sawFirst, sawSecond)
		}
	}
	if !strings.HasSuffix(strings.TrimSpace(sawSecond), "rows=0") {
		t.Fatalf("the zero-row publish is not logged as zero rows: %q", sawSecond)
	}
	if !strings.Contains(sawFirst, "sha256="+sha256Hex(readersFile)[:16]) {
		t.Fatalf("the summary line does not carry the document identity: %q", sawFirst)
	}
}

// Before the first publish there is no document to name, and the report must not invent one:
// an identity that matches nothing the client holds is exactly as useful as none, and worse
// if a client treats "present" as "about my file".
func TestBeforeTheFirstPublishTheReportNamesNoDocument(t *testing.T) {
	previous := publishedDeviations.Load()
	t.Cleanup(func() { publishedDeviations.Store(previous) })
	publishedDeviations.Store(nil)

	served := serveDeviationsNow(t)
	if served.Document != nil || served.Sequence != 0 || served.Entry != "" {
		t.Fatalf("a report served before any publish claims an identity: %+v", served)
	}
	if served.Deviations == nil {
		t.Fatalf("deviations is null before the first publish; an empty array is the honest answer")
	}
}

// The offline report names its document too, so one describes(text) works on both kinds.
func TestTheOfflineReportNamesItsDocument(t *testing.T) {
	const document = "tun:\n  mtu: 1500\nproxies: []\nrules:\n  - MATCH,DIRECT\n"
	box, err := ConfigDeviationsJSON(document, RuntimeProfileIOSPacketTunnel)
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		Document *deviationDocumentIdentity `json:"document"`
	}
	if err := json.Unmarshal([]byte(box.Value), &env); err != nil {
		t.Fatal(err)
	}
	if env.Document == nil || env.Document.Bytes != len(document) || env.Document.SHA256 != sha256Hex(document) {
		t.Fatalf("offline report does not name the text it was computed over: %+v", env.Document)
	}
}
