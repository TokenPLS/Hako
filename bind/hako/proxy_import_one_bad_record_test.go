package hako

import (
	"encoding/json"
	"strings"
	"testing"
)

// One record a container format cannot read does not cost the others.
//
// Share links arrive a few at a time and each is its own record, so a bad one
// was already just a skip. A configuration arrives with hundreds of nodes in
// one document, and every per-record failure in the surge and JSON parsers
// returned an error that reached the caller as the whole payload's verdict:
// `parse surge proxy payload: ...`, no report, nothing. A person whose file
// carried one line naming a field this build does not map got none of their
// nodes back and no reason for any of them.
//
// That is the same defect the share-link path had -- an unmapped field costing
// a node -- one level up, where it costs the document. It survived the first
// pass because the first pass was looking at share links.
//
// The fixtures put the unreadable record in the middle so a parser that stops
// at the first problem is distinguishable from one that skips it: stopping
// yields A alone, skipping yields A and C.
func TestOneUnreadableRecordDoesNotCostTheRestOfTheDocument(t *testing.T) {
	for _, test := range []struct {
		name    string
		payload string
		reason  string
	}{
		{
			name: "a surge line naming a field this build does not map",
			payload: "[Proxy]\n" +
				"A = trojan, a.example, 443, password=pw\n" +
				"B = trojan, b.example, 443, password=pw, hako-unknown=1\n" +
				"C = trojan, c.example, 443, password=pw\n",
			reason: "hako-unknown",
		},
		{
			name: "a surge line that is not a proxy line at all",
			payload: "[Proxy]\n" +
				"A = trojan, a.example, 443, password=pw\n" +
				"BBBB\n" +
				"C = trojan, c.example, 443, password=pw\n",
			reason: "BBBB",
		},
		{
			// Until 2026-09-02 this row carried a field this build does not map,
			// and that was enough to make the record unreadable. It no longer is
			// (the node arrives and the field is named under it -- see
			// proxy_import_json_body_keys_are_named_not_refused_test.go), so the
			// unreadable record here is one with no port, which nobody can build.
			name: "a sing-box outbound with no server_port",
			payload: `{"outbounds":[` +
				`{"type":"trojan","tag":"A","server":"a.example","server_port":443,"password":"pw"},` +
				`{"type":"trojan","tag":"B","server":"b.example","password":"pw"},` +
				`{"type":"trojan","tag":"C","server":"c.example","server_port":443,"password":"pw"}]}`,
			reason: "server_port",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			box, err := InspectProxyPayloadForIOS([]byte(test.payload), "nodeBundle")
			if err != nil {
				t.Fatalf("one unreadable record cost the whole document: %v", err)
			}
			var report struct {
				Proxies []map[string]any `json:"proxies"`
				Skipped []struct {
					Message string `json:"message"`
				} `json:"skipped"`
			}
			if err := json.Unmarshal([]byte(box.Value), &report); err != nil {
				t.Fatalf("decode: %v", err)
			}
			names := make([]string, 0, len(report.Proxies))
			for _, proxy := range report.Proxies {
				name, _ := proxy["name"].(string)
				names = append(names, name)
			}
			if len(names) != 2 || names[0] != "A" || names[1] != "C" {
				t.Fatalf("the readable records did not survive: %v", names)
			}
			if len(report.Skipped) != 1 {
				t.Fatalf("expected one skip, got %d: %#v", len(report.Skipped), report.Skipped)
			}
			if !strings.Contains(report.Skipped[0].Message, test.reason) {
				t.Fatalf("the skip does not say what was wrong with the record: %q", report.Skipped[0].Message)
			}
		})
	}
}

// A document where nothing could be read comes back as reasons, not as one
// sentence saying it held no proxies.
func TestADocumentWhoseRecordsAllFailedStillReportsWhy(t *testing.T) {
	payload := "[Proxy]\nAAAA\nBBBB\n"
	box, err := InspectProxyPayloadForIOS([]byte(payload), "nodeBundle")
	if err != nil {
		t.Fatalf("a document of unreadable records produced no report at all: %v", err)
	}
	var report struct {
		Proxies []map[string]any `json:"proxies"`
		Skipped []struct {
			Message string `json:"message"`
		} `json:"skipped"`
	}
	if err := json.Unmarshal([]byte(box.Value), &report); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(report.Proxies) != 0 || len(report.Skipped) != 2 {
		t.Fatalf("expected two skips and no nodes: %#v", report)
	}
}
