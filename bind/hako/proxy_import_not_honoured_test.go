package hako

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// TestRegisteredUnhonouredFieldsImportAndAreNamed holds the three-way ruling on a
// field the exporter emits that the kernel has nowhere to put: the record still
// imports, the field is named in the report, and a field nobody registered still
// refuses the whole record. The last cell is the one that matters -- a blanket
// pass-through would silently drop a connection-critical field and hand back a
// node that looks complete and cannot connect, which is the defect this importer
// keeps being bitten by.
func TestRegisteredUnhonouredFieldsImportAndAreNamed(t *testing.T) {
	authority := base64.RawURLEncoding.EncodeToString([]byte("user:secret@198.51.100.10:443"))
	read := func(t *testing.T, link string) proxyImportReport {
		t.Helper()
		box, err := InspectProxyPayloadForIOS([]byte(link+"#node"), "singleNode")
		if err != nil {
			t.Fatalf("%s: %v", link, err)
		}
		var report proxyImportReport
		if err := json.Unmarshal([]byte(box.Value), &report); err != nil {
			t.Fatalf("report: %v", err)
		}
		return report
	}

	t.Run("registered field imports and is named", func(t *testing.T) {
		for _, honoured := range []struct{ link, field string }{
			{"ssocks://" + authority + "?remarks=probe&tls=1&peer=sni.example.invalid", "peer"},
			{"trojan-go://secret@198.51.100.10:443?peer=sni.example.invalid&mux=1", "mux"},
		} {
			report := read(t, honoured.link)
			if len(report.Proxies) != 1 {
				t.Errorf("%s: refused instead of imported: %+v %+v",
					honoured.field, report.Skipped, report.Skipped)
				continue
			}
			named := false
			for _, notice := range report.NotHonoured {
				if strings.Contains(notice.Message, "."+honoured.field+":") {
					named = true
					if notice.Code != "fieldNotHonoured" {
						t.Errorf("%s: code = %q", honoured.field, notice.Code)
					}
					// The reason is what makes the notice actionable rather than a
					// shrug; a bare field name tells the reader nothing.
					if !strings.Contains(notice.Message, "mihomo") {
						t.Errorf("%s: notice carries no reason: %s", honoured.field, notice.Message)
					}
				}
			}
			if !named {
				t.Errorf("%s: imported without naming the field it dropped: %+v", honoured.field, report.NotHonoured)
			}
		}
	})

	// The reader's ruling on 2026-08-28 reversed this one: there is no
	// "recognized but unsupported" outcome, and a key nobody here has registered
	// is a key nobody here has registered -- not a broken link. Upstream reads
	// the keys it knows and ignores the rest, and two of the reader's own
	// airport links were lost to this whitelist within an hour of each other.
	//
	// What is still asserted is that the field is named. Tolerating without
	// saying so is the other half of the same mistake: the node would import
	// with a field silently missing and fail later, somewhere that does not
	// point back at the link.
	t.Run("an unregistered field is named, and the node still arrives", func(t *testing.T) {
		report := read(t, "trojan://secret@198.51.100.10:443?peer=sni.example.invalid&hakoFutureField=x")
		if len(report.Proxies) != 1 {
			t.Fatalf("an unregistered field cost the node: %+v", report)
		}
		if len(report.Skipped) != 0 {
			t.Fatalf("the record was skipped over one unregistered field: %+v", report.Skipped)
		}
		if len(report.NotHonoured) != 1 ||
			!strings.Contains(report.NotHonoured[0].Message, "hakoFutureField") {
			t.Fatalf("the unregistered field was dropped without saying so: %+v", report.NotHonoured)
		}
	})

	t.Run("a clean link reports nothing", func(t *testing.T) {
		report := read(t, "trojan://secret@198.51.100.10:443?peer=sni.example.invalid")
		if len(report.Proxies) != 1 || len(report.NotHonoured) != 0 {
			t.Fatalf("clean link: proxies=%d notHonoured=%+v", len(report.Proxies), report.NotHonoured)
		}
	})

	t.Run("every registered field states a kernel reason", func(t *testing.T) {
		if len(proxyImportUnhonouredFields) == 0 {
			t.Fatal("the registry is empty, so this test would pass without checking anything")
		}
		for canonicalType, fields := range proxyImportUnhonouredFields {
			for field, reason := range fields {
				if !strings.Contains(reason, "mihomo") {
					t.Errorf("%s.%s: reason does not say what the kernel lacks: %q", canonicalType, field, reason)
				}
			}
		}
	})
}
