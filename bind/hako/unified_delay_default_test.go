package hako

import (
	"encoding/json"
	"strings"
	"testing"
)


func TestUnifiedDelayDefaultForASilentReader(t *testing.T) {
	restoreRuntimeProfileForTest(t)
	const silent = `
mixed-port: 7890
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	mihomo, ours := parseBoth(t, silent)
	t.Logf("unified-delay  mihomo=%v ours=%v", mihomo.General.UnifiedDelay, ours.General.UnifiedDelay)
	if mihomo.General.UnifiedDelay {
		t.Fatal("upstream now defaults unified-delay on; the deviation row is stale and this fork arm is dead")
	}
	if !ours.General.UnifiedDelay {
		t.Fatal("a silent reader must get unified-delay on: without it every probe bills the full cold handshake")
	}
}

func TestUnifiedDelayIsPreservedWhenTheReaderIsExplicit(t *testing.T) {
	restoreRuntimeProfileForTest(t)
	for _, want := range []bool{true, false} {
		document := `
mixed-port: 7890
unified-delay: ` + map[bool]string{true: "true", false: "false"}[want] + `
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
		mihomo, ours := parseBoth(t, document)
		if mihomo.General.UnifiedDelay != want {
			t.Fatalf("upstream did not take unified-delay: %v; fixture proves nothing", want)
		}
		if ours.General.UnifiedDelay != want {
			t.Errorf("unified-delay: reader wrote %v, this core produced %v — an explicit value was overridden", want, ours.General.UnifiedDelay)
		}
	}
}

func unifiedDelayRowFor(t *testing.T, yaml string) map[string]any {
	t.Helper()
	box, err := ConfigDeviationsJSON(yaml, RuntimeProfileMacOSPacketTunnel)
	if err != nil {
		t.Fatalf("ConfigDeviationsJSON: %v", err)
	}
	var report struct {
		Deviations []map[string]any `json:"deviations"`
	}
	if err := json.Unmarshal([]byte(box.Value), &report); err != nil {
		t.Fatal(err)
	}
	for _, d := range report.Deviations {
		if d["field"] == "unified-delay" {
			return d
		}
	}
	return nil
}

func TestUnifiedDelayDeviationRowShape(t *testing.T) {
	row := unifiedDelayRowFor(t, "proxies: []\nrules:\n  - MATCH,DIRECT\n")
	if row == nil {
		t.Fatal("a silent configuration must carry the unified-delay default row")
	}
	if row["category"] != "forced" || row["recoverable"] != true {
		t.Fatalf("row must be forced+recoverable, got %v", row)
	}
	if row["upstreamDefault"] != "false" {
		t.Fatalf("upstreamDefault must be the string false, got %v", row["upstreamDefault"])
	}
	alternative, _ := row["alternative"].(string)
	if !strings.Contains(alternative, "unified-delay") {
		t.Fatalf("alternative must tell the reader to write unified-delay explicitly, got %q", alternative)
	}
	if written := unifiedDelayRowFor(t, "unified-delay: false\nproxies: []\nrules:\n  - MATCH,DIRECT\n"); written != nil {
		t.Fatalf("an explicit value is honoured, so no deviation happened, yet a row was reported: %v", written)
	}
}
