package hako

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// A rule set the App staged EMPTY because its download failed (a 404'd rule
// set, a walled network) is the client's deliberate start-first design: the
// profile starts and that one rule set matches nothing, exactly as upstream
// treats a rule provider whose Initial() fails (hub/executor/executor.go:
// 318-338, warn-and-continue). The staging size guard sat in front of that
// tolerance and killed the whole start with "published provider size is
// invalid" before mihomo ever saw the file — the second half of the 100K
// incident, after the client-side store refused to read the same revision
// back. Zero bytes must take the same non-fatal path as unreadable content.
func TestZeroByteRuleProviderFileStartsWarnAndContinue(t *testing.T) {
	options := testOptions(t)
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, behavior, format string }{
		{"mrs", "ipcidr", "mrs"},
		{"classical", "classical", "yaml"},
	} {
		payload := filepath.Join(options.WorkingPath, "empty-"+tc.name+"."+tc.format)
		if err := os.WriteFile(payload, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		content := fmt.Sprintf(`
dns:
  enable: true
  nameserver: [8.8.8.8]
rule-providers:
  gone:
    type: file
    behavior: %s
    format: %s
    path: %q
rules:
  - RULE-SET,gone,DIRECT
  - MATCH,DIRECT
`, tc.behavior, tc.format, payload)
		service, err := NewService(newRecordingPlatform())
		if err != nil {
			t.Fatal(err)
		}
		startErr := service.Start(content)
		_ = service.Close()
		if startErr != nil {
			t.Fatalf("%s: a zero-byte rule provider must warn and continue, got: %v", tc.name, startErr)
		}
	}
}
