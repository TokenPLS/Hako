package hako

import (
	"testing"

	"github.com/TokenPLS/Hako/log"
)

// /debug/gc and /debug/pprof were absent from every build this product ever shipped, and the
// reason was not a decision: route.Config.IsDebug was never assigned, so its zero value kept
// the whole group unregistered. Upstream gates them the same way, so this was never "stricter
// than upstream" -- it was a switch nobody wired, which is a different defect and would not have
// been found by looking for invented constraints.
//
// It matters more than a debug endpoint usually would: the memory attribution this batch did by
// hand -- reading breadcrumbs, correlating footprints across probes -- is what pprof answers
// directly, and the extension was being killed at 49.5 MiB while we did it.
func TestDebugRoutesFollowTheConfiguredLogLevel(t *testing.T) {
	for name, document := range map[string]string{
		"debug": `
log-level: debug
external-controller: 127.0.0.1:9090
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`,
		"info": `
log-level: info
external-controller: 127.0.0.1:9090
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`,
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := parseConfigForIOS(document, true)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			server := controllerServerConfig(cfg, "/tmp/hako-debug-test.sock")
			want := cfg.General.LogLevel == log.DEBUG
			if server.IsDebug != want {
				t.Errorf("log-level %s produced IsDebug=%v, want %v", name, server.IsDebug, want)
			}
			// Fixture check: the two cases must actually differ, or this test passes by
			// comparing a constant with itself.
			if name == "debug" && !want {
				t.Fatal("fixture is wrong: log-level debug did not parse as log.DEBUG")
			}
		})
	}
}
