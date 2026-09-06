package hako

import (
	"strings"
	"testing"
)

// Every rule provider says what became of it, on every path, exactly once.
//
// Before 2026-08-22 the core only spoke when something was wrong. compiled-to-MRS and
// kept-as-source were logged on the publishing path and replayed on a cache hit, but the
// path that stages WITHOUT compiling -- which is what an extension does, and what a
// television's only delivery route goes through -- set no verdict and logged nothing. On a
// real Apple TV run with 15 rule providers the tvOS lane could account for 9 of them, and
// only by noticing a PROCESS-NAME stripping WARNING, which happens to prove the core held
// the source. The other 6 were indistinguishable from compiled sets.
//
// A census assembled out of somebody else's side effects is not a census. This pins the line
// on the silent path specifically, because that is the one that had no test and no caller
// to notice it was missing.
func TestEveryRuleProviderSaysWhatBecameOfIt(t *testing.T) {
	for name, testCase := range map[string]struct {
		compile bool
		want    string
	}{
		// The path that was silent. compile=false is the extension, and a television.
		"staged without compiling": {compile: false, want: "staged as source, not compiled on this profile"},
		// The set holds a kind the domain strategy cannot store, so it rides as text.
		"kept as source": {compile: true, want: "kept as source, every rule loads"},
	} {
		t.Run(name, func(t *testing.T) {
			compileStagingHome(t)
			source := writeRuleSource(t, "set.yaml",
				"payload:\n  - DOMAIN-KEYWORD,ads\n  - IP-CIDR,10.0.0.0/8\n")
			raw := rawWithRuleProvider(source, "classical", "yaml")
			logBuffer := capturePublishLog(t)

			runtime, err := stageProviderRuntime(raw,
				runtimePolicyFor(runtimeProfileIOSPacketTunnel, true), testCase.compile)
			if err != nil {
				t.Fatalf("stage: %v", err)
			}
			defer runtime.close()

			logged := logBuffer.String()
			// The name has to be on the SAME line as the disposition, or a reader with
			// fifteen providers cannot tell which one this is. Searching the whole buffer
			// would pass on the fixture's own file path, which also contains the name.
			var line string
			for _, candidate := range strings.Split(logged, "\n") {
				if strings.Contains(candidate, testCase.want) {
					line = candidate
					break
				}
			}
			if line == "" {
				t.Fatalf("no disposition for the provider on this path; wanted %q in:\n%s",
					testCase.want, logged)
			}
			if !strings.Contains(line, "reject") {
				t.Errorf("the disposition line does not name the provider: %s", line)
			}
			// The prefix is the platform family, not one phone. This same line prints on an
			// Apple TV, where `[iOS]` was simply false.
			if strings.Contains(logged, "[iOS] rule provider") {
				t.Errorf("provider lines still claim iOS on every Apple platform:\n%s", logged)
			}
		})
	}
}

// A set that compiles cleanly is also accounted for -- the census has no holes, including
// the outcome that is completely normal.
func TestACompiledRuleProviderIsAccountedForToo(t *testing.T) {
	compileStagingHome(t)
	source := writeRuleSource(t, "domains.yaml",
		"payload:\n  - DOMAIN,example.com\n  - DOMAIN-SUFFIX,example.org\n")
	raw := rawWithRuleProvider(source, "classical", "yaml")
	logBuffer := capturePublishLog(t)

	runtime, err := stageProviderRuntime(raw,
		runtimePolicyFor(runtimeProfileIOSPacketTunnel, true), true)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	defer runtime.close()

	if logged := logBuffer.String(); !strings.Contains(logged, "compiled to MRS") {
		t.Fatalf("a compiled set produced no disposition:\n%s", logged)
	}
}
