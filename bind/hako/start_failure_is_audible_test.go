package hako

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// A start or reload that fails must leave a readable reason in the core's log.
//
// Until 2026-08-28 it did not. Start's refusal path was `done <- err; return`,
// so the phase record stopped at config-parsed, the core log's last line was a
// memory footprint, and the extension's unified log had nothing at all. The
// macOS lane hit it while trying to attribute seven device results and could
// not tell a refusal from a crash from a fixture mistake -- and what a user
// sees in that state is "I tapped it and nothing happened".
//
// settles what the line may say: verbatim, no redaction, no rewording.
// It does not say the core may say nothing.
//
// This reads the source rather than driving a start, because driving one means
// applying a configuration to the live core -- which is what made an earlier
// sweep crash the suite. A source check is weaker and is enough for the one
// thing that regresses here: somebody adding a fifth exit that returns in
// silence.
func TestNoStartOrReloadFailureIsSilent(t *testing.T) {
	source, err := os.ReadFile("service.go")
	if err != nil {
		t.Fatalf("cannot read service.go: %v", err)
	}
	lines := strings.Split(string(source), "\n")

	// Every place the start/reload goroutines hand an error back.
	// fail(...) is covered by the helper rather than at the call site, so the
	// helper is checked once and its callers are not asked to repeat it. An
	// earlier version of this scan demanded a nearby log line for every
	// fail(err) too and reported two false positives -- a gate that cries wolf
	// about correct code gets edited until it stops, usually by weakening it.
	exit := regexp.MustCompile(`^\s*(done <- err|done <- fmt\.Errorf)`)
	logged := regexp.MustCompile(`log\.(Errorln|Warnln)\(`)

	exits, silent := 0, []int{}
	for index, line := range lines {
		if !exit.MatchString(line) {
			continue
		}
		exits++
		// A line is covered when the same block logs within the few lines
		// above it -- the shape every one of these takes.
		covered := false
		for back := index - 1; back >= 0 && back >= index-8; back-- {
			if logged.MatchString(lines[back]) {
				covered = true
				break
			}
			// Do not read across into the previous statement's block.
			if strings.TrimSpace(lines[back]) == "}" && back < index-1 {
				break
			}
		}
		if !covered {
			silent = append(silent, index+1)
		}
	}

	if exits == 0 {
		t.Fatal("found no error exits in service.go; the scan is broken, not the code")
	}

	// The fail helpers, checked where they are defined.
	helpers := 0
	for index, line := range lines {
		if !strings.Contains(line, "fail := func(err error) {") {
			continue
		}
		helpers++
		audible := false
		for ahead := index + 1; ahead < len(lines) && ahead <= index+6; ahead++ {
			if logged.MatchString(lines[ahead]) {
				audible = true
				break
			}
		}
		if !audible {
			t.Errorf("the fail helper at service.go:%d returns without logging, and every one of its "+
				"callers relies on it to", index+1)
		}
	}
	if helpers == 0 {
		t.Fatal("found no fail helper; the scan no longer matches the code it describes")
	}
	if len(silent) != 0 {
		t.Errorf("service.go returns a start/reload failure with no log line at %v -- a failure that "+
			"leaves no readable reason is indistinguishable from a crash, and from nothing having "+
			"happened at all", silent)
	}
	t.Logf("checked %d error exits, all audible", exits)
}
