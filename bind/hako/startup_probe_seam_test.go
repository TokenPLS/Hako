package hako

import (
	"path/filepath"
	"testing"

	"github.com/TokenPLS/Hako/config"
	"github.com/TokenPLS/Hako/hub/executor"
)

// What the killed tunnel is found at has to be the step that spent the memory.
//
// The breadcrumb is the only account that survives jetsam, and the client branches on
// its stage to tell the reader what to change. Both halves existed and neither was
// wired to the other: the probes Start installs reported to the phase log -- a
// developer's file, written only when a bill is being collected -- while the breadcrumb
// heard only the six bind:* steps of the parse. Every stage the client's explanation
// names (apply:profile, apply:proxy-providers*, parse:dns, parse:rules, apply:rules)
// therefore could not occur in the field, and a reader killed at 50 MiB got a card with
// no way out on it.
//
// These tests drive armStartupProbes, which is what a tunnel installs. The earlier
// tests of this reporting called recordStartupStage directly and asserted on the name
// they had just passed it, so they stayed green through the whole defect.

func armedProbeBreadcrumb(t *testing.T) string {
	t.Helper()
	home := breadcrumbHome(t)
	setStartupBreadcrumbRecording(true)
	t.Cleanup(func() { setStartupBreadcrumbRecording(false) })
	t.Cleanup(armStartupProbes())
	return filepath.Join(home, breadcrumbFileName)
}

func TestApplyStepsReachTheBreadcrumbAndNotOnlyThePhaseLog(t *testing.T) {
	path := armedProbeBreadcrumb(t)

	// The last step ApplyConfig reports before it walks the rule providers.
	executor.StartupProbe("profile")

	record, err := readBreadcrumb(path)
	if err != nil {
		t.Fatalf("an apply step left no breadcrumb for the next launch to read: %v", err)
	}
	if record.Stage != "apply:profile" {
		t.Fatalf("breadcrumb stage is %q, so the client's apply:profile branch is unreachable in the field", record.Stage)
	}
}

func TestParseSectionsReachTheBreadcrumbToo(t *testing.T) {
	path := armedProbeBreadcrumb(t)

	config.StartupProbe("dns")

	record, err := readBreadcrumb(path)
	if err != nil {
		t.Fatalf("a parse section left no breadcrumb: %v", err)
	}
	if record.Stage != "parse:dns" {
		t.Fatalf("breadcrumb stage is %q, so the client's parse:dns branch is unreachable in the field", record.Stage)
	}
}

// A kill inside Initial has to name the provider it was building. The pair of probes
// around Initial exists for exactly this: the second one cannot be reached by a process
// that dies in between.
func TestTheProviderBeingBuiltIsNamedBeforeItIsBuilt(t *testing.T) {
	path := armedProbeBreadcrumb(t)

	executor.StartupProbe("rule-provider-begin:reject")

	record, err := readBreadcrumb(path)
	if err != nil {
		t.Fatalf("the provider about to be built left no breadcrumb: %v", err)
	}
	if record.Resource != "rule-provider:reject" {
		t.Fatalf("breadcrumb resource is %q; a kill inside Initial would not name the provider", record.Resource)
	}
	if record.Stage != "apply:rule-provider-begin:reject" {
		t.Fatalf("breadcrumb stage is %q", record.Stage)
	}
}

// What routing the apply steps into the breadcrumb costs the reader.
//
// Every step now writes the record, and the record is read before it is written, so the
// price is a small read-modify-write per step on the path a reader waits on. A start
// walks roughly twenty apply steps and a dozen parse sections, plus two per provider.
// Measured rather than assumed, because the same startup path had 94ms of provider
// loads argued over.
func BenchmarkAnApplyStepThroughTheBreadcrumb(b *testing.B) {
	home := b.TempDir()
	previous := breadcrumbDirectory
	breadcrumbDirectory = home
	b.Cleanup(func() { breadcrumbDirectory = previous })
	setStartupBreadcrumbRecording(true)
	b.Cleanup(func() { setStartupBreadcrumbRecording(false) })

	for i := 0; i < b.N; i++ {
		recordStartupStage("apply:profile")
	}
}

// The app process runs the same parse for its editor preflight and must not write the
// tunnel's telemetry. Disarming is what separates them, so it is worth an assertion.
func TestDisarmingStopsTheProbesFromWritingAnything(t *testing.T) {
	home := breadcrumbHome(t)
	setStartupBreadcrumbRecording(true)
	t.Cleanup(func() { setStartupBreadcrumbRecording(false) })

	disarm := armStartupProbes()
	disarm()

	if config.StartupProbe != nil || executor.StartupProbe != nil {
		t.Fatal("a disarmed Start left its probes installed for the next caller")
	}
	if _, err := readBreadcrumb(filepath.Join(home, breadcrumbFileName)); err == nil {
		t.Fatal("arming and disarming with no steps in between still wrote a record")
	}
}
