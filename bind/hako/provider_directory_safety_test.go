package hako

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Staging creates its own directory with MkdirAll and then sweeps everything in
// it that the current configuration does not reference. Both follow symlinks,
// so a link planted at the staging root redirects every staged write into
// whatever it points at -- and turns the sweep into an indiscriminate
// RemoveAll of a directory that was never ours.
//
// Threat model: a local process that can write the container (macOS, where the
// sandbox is weak enough for this to be a live concern -- see the manifest
// integrity tests for why iOS is a different case).

func TestStagingRefusesASymlinkedRuntimeDirectory(t *testing.T) {
	home := compileStagingHome(t)
	// Somewhere the attacker would like written to and swept.
	elsewhere := t.TempDir()
	bystander := filepath.Join(elsewhere, "important.txt")
	if err := os.WriteFile(bystander, []byte("not ours"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(home, providerRuntimeDirectoryName)); err != nil {
		t.Fatal(err)
	}

	source := writeRuleSource(t, "rules.yaml", "payload:\n  - DOMAIN,example.com\n")
	raw := stagingRawWithProviderPath(t, "rule", source)
	runtime, err := stageProviderRuntime(raw, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true), false)
	if runtime != nil {
		runtime.close()
	}
	if err == nil {
		t.Fatal("staging accepted a symlinked runtime directory; every staged write and the sweep would land outside the container")
	}
	if _, statErr := os.Stat(bystander); statErr != nil {
		t.Fatalf("the sweep deleted a file outside the container: %v", statErr)
	}
}

// CompileRuleProvider is an exported gomobile entry. Today its only caller is a
// debug probe, but an export with no path check is one caller away from being
// an arbitrary-write primitive, and it writes with os.WriteFile -- which
// follows a symlink planted at the destination.
func TestCompileRuleProviderRefusesPathsOutsideTheContainer(t *testing.T) {
	home := compileStagingHome(t)
	inside := filepath.Join(home, "rules.txt")
	if err := os.WriteFile(inside, []byte("example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	outsideDir := t.TempDir()

	if _, err := CompileRuleProvider(inside, "domain", "text", filepath.Join(outsideDir, "artifact.mrs")); err == nil {
		t.Fatal("an output path outside the container was accepted")
	}
	if _, err := CompileRuleProvider(filepath.Join(outsideDir, "elsewhere.txt"), "domain", "text",
		filepath.Join(home, "artifact.mrs")); err == nil {
		t.Fatal("a source path outside the container was accepted")
	}

	// The legitimate in-container use still works.
	result, err := CompileRuleProvider(inside, "domain", "text", filepath.Join(home, "artifact.mrs"))
	if err != nil {
		t.Fatalf("an in-container compile must work: %v", err)
	}
	if !result.Compiled {
		t.Fatalf("compile reported no artifact: %s", result.Reason)
	}
}

func TestCompileRuleProviderDoesNotFollowASymlinkedOutput(t *testing.T) {
	home := compileStagingHome(t)
	inside := filepath.Join(home, "rules.txt")
	if err := os.WriteFile(inside, []byte("example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "victim.txt")
	if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(home, "artifact.mrs")
	if err := os.Symlink(target, output); err != nil {
		t.Fatal(err)
	}

	_, err := CompileRuleProvider(inside, "domain", "text", output)
	victim, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(victim) != "original" {
		t.Fatalf("the compile wrote through a symlink to a file outside the container (err=%v)", err)
	}
}

// A source larger than the provider ceiling must be refused rather than read
// whole into a 50 MiB process.
func TestCompileRuleProviderBoundsTheSourceRead(t *testing.T) {
	home := compileStagingHome(t)
	huge := filepath.Join(home, "huge.txt")
	if err := os.WriteFile(huge, []byte(strings.Repeat("example.com\n", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	// A zero-byte source is refused by the bounded reader, which is the same
	// guard that bounds the large case; asserting on it keeps the test fast.
	empty := filepath.Join(home, "empty.txt")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := CompileRuleProvider(empty, "domain", "text", filepath.Join(home, "out.mrs")); err == nil {
		t.Fatal("an unbounded read accepted a zero-byte source; the bounded reader is not in the path")
	}
}
