package hako

import (
	"os"

	C "github.com/TokenPLS/Hako/constant"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TokenPLS/Hako/config"
)

// A provider whose staging was skipped must not be side-updateable.
//
// stageProviderRuntime used to abort the whole activation when it could not
// read a provider's source; on 2026-08-27 it began stepping aside instead, so
// the configuration starts and the provider rides empty, as it does upstream.
// That left a question worth answering out loud rather than reasoning past:
// side-update's contract is that "the Extension writes only its private
// copy-on-write runtime shadow; the App's published revision remains
// immutable" (clash_api_client.go:846-848), and a skipped provider HAS no
// shadow -- its definition still points at the App's own file. If such a
// provider were side-updateable, the Extension would write the published
// revision, which is precisely what the shadow exists to prevent.
//
// It is not, and the mechanism is that entries[] is populated only where
// staging succeeds (provider_runtime.go:593 and :873), while the skip returns
// before that. The side-update path then fails at "provider is not
// side-updateable" (:1174-1177).
//
// That is an implicit invariant -- nothing in the skip says "and therefore no
// entry" -- so it is the kind that regresses in silence when someone later
// makes the skip "more helpful" by recording something. This pins it.
func TestASkippedProviderIsNotSideUpdateable(t *testing.T) {
	setupConfigPipelineTest(t)

	// Inside the container, because a path outside it is refused earlier for a
	// different reason (provider_runtime.go:514) and would test that guard
	// rather than this one.
	home := t.TempDir()
	previousHome := C.Path.HomeDir()
	C.SetHomeDir(home)
	t.Cleanup(func() { C.SetHomeDir(previousHome) })

	absent := filepath.Join(home, "not-there.yaml")
	document := `
proxies:
  - {name: n, type: ss, server: e.com, port: 8388, cipher: aes-128-gcm, password: p}
proxy-providers:
  gone: {type: file, path: ` + absent + `}
`
	raw, err := config.UnmarshalRawConfig([]byte(document))
	if err != nil {
		t.Fatalf("fixture does not parse: %v", err)
	}

	runtime, err := stageProviderRuntime(raw, nePolicy(), false)
	if err != nil {
		t.Fatalf("a provider whose source is missing must not fail staging: %v", err)
	}
	if runtime != nil {
		t.Cleanup(runtime.close)
	}

	// Positive control: staging really did run and really did see this
	// provider. Without it, an empty entries map proves nothing -- a staging
	// step that returned early for an unrelated reason looks identical.
	if path, _ := raw.ProxyProvider["gone"]["path"].(string); path != absent {
		t.Fatalf("the skipped provider's path was rewritten to %q; it must still name the source, "+
			"or this test is measuring a different code path than it describes", path)
	}

	if runtime == nil {
		return // nothing staged at all, so nothing is side-updateable either
	}
	if _, exists := runtime.entries[providerRuntimeKey("proxy", "gone")]; exists {
		t.Fatal("a provider that was skipped during staging has a runtime entry, so side-update would " +
			"accept it -- and with no shadow to write, it would write the App's published revision. " +
			"The skip must return before entries[] is touched.")
	}
}

// The other half: a provider that DID stage keeps its entry, so the skip did
// not quietly disable side-update for everyone.
func TestAStagedProviderKeepsItsRuntimeEntry(t *testing.T) {
	setupConfigPipelineTest(t)

	home := t.TempDir()
	previousHome := C.Path.HomeDir()
	C.SetHomeDir(home)
	t.Cleanup(func() { C.SetHomeDir(previousHome) })

	source := filepath.Join(home, "nodes.yaml")
	if err := os.WriteFile(source, []byte("proxies: []\n"), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	document := `
proxies:
  - {name: n, type: ss, server: e.com, port: 8388, cipher: aes-128-gcm, password: p}
proxy-providers:
  here: {type: file, path: ` + source + `}
`
	raw, err := config.UnmarshalRawConfig([]byte(document))
	if err != nil {
		t.Fatalf("fixture does not parse: %v", err)
	}
	runtime, err := stageProviderRuntime(raw, nePolicy(), false)
	if err != nil {
		t.Fatalf("staging a readable provider failed: %v", err)
	}
	if runtime == nil {
		t.Fatal("a readable file provider produced no runtime at all")
	}
	t.Cleanup(runtime.close)
	if _, exists := runtime.entries[providerRuntimeKey("proxy", "here")]; !exists {
		t.Fatal("a provider that staged normally lost its runtime entry, so side-update would refuse it")
	}
	if path, _ := raw.ProxyProvider["here"]["path"].(string); path == source || !strings.Contains(path, providerRuntimeDirectoryName) {
		t.Fatalf("a staged provider must be redirected to its shadow, got %q", path)
	}
}
