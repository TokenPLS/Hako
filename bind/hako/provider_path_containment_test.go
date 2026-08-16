package hako

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TokenPLS/Hako/config"
	C "github.com/TokenPLS/Hako/constant"
)

// A file provider's `path` is subscription-authored text. Upstream guards it
// with C.Path.IsSafePath (rules/provider/parse.go:47) -- but that guard opens
// with `if p.allowUnsafePath || features.CMFA { return true }`
// (constant/path.go), and this fork builds with the cmfa tag by ruling
// (cmd/build_libbox/main.go:58), so in every shipped Hako binary the upstream
// check is a no-op. Staging then reads the path itself and rewrites the
// definition to the staged copy, so nothing downstream ever sees the original
// either.
//
// Containment therefore has to be enforced here. Threat model: the
// subscription author, who writes `path: ../../../../etc/passwd` and reads the
// answer out of whatever the core says about the file.

func stagingRawWithProviderPath(t *testing.T, kind, path string) *config.RawConfig {
	t.Helper()
	raw := &config.RawConfig{}
	definition := map[string]any{"type": "file", "path": path}
	if kind == "rule" {
		definition["behavior"] = "classical"
		definition["format"] = "yaml"
		raw.RuleProvider = map[string]map[string]any{"probe": definition}
	} else {
		raw.ProxyProvider = map[string]map[string]any{"probe": definition}
	}
	return raw
}

func TestStagingRefusesAProviderPathOutsideTheContainer(t *testing.T) {
	home := compileStagingHome(t)
	// A real file outside the container, standing in for /etc/passwd.
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("root:x:0:0:secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, kind := range []string{"rule", "proxy"} {
		for _, spelling := range []string{
			outside,
			filepath.Join(home, "..", filepath.Base(filepath.Dir(outside)), "secret.txt"),
		} {
			raw := stagingRawWithProviderPath(t, kind, spelling)
			runtime, err := stageProviderRuntime(raw, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true), false)
			if runtime != nil {
				runtime.close()
			}
			if err == nil {
				t.Fatalf("%s provider with path %q was staged; a subscription can read any file the process can", kind, spelling)
			}
			// The refusal must not quote the path back: the reader's own
			// configuration is what the attacker is probing with.
			if strings.Contains(err.Error(), "secret") {
				t.Fatalf("%s: the refusal echoes the attacker-controlled path: %v", kind, err)
			}
		}
	}
}

func TestStagingAcceptsAProviderPathInsideTheContainer(t *testing.T) {
	home := compileStagingHome(t)
	inside := filepath.Join(home, "published-rule.yaml")
	if err := os.WriteFile(inside, []byte("payload:\n  - DOMAIN,example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	raw := stagingRawWithProviderPath(t, "rule", inside)
	runtime, err := stageProviderRuntime(raw, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true), false)
	if err != nil {
		t.Fatalf("an in-container provider must stage: %v", err)
	}
	defer runtime.close()

	// A relative path resolves against the home directory and must work too --
	// that is how the App writes them.
	relative := stagingRawWithProviderPath(t, "rule", "published-rule.yaml")
	relativeRuntime, err := stageProviderRuntime(relative, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true), false)
	if err != nil {
		t.Fatalf("a relative in-container provider must stage: %v", err)
	}
	relativeRuntime.close()
	_ = C.Path.HomeDir()
}

// A symlink inside the container pointing outside it is the same attack with
// one more step, and a purely lexical containment check waves it through.
func TestStagingRefusesASymlinkEscapingTheContainer(t *testing.T) {
	home := compileStagingHome(t)
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("root:x:0:0:secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(home, "innocent.yaml")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}

	raw := stagingRawWithProviderPath(t, "rule", link)
	runtime, err := stageProviderRuntime(raw, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true), false)
	if runtime != nil {
		runtime.close()
	}
	if err == nil {
		t.Fatal("a symlink escaping the container was staged; containment must resolve links, not just clean the path")
	}
}

// The compile refusal reason travels into the manifest and the product log. It
// must never carry the file's own bytes: that is what turns a path-traversal
// read into a working oracle, and provider_resource.go:405-408 already states
// the rule for the sibling path ("record only the index -- never the entry
// text").
func TestCompileRefusalDoesNotEchoFileContent(t *testing.T) {
	secret := "TOKEN-abcdef0123456789-DO-NOT-LOG"
	reason := ruleProviderCompileRefusal([]byte(secret+"\n"), "classical", "yaml")
	if reason == "" {
		t.Fatal("a non-rule line must still be refused")
	}
	if strings.Contains(reason, secret) || strings.Contains(reason, secret[:12]) {
		t.Fatalf("the refusal reason echoes file content: %q", reason)
	}

	compilation := compileRuleProviderPayload([]byte(secret+"\n"), "classical", "yaml")
	if compilation.Reason == "" {
		t.Fatal("the compiler must still refuse")
	}
	if strings.Contains(compilation.Reason, secret) || strings.Contains(compilation.Reason, secret[:12]) {
		t.Fatalf("the compiler's reason echoes file content: %q", compilation.Reason)
	}
	// It must still say enough to act on: which line, and what was wrong.
	if !strings.Contains(compilation.Reason, "1") {
		t.Fatalf("the reason names no line number, so it cannot be acted on: %q", compilation.Reason)
	}
}
