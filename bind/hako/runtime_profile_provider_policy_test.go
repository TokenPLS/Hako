package hako

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/TokenPLS/Hako/tunnel"
)

func TestMacOSTransparentRuntimePreservesFileProviderMetadataRules(t *testing.T) {
	restoreRuntimeProfileForTest(t)
	base, err := os.MkdirTemp("/private/tmp", "hako-mp-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	options := &SetupOptions{
		BasePath: base, WorkingPath: filepath.Join(base, "working"), TempPath: filepath.Join(base, "temp"),
		RuntimeProfile: RuntimeProfileMacOSApplication,
	}
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	published := filepath.Join(options.WorkingPath, "transparent-rules.yaml")
	original := []byte("payload:\n  - PROCESS-NAME,curl\n  - UID,501\n  - IN-USER,alice\n  - SOURCE-APP-SIGNING-ID,com.example.cli\n  - SOURCE-APP-TEAM-ID,ABCDE12345\n  - DOMAIN,example.com\n")
	if err := os.WriteFile(published, original, 0o600); err != nil {
		t.Fatal(err)
	}
	content := fmt.Sprintf(`
rule-providers:
  controlled:
    type: file
    behavior: classical
    format: yaml
    path: %q
rules:
  - RULE-SET,controlled,DIRECT
  - MATCH,DIRECT
`, published)
	platform := newRecordingPlatform()
	platform.underNetworkExtension = true
	service, err := NewService(platform)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Start(content); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })

	entry := service.providerRuntime.entries[providerRuntimeKey("rule", "controlled")]
	runtimePayload, err := os.ReadFile(entry.runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(runtimePayload, original) {
		t.Fatalf("transparent runtime provider was rewritten: %q", runtimePayload)
	}
	if got := tunnel.RuleProviders()["controlled"].Count(); got != 6 {
		t.Fatalf("transparent runtime provider count = %d, want 6", got)
	}
	publishedPayload, err := os.ReadFile(published)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(publishedPayload, original) {
		t.Fatal("transparent runtime staging mutated the published provider")
	}
}
