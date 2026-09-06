package hako

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TokenPLS/Hako/config"
	C "github.com/TokenPLS/Hako/constant"
)

// substoreShapedPayload is the shape the reader's Sub-Store link served: a
// proxy list in some other client's dialect. No `proxies:` mapping and no
// `://` anywhere, so neither YAML nor the share-link reader can make anything
// of it -- and neither can upstream's convert.ConvertsV2Ray, which is the
// point: what this core refuses here, mihomo refuses at Initial() too, so a
// verbatim staged copy can never hand the core a node that skipped the
// egress strip.
const substoreShapedPayload = "KyCloud-HK01 = ss, 198.51.100.20, 8388, " +
	"encrypt-method=aes-256-gcm, password=secret\n" +
	"KyCloud-SG02 = ss, 198.51.100.21, 8388, " +
	"encrypt-method=aes-256-gcm, password=secret\n"

func rawWithFileProxyProvider(t *testing.T, name, content string) *config.RawConfig {
	t.Helper()
	source := filepath.Join(C.Path.HomeDir(), name)
	if err := os.WriteFile(source, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	raw := &config.RawConfig{}
	raw.ProxyProvider = map[string]map[string]any{
		"air": {"type": "file", "path": source},
	}
	return raw
}

func TestAnUnreadableProxyProviderDoesNotEndTheActivation(t *testing.T) {
	if _, _, err := sanitizeProxyProviderPayloadForIOS("", []byte(substoreShapedPayload), false); err == nil {
		t.Fatal("the payload parsed; this fixture no longer reproduces the reader's shape")
	}

	t.Run("unreadable payload stages verbatim and the activation continues", func(t *testing.T) {
		home := compileStagingHome(t)
		raw := rawWithFileProxyProvider(t, "substore.txt", substoreShapedPayload)

		runtime, err := stageProviderRuntime(raw, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true), false)
		if err != nil {
			t.Fatalf("an unreadable proxy provider still ends the activation: %v", err)
		}
		defer runtime.close()

		staged, err := os.ReadFile(raw.ProxyProvider["air"]["path"].(string))
		if err != nil {
			t.Fatal(err)
		}
		if string(staged) != substoreShapedPayload {
			t.Fatalf("staged %d bytes that are not the published source", len(staged))
		}
		entry := manifestEntry(t, home, "proxy", "air")
		if !strings.Contains(entry, `"unreadableWarn"`) {
			t.Fatalf("the failure left no account in the manifest: %s", entry)
		}
	})

	t.Run("readable payload still passes the egress strip", func(t *testing.T) {
		compileStagingHome(t)
		readable := "proxies:\n  - name: a\n    type: ss\n    server: 198.51.100.22\n    port: 443\n    cipher: aes-128-gcm\n    password: x\n    interface-name: en0\n"
		raw := rawWithFileProxyProvider(t, "readable.yaml", readable)

		runtime, err := stageProviderRuntime(raw, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true), false)
		if err != nil {
			t.Fatalf("stage: %v", err)
		}
		defer runtime.close()

		staged, err := os.ReadFile(raw.ProxyProvider["air"]["path"].(string))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(staged), "interface-name") {
			t.Fatal("the tolerant branch swallowed the egress strip; a readable payload must still be sanitized")
		}
	})
}
