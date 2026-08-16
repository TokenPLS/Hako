//go:build with_gvisor

package hako

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TokenPLS/Hako/adapter"
	"github.com/TokenPLS/Hako/config"
)

// TestOfficialOutboundCatalogParses turns docs/config.yaml into an executable
// schema fixture for every outbound shipped by the pinned mihomo parser. It is
// intentionally production-tag-only: WireGuard, MASQUE and Tailscale require
// with_gvisor, which Hako's iOS XCFramework always enables.
func TestOfficialOutboundCatalogParses(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "config.yaml"))
	if err != nil {
		t.Fatalf("read official config catalog: %v", err)
	}
	raw, err := config.UnmarshalRawConfig(data)
	if err != nil {
		t.Fatalf("unmarshal official config catalog: %v", err)
	}

	type fixture struct {
		typeName string
		ordinal  int
		mapping  map[string]any
	}
	fixtures := make([]fixture, 0, len(raw.Proxy)+1)
	seenByType := map[string]int{}
	for _, original := range raw.Proxy {
		mapping := cloneMapping(original)
		typeName, _ := mapping["type"].(string)
		if typeName == "" {
			continue
		}
		normalizeOfficialCatalogPlaceholders(typeName, mapping)
		// The catalog's OpenVPN PEM is explanatory placeholder text. Preserve all
		// documented schema fields but use a parseable PEM envelope and the
		// documented auth-user-pass branch so this remains an offline schema test.
		if typeName == "openvpn" {
			mapping["ca"] = "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----"
			mapping["cert"] = ""
			mapping["key"] = ""
			mapping["username"] = "fixture"
			mapping["password"] = "fixture"
		}
		ordinal := seenByType[typeName]
		seenByType[typeName]++
		fixtures = append(fixtures, fixture{typeName: typeName, ordinal: ordinal, mapping: mapping})
	}
	// The official catalog documents reject through built-ins/rules rather
	// than a named proxy. Keep it in the parser matrix explicitly.
	fixtures = append(fixtures, fixture{typeName: "reject", mapping: map[string]any{"name": "reject-probe", "type": "reject"}})
	seenByType["reject"]++

	expectedTypes := []string{
		"ss", "ssr", "socks5", "http", "vmess", "vless", "snell", "trojan",
		"hysteria", "hysteria2", "wireguard", "tuic", "shadowquic", "gost-relay", "direct",
		"dns", "reject", "rematch", "ssh", "mieru", "anytls", "sudoku", "masque",
		"trusttunnel", "openvpn", "tailscale",
	}
	for _, typeName := range expectedTypes {
		if seenByType[typeName] == 0 {
			t.Errorf("official config catalog has no %q outbound fixture", typeName)
		}
	}
	if len(seenByType) != len(expectedTypes) {
		t.Fatalf("official config catalog types = %d, want %d; parser inventory must classify every type", len(seenByType), len(expectedTypes))
	}

	for _, item := range fixtures {
		item := item
		t.Run(fmt.Sprintf("%s-%02d", item.typeName, item.ordinal), func(t *testing.T) {
			proxy, err := adapter.ParseProxy(item.mapping)
			if err != nil {
				t.Fatalf("parse official %s fixture: %v", item.typeName, err)
			}
			if err := proxy.Close(); err != nil {
				t.Fatalf("close %s fixture: %v", item.typeName, err)
			}
		})
	}
}

// normalizeOfficialCatalogPlaceholders replaces values which docs/config.yaml
// deliberately uses to explain a choice or the expected wire format. It keeps
// every documented field in the fixture: this test exercises the complete
// example shape, not a reduced hand-written proxy.
func normalizeOfficialCatalogPlaceholders(typeName string, mapping map[string]any) {
	if typeName == "ss" {
		for _, key := range []string{"server", "password"} {
			if choices, ok := mapping[key].([]any); ok && len(choices) > 0 {
				mapping[key] = choices[0]
			}
		}
		if pluginOptions, ok := mapping["plugin-opts"].(map[string]any); ok {
			pluginOptions = cloneMapping(pluginOptions)
			if choices, ok := pluginOptions["password"].([]any); ok && len(choices) > 0 {
				pluginOptions["password"] = choices[0]
			}
			mapping["plugin-opts"] = pluginOptions
		}
	}
	if typeName != "vless" {
		return
	}

	if value, ok := mapping["encryption"].(string); ok && strings.Contains(value, "(") {
		mapping["encryption"] = "none"
	}
	reality, ok := mapping["reality-opts"].(map[string]any)
	if !ok || reality["public-key"] != "xxx" {
		return
	}
	reality = cloneMapping(reality)
	key := make([]byte, 32)
	for i := range key {
		key[i] = 1
	}
	reality["public-key"] = base64.RawURLEncoding.EncodeToString(key)
	reality["short-id"] = "0123456789abcdef"
	mapping["reality-opts"] = reality
}

func cloneMapping(source map[string]any) map[string]any {
	result := make(map[string]any, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}
