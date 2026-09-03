package hako

import (
	"strings"
	"testing"
)

func TestSubscriptionToleranceMatchesUpstreamLineSkipping(t *testing.T) {
	payload := strings.Join([]string{
		"ss://YWVzLTEyOC1nY206cGFzcw==@good-one.example:8388#good-1",
		"newproto://whatever@host:1234#unknown-scheme-line",
		"juicity://uuid:pass@host:443#recognized-but-core-unsupported",
		"ss://%%%broken%%%",
		"trojan://secret@good-two.example:443?hakoUnmappedField=1#good-2",
	}, "\n")

	t.Run("subscription context keeps every readable node", func(t *testing.T) {
		proxies, err := convertProxyShareLinks([]byte(payload), true)
		if err != nil {
			t.Fatalf("tolerant conversion failed: %v", err)
		}
		if len(proxies) != 2 {
			names := make([]string, 0, len(proxies))
			for _, p := range proxies {
				names = append(names, p["name"].(string))
			}
			t.Fatalf("want the 2 readable nodes, got %d: %v", len(proxies), names)
		}
	})
	t.Run("interactive context still refuses loudly", func(t *testing.T) {
		if _, err := convertProxyShareLinks([]byte(payload), false); err == nil {
			t.Fatal("the strict path must keep refusing a payload with unreadable lines")
		}
	})
	t.Run("nothing readable still reports instead of an empty ride", func(t *testing.T) {
		if _, err := convertProxyShareLinks([]byte("newproto://a@b:1#only-line"), true); err == nil {
			t.Fatal("a payload with zero readable nodes must still return an error")
		}
	})
}
