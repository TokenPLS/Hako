package hako

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/TokenPLS/Hako/tunnel"
	"github.com/sirupsen/logrus"
)

const widgetYAML = `
mode: rule
log-level: info
dns:
  enable: true
  enhanced-mode: fake-ip
  nameserver:
    - 8.8.8.8
proxies:
  - name: probe
    type: socks5
    server: 127.0.0.1
    port: 1080
  - name: second
    type: socks5
    server: 127.0.0.1
    port: 1081
proxy-groups:
  - name: Top
    type: select
    proxies: [Inner, DIRECT]
  - name: Inner
    type: select
    proxies: [probe, second, DIRECT]
rules:
  - MATCH,Top
`

func startWidgetCore(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { logrus.SetOutput(os.Stdout) })
	if err := Setup(testOptions(t)); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	svc, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	if err := svc.Start(widgetYAML); err != nil {
		t.Fatalf("Start: %v", err)
	}
}

func decodeWidget(t *testing.T, payload string) map[string]any {
	t.Helper()
	var decoded map[string]any
	if err := json.Unmarshal([]byte(payload), &decoded); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, payload)
	}
	return decoded
}

func TestWidgetStatsFollowsTheGroupToItsLeaf(t *testing.T) {
	startWidgetCore(t)
	stats := decodeWidget(t, WidgetStatsJSON("Top"))
	if stats["mode"] != "rule" {
		t.Fatalf("mode = %v, want rule", stats["mode"])
	}
	if stats["egress"] != "probe" {
		t.Fatalf("egress = %v, want probe (Top -> Inner -> probe)", stats["egress"])
	}
	for _, key := range []string{"upTotal", "downTotal", "byOutbound", "connections"} {
		if _, ok := stats[key]; !ok {
			t.Fatalf("missing %q:\n%s", key, WidgetStatsJSON("Top"))
		}
	}
	byOutbound := stats["byOutbound"].(map[string]any)
	for _, bucket := range []string{"proxy", "direct", "reject"} {
		entry, ok := byOutbound[bucket].(map[string]any)
		if !ok {
			t.Fatalf("byOutbound.%s missing", bucket)
		}
		for _, key := range []string{"up", "down"} {
			if _, ok := entry[key].(float64); !ok {
				t.Fatalf("byOutbound.%s.%s is not a number: %v", bucket, key, entry[key])
			}
		}
	}
	if _, ok := byOutbound["reject"].(map[string]any)["count"].(float64); !ok {
		t.Fatalf("byOutbound.reject.count missing")
	}
	connections := stats["connections"].(map[string]any)
	for _, key := range []string{"opened", "active", "rejected"} {
		if _, ok := connections[key].(float64); !ok {
			t.Fatalf("connections.%s is not a number: %v", key, connections[key])
		}
	}
	if _, rate := stats["up"]; rate {
		t.Fatalf("a widget sample carries no rate")
	}
}

func TestWidgetStatsLeavesEgressOutWhenItCannotAnswer(t *testing.T) {
	startWidgetCore(t)
	for _, group := range []string{"", "no-such-group"} {
		if _, present := decodeWidget(t, WidgetStatsJSON(group))["egress"]; present {
			t.Fatalf("group %q: egress present, want the key left out", group)
		}
	}
}

func TestWidgetStatsInGlobalModeFollowsGLOBAL(t *testing.T) {
	startWidgetCore(t)
	previous := tunnel.Mode()
	tunnel.SetMode(tunnel.Global)
	t.Cleanup(func() { tunnel.SetMode(previous) })
	stats := decodeWidget(t, WidgetStatsJSON("Top"))
	if stats["mode"] != "global" {
		t.Fatalf("mode = %v, want global", stats["mode"])
	}
	egress, _ := stats["egress"].(string)
	if egress == "" || egress == "GLOBAL" {
		t.Fatalf("egress = %q, want the node GLOBAL currently selects", egress)
	}
}

func TestWidgetGroupIsTheSmallSliceAWidgetDraws(t *testing.T) {
	startWidgetCore(t)
	group := decodeWidget(t, WidgetGroupJSON("Inner", 2))
	if group["name"] != "Inner" || group["type"] != "Selector" || group["now"] != "probe" {
		t.Fatalf("group = %v", group)
	}
	all, _ := group["all"].([]any)
	if len(all) != 2 || all[0] != "probe" || all[1] != "second" {
		t.Fatalf("all with limit 2 = %v, want [probe second] in definition order", all)
	}
	if all, _ := decodeWidget(t, WidgetGroupJSON("Inner", 0))["all"].([]any); len(all) != 3 {
		t.Fatalf("all with no limit = %v, want three members", all)
	}
	if got := WidgetGroupJSON("probe", 0); got != "{}" {
		t.Fatalf("a node is not a group; got %s", got)
	}
	if got := WidgetGroupJSON("no-such-group", 0); got != "{}" {
		t.Fatalf("an unknown name is not a group; got %s", got)
	}
}
