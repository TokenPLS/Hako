package hako

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/sirupsen/logrus"
)

// DoD: the getters return valid JSON reflecting the running core,
// with no HTTP controller started.
func TestCommandGettersReturnJSON(t *testing.T) {
	t.Cleanup(func() { logrus.SetOutput(os.Stdout) })
	if err := Setup(testOptions(t)); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	svc, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	if err := svc.Start(helloYAML); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Status reflects the running core.
	var status map[string]string
	if err := json.Unmarshal([]byte(StatusJSON()), &status); err != nil {
		t.Fatalf("StatusJSON invalid: %v", err)
	}
	if status["status"] != "running" {
		t.Fatalf("status = %q, want running", status["status"])
	}
	if status["mode"] == "" {
		t.Fatal("mode missing")
	}

	// Traffic parses and carries the expected keys.
	var traffic map[string]int64
	if err := json.Unmarshal([]byte(TrafficJSON()), &traffic); err != nil {
		t.Fatalf("TrafficJSON invalid: %v", err)
	}
	for _, k := range []string{"up", "down", "upTotal", "downTotal"} {
		if _, ok := traffic[k]; !ok {
			t.Fatalf("traffic missing key %q", k)
		}
	}

	// Connections snapshot parses.
	var conns map[string]json.RawMessage
	if err := json.Unmarshal([]byte(ConnectionsJSON()), &conns); err != nil {
		t.Fatalf("ConnectionsJSON invalid: %v", err)
	}
	if _, ok := conns["connections"]; !ok {
		t.Fatal("connections key missing")
	}

	// Proxies includes the config's "probe" proxy.
	var proxies struct {
		Proxies map[string]json.RawMessage `json:"proxies"`
	}
	if err := json.Unmarshal([]byte(ProxiesJSON()), &proxies); err != nil {
		t.Fatalf("ProxiesJSON invalid: %v", err)
	}
	if _, ok := proxies.Proxies["probe"]; !ok {
		t.Fatalf("proxies missing 'probe': got keys %v", keysOf(proxies.Proxies))
	}
}

func keysOf(m map[string]json.RawMessage) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}
