package hako

import (
	"encoding/json"
	"strings"
	"testing"

	tun "github.com/metacubex/sing-tun"
)

// Diagnostics must carry the LIVE window report while a gVisor stack runs and
// omit the keys entirely when none does — consumers distinguish "no stack"
// from "window zero".
func TestRuntimeDiagnosticsCarriesGVisorWindow(t *testing.T) {
	service := &BoxService{}
	if strings.Contains(service.RuntimeDiagnosticsJSON(), "gvisorTCPWindow") {
		t.Fatal("window keys must be absent without a live gVisor stack")
	}
	prior := tun.GVisorTCPWindowSnapshot
	t.Cleanup(func() { tun.GVisorTCPWindowSnapshot = prior })
	tun.GVisorTCPWindowSnapshot = func() tun.GVisorTCPWindowReport {
		return tun.GVisorTCPWindowReport{
			MinBytes: 4096, DefaultBytes: 32768, MaxBytes: 131072,
			TCPConnections: 3, ReceiveOccupancyP50Bytes: 20000, ReceiveOccupancyP95Bytes: 118000,
			ReceiveOccupancyMaxBytes: 120000, ConnectionsNearReceiveMax: 1,
		}
	}
	var diagnostics map[string]any
	if err := json.Unmarshal([]byte(service.RuntimeDiagnosticsJSON()), &diagnostics); err != nil {
		t.Fatal(err)
	}
	if diagnostics["gvisorTCPWindowMaxBytes"].(float64) != 131072 ||
		diagnostics["gvisorTCPWindowConnections"].(float64) != 3 ||
		diagnostics["gvisorTCPReceiveOccupancyMaxBytes"].(float64) != 120000 ||
		diagnostics["gvisorTCPConnectionsNearReceiveMax"].(float64) != 1 {
		t.Fatalf("live window report not surfaced: %v", diagnostics)
	}
}
