package hako

import (
	"encoding/json"
	"testing"

	tun "github.com/metacubex/sing-tun"
)

func TestRuntimeDiagnosticsIncludesGVisorPacketIO(t *testing.T) {
	original := tun.GVisorPacketIOSnapshot
	t.Cleanup(func() { tun.GVisorPacketIOSnapshot = original })
	tun.GVisorPacketIOSnapshot = func() tun.GVisorPacketIOReport {
		return tun.GVisorPacketIOReport{
			IngressReadCalls:       11,
			IngressReadWouldBlock:  23,
			IngressReadPackets:     12,
			IngressReadBytes:       13,
			IngressReadErrors:      14,
			IngressDispatchPackets: 15,
			IngressDispatchBytes:   16,
			ProcessorQueueDepth:    17,
			ProcessorQueuePeak:     18,
			EgressWriteCalls:       19,
			EgressWritePackets:     20,
			EgressWriteBytes:       21,
			EgressWriteErrors:      22,
		}
	}

	service := &BoxService{}
	var diagnostics map[string]any
	if err := json.Unmarshal([]byte(service.RuntimeDiagnosticsJSON()), &diagnostics); err != nil {
		t.Fatal(err)
	}
	want := map[string]float64{
		"corePacketIngressReadCalls":       11,
		"corePacketIngressReadWouldBlock":  23,
		"corePacketIngressReadPackets":     12,
		"corePacketIngressReadBytes":       13,
		"corePacketIngressReadErrors":      14,
		"corePacketIngressDispatchPackets": 15,
		"corePacketIngressDispatchBytes":   16,
		"corePacketProcessorQueueDepth":    17,
		"corePacketProcessorQueuePeak":     18,
		"corePacketEgressWriteCalls":       19,
		"corePacketEgressWritePackets":     20,
		"corePacketEgressWriteBytes":       21,
		"corePacketEgressWriteErrors":      22,
	}
	for key, value := range want {
		if got := diagnostics[key]; got != value {
			t.Fatalf("%s = %#v, want %v (all diagnostics: %#v)", key, got, value, diagnostics)
		}
	}
}
