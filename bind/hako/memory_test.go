package hako

import (
	"os"
	"testing"

	"github.com/TokenPLS/Hako/tunnel/statistic"
)

// fakeTracker is a minimal statistic.Tracker recording that Close was called.
// Only ID/Close are exercised by Join/Range/Leave; the rest of the interface
// is satisfied by the embedded (nil) Tracker and never called here.
type fakeTracker struct {
	statistic.Tracker
	closed bool
}

func (f *fakeTracker) ID() string   { return "hako-test-tracker" }
func (f *fakeTracker) Close() error { f.closed = true; return nil }

// DoD: the pressure handler records evidence, counts the event, releases memory,
// and does not panic. The GCD source that invokes it is darwin-only and exercised on-device
// .
//
// This test twice asserted the opposite of what it asserts now. It first required the handler
// to close every tracked connection on EVERY event; that was the defect. It was then narrowed
// to shed only near the configured budget. sing-box sheds in neither case -- see
// memory_pressure_gate_test.go for that comparison and for the no-teardown assertions across
// footprints.
//
// What this test uniquely covers is that the evidence file actually lands on disk, which is
// the part of the response a consumer can read afterwards.
func TestHandleMemoryPressureRecordsEvidenceAndKeepsConnections(t *testing.T) {
	const softLimit = 50 << 20
	path := setupOOMEvidenceTest(t)
	before := memoryPressureEventCount.Load()

	tracker := &fakeTracker{}
	statistic.DefaultManager.Join(tracker)
	t.Cleanup(func() { statistic.DefaultManager.Leave(tracker) })

	// 39.58 MiB of 50 MiB is the first pressure event actually observed on a device, i.e. the
	// exact case the removed teardown existed for.
	handleMemoryPressureWith(39_580_000, softLimit)

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("pressure evidence was not persisted: %v", err)
	}
	if tracker.closed {
		t.Fatal("closed a live connection from the pressure NOTIFICATION; sing-box does not " +
			"shed there either. It does shed from its own threshold machine, which we have not " +
			"ported yet")
	}
	if got := memoryPressureEventCount.Load(); got != before+1 {
		t.Fatalf("memory pressure event count = %d, want %d", got, before+1)
	}
}

// startMemoryPressureMonitor must be safe to call (idempotent; no-op off
// darwin). On darwin/cgo it arms the real GCD source.
func TestStartMemoryPressureMonitorIsSafe(t *testing.T) {
	startMemoryPressureMonitor()
	startMemoryPressureMonitor()
}

func TestArmMemoryPressureMonitorForNetworkExtensionProfiles(t *testing.T) {
	tests := []struct {
		name     string
		profile  runtimeProfile
		appOnly  bool
		wantArms int
	}{
		{name: "iOS packet tunnel without a budget", profile: runtimeProfileIOSPacketTunnel, wantArms: 1},
		{name: "macOS packet tunnel without a budget", profile: runtimeProfileMacOSPacketTunnel, wantArms: 1},
		{name: "macOS containing application", profile: runtimeProfileMacOSApplication},
		{name: "app-only preflight", profile: runtimeProfileIOSPacketTunnel, appOnly: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			arms := 0
			armMemoryPressureMonitorForRuntime(test.profile, test.appOnly, func() {
				arms++
			})
			if arms != test.wantArms {
				t.Fatalf("memory pressure monitor arms = %d, want %d", arms, test.wantArms)
			}
		})
	}
}
