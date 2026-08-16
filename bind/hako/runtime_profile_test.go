package hako

import (
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
)

func TestNormalizeRuntimeProfile(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  runtimeProfile
	}{
		{name: "legacy empty defaults to iOS packet tunnel", want: runtimeProfileIOSPacketTunnel},
		{name: "iOS packet tunnel", input: RuntimeProfileIOSPacketTunnel, want: runtimeProfileIOSPacketTunnel},
		{name: "macOS packet tunnel", input: RuntimeProfileMacOSPacketTunnel, want: runtimeProfileMacOSPacketTunnel},
		{name: "macOS application", input: RuntimeProfileMacOSApplication, want: runtimeProfileMacOSApplication},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := normalizeRuntimeProfile(test.input)
			if err != nil {
				t.Fatalf("normalizeRuntimeProfile(%q): %v", test.input, err)
			}
			if got != test.want {
				t.Fatalf("normalizeRuntimeProfile(%q) = %q, want %q", test.input, got, test.want)
			}
		})
	}
}

func TestMacOSRuntimeProfileWithoutBudgetKeepsRuntimeDefaults(t *testing.T) {
	restoreRuntimeProfileForTest(t)
	originalGC := debug.SetGCPercent(73)
	originalProcs := runtime.GOMAXPROCS(0)
	wantProcs := min(2, runtime.NumCPU())
	runtime.GOMAXPROCS(wantProcs)
	t.Cleanup(func() {
		debug.SetGCPercent(originalGC)
		runtime.GOMAXPROCS(originalProcs)
	})

	opts := testOptions(t)
	opts.RuntimeProfile = RuntimeProfileMacOSApplication
	if err := Setup(opts); err != nil {
		t.Fatalf("Setup macOS profile: %v", err)
	}
	if previous := debug.SetGCPercent(73); previous != 73 {
		t.Fatalf("macOS profile changed GC percent to %d without a budget", previous)
	}
	if got := runtime.GOMAXPROCS(0); got != wantProcs {
		t.Fatalf("macOS profile changed GOMAXPROCS to %d without an explicit cap; want %d", got, wantProcs)
	}
}

func TestNormalizeRuntimeProfileRejectsUnknownValue(t *testing.T) {
	if _, err := normalizeRuntimeProfile("macosRootHelper"); err == nil || !strings.Contains(err.Error(), "RuntimeProfile") {
		t.Fatalf("unknown RuntimeProfile error = %v", err)
	}
}

func TestSetupRuntimeProfileDefaultsToLegacyIOSBehavior(t *testing.T) {
	restoreRuntimeProfileForTest(t)
	opts := testOptions(t)
	if err := Setup(opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if got := currentRuntimeProfile(); got != runtimeProfileIOSPacketTunnel {
		t.Fatalf("currentRuntimeProfile = %q, want %q", got, runtimeProfileIOSPacketTunnel)
	}
}

func TestSetupRuntimeProfileChangeRequiresRestart(t *testing.T) {
	restoreRuntimeProfileForTest(t)
	activeCoreCount.Store(0)
	t.Cleanup(func() { activeCoreCount.Store(0) })

	ios := testOptions(t)
	ios.RuntimeProfile = RuntimeProfileIOSPacketTunnel
	if err := Setup(ios); err != nil {
		t.Fatalf("Setup iOS profile: %v", err)
	}

	activeCoreCount.Store(1)
	macOS := testOptions(t)
	macOS.RuntimeProfile = RuntimeProfileMacOSApplication
	if err := Setup(macOS); err == nil || !strings.Contains(err.Error(), "requires restart") {
		t.Fatalf("running profile change error = %v", err)
	}
	if got := currentRuntimeProfile(); got != runtimeProfileIOSPacketTunnel {
		t.Fatalf("rejected change altered RuntimeProfile to %q", got)
	}
}

func restoreRuntimeProfileForTest(t *testing.T) {
	t.Helper()
	previous := setupRuntimeProfile.Load()
	setupRuntimeProfile.Store(uint32(runtimeProfileIOSPacketTunnel))
	t.Cleanup(func() {
		setupRuntimeProfile.Store(previous)
	})
}
