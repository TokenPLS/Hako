package hako

import (
	"os"
	"path/filepath"
	"testing"

	tun "github.com/metacubex/sing-tun"
)

// TestApplyGVisorTCPBufferOverride covers the on-device window wiring: an
// App-Group file lets an out-of-band benchmark tool tune the gVisor TCP window through
// Setup, without a public SetupOptions knob. A missing/invalid/non-positive file
// leaves the historical 20 KiB default untouched (a no-op in production).
func TestApplyGVisorTCPBufferOverride(t *testing.T) {
	original := tun.GVisorTCPBufferBytes
	t.Cleanup(func() { tun.GVisorTCPBufferBytes = original })

	base := t.TempDir()
	overridePath := filepath.Join(base, gVisorTCPBufferOverrideFile)

	// Absent file → default untouched.
	tun.GVisorTCPBufferBytes = 20 * 1024
	applyGVisorTCPBufferOverride(base)
	if tun.GVisorTCPBufferBytes != 20*1024 {
		t.Fatalf("absent override changed the window: %d", tun.GVisorTCPBufferBytes)
	}

	// Valid override → applied to the shared sing-tun knob.
	if err := os.WriteFile(overridePath, []byte("131072\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	applyGVisorTCPBufferOverride(base)
	if tun.GVisorTCPBufferBytes != 131072 {
		t.Fatalf("valid override not applied: %d", tun.GVisorTCPBufferBytes)
	}

	// Invalid / non-positive → ignored, so a bad value cannot produce an invalid
	// stack or silently shrink the window.
	for _, bad := range []string{"0", "-5", "not-a-number", ""} {
		tun.GVisorTCPBufferBytes = 20 * 1024
		if err := os.WriteFile(overridePath, []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		applyGVisorTCPBufferOverride(base)
		if tun.GVisorTCPBufferBytes != 20*1024 {
			t.Fatalf("invalid override %q changed the window: %d", bad, tun.GVisorTCPBufferBytes)
		}
	}
}
