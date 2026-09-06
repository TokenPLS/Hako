package hako

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	C "github.com/TokenPLS/Hako/constant"
	"github.com/TokenPLS/Hako/listener/sing_tun"
	tun "github.com/metacubex/sing-tun"
)

// A tunnel started with Include All Networks carries traffic through the gVisor stack and
// through nothing else: the system and mixed stacks hand the packets they re-inject to the
// kernel, and under Include All Networks the kernel drops them on the way out, so the
// session looks alive (proxy tests run on the extension's own sockets) while every flow
// through the tun goes nowhere. sing-tun knows this and refuses `system`/`mixed` when it is
// told about the setting; nobody told it, so the failure was silent. Two halves close it:
// the override moves the stack where it can work and says so, and the stack layer is told
// the truth so that anything the override misses fails loudly at Start instead.

func withIncludeAllNetworks(t *testing.T, on bool) {
	t.Helper()
	previous := includeAllNetworksRequested.Load()
	includeAllNetworksRequested.Store(on)
	t.Cleanup(func() { includeAllNetworksRequested.Store(previous) })
}

func tunStackDocument(stack string) string {
	document := "tun:\n  enable: true\n"
	if stack != "" {
		document += "  stack: " + stack + "\n"
	}
	return document + "proxies: []\nproxy-groups: []\nrules:\n  - MATCH,DIRECT\n"
}

func TestIncludeAllNetworksMovesSystemAndMixedToGVisor(t *testing.T) {
	for _, tc := range []struct {
		name    string
		written string
		on      bool
		want    C.TUNStack
	}{
		{"system under include-all-networks", "system", true, C.TunGvisor},
		{"mixed under include-all-networks", "mixed", true, C.TunGvisor},
		{"gvisor under include-all-networks", "gvisor", true, C.TunGvisor},
		{"unset under include-all-networks", "", true, C.TunGvisor},
		{"system without it", "system", false, C.TunSystem},
		{"mixed without it", "mixed", false, C.TunMixed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withIncludeAllNetworks(t, tc.on)
			_, ours := parseBoth(t, tunStackDocument(tc.written))
			finalizeConfigForIOS(ours, true)
			if ours.General.Tun.Stack != tc.want {
				t.Fatalf("tun.stack %q with includeAllNetworks=%v finalized to %v, want %v",
					tc.written, tc.on, ours.General.Tun.Stack, tc.want)
			}
		})
	}
}

// The setting belongs to a packet tunnel. A process that is not one (the macOS application
// profile) has no NEPacketTunnelNetworkSettings to carry it, so the override must not fire
// there even if the bit is somehow set.
func TestIncludeAllNetworksLeavesTheStackAloneOutsideAPacketTunnel(t *testing.T) {
	withIncludeAllNetworks(t, true)
	_, ours := parseBoth(t, tunStackDocument("system"))
	finalizeConfigForApple(ours, runtimePolicyFor(runtimeProfileMacOSApplication, false))
	if ours.General.Tun.Stack != C.TunSystem {
		t.Fatalf("the application profile moved tun.stack to %v; only packet tunnels run under Include All Networks",
			ours.General.Tun.Stack)
	}
}

func tunStackDeviations(t *testing.T, document string, policy appleRuntimePolicy) []configDeviation {
	t.Helper()
	all, err := collectConfigDeviations(document, policy)
	if err != nil {
		t.Fatalf("collectConfigDeviations: %v", err)
	}
	var rows []configDeviation
	for _, deviation := range all {
		if deviation.Field == "tun.stack" {
			rows = append(rows, deviation)
		}
	}
	return rows
}

// The report row exists exactly when the move happened: written system or mixed under
// Include All Networks. A written gvisor, a silent configuration, a tunnel without the
// setting, and a process that is not a packet tunnel all report nothing ( nonevent
// discipline).
func TestIncludeAllNetworksReportsTheMoveAndOnlyTheMove(t *testing.T) {
	tunnel := runtimePolicyFor(runtimeProfileIOSPacketTunnel, true)

	withIncludeAllNetworks(t, true)
	for _, written := range []string{"system", "mixed"} {
		rows := tunStackDeviations(t, tunStackDocument(written), tunnel)
		if len(rows) != 1 {
			t.Fatalf("%s under Include All Networks: want one tun.stack row, got %d: %+v", written, len(rows), rows)
		}
		row := rows[0]
		if row.Category != deviationForced || row.Given != written || !row.Written || !row.Recoverable {
			t.Fatalf("%s: row = %+v; want forced, given %q, written, recoverable", written, row, written)
		}
		if !strings.Contains(row.Effective, "gvisor") {
			t.Fatalf("%s: effective %q does not name the stack the tunnel actually runs", written, row.Effective)
		}
		if row.Alternative == "" {
			t.Fatalf("%s: a recoverable move must tell the reader how to recover", written)
		}
	}
	for _, written := range []string{"gvisor", ""} {
		if rows := tunStackDeviations(t, tunStackDocument(written), tunnel); len(rows) != 0 {
			t.Fatalf("tun.stack %q moved nothing, yet the report says %+v", written, rows)
		}
	}
	if rows := tunStackDeviations(t, tunStackDocument("system"), runtimePolicyFor(runtimeProfileMacOSApplication, false)); len(rows) != 0 {
		t.Fatalf("the application profile reports a packet-tunnel move: %+v", rows)
	}

	withIncludeAllNetworks(t, false)
	if rows := tunStackDeviations(t, tunStackDocument("system"), tunnel); len(rows) != 0 {
		t.Fatalf("without Include All Networks the stack stays as written, yet the report says %+v", rows)
	}
}

// Setup carries the extension's reading of NETunnelProviderProtocol.includeAllNetworks into
// both consumers: the override that moves the stack, and sing-tun's own guard, which turns
// a stack the override did not catch into a loud Start failure instead of a silent tunnel.
func TestSetupCarriesIncludeAllNetworksToTheOverrideAndTheStack(t *testing.T) {
	withIncludeAllNetworks(t, false)
	previousStackFlag := sing_tun.IncludeAllNetworks
	t.Cleanup(func() { sing_tun.IncludeAllNetworks = previousStackFlag })

	base := t.TempDir()
	options := func(on bool) *SetupOptions {
		return &SetupOptions{
			BasePath:           base,
			WorkingPath:        filepath.Join(base, "working"),
			TempPath:           filepath.Join(base, "temp"),
			IncludeAllNetworks: on,
		}
	}
	if err := Setup(options(true)); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if !includeAllNetworksRequested.Load() || !sing_tun.IncludeAllNetworks {
		t.Fatalf("Setup(IncludeAllNetworks: true) left override=%v stack=%v",
			includeAllNetworksRequested.Load(), sing_tun.IncludeAllNetworks)
	}
	if err := Setup(options(false)); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if includeAllNetworksRequested.Load() || sing_tun.IncludeAllNetworks {
		t.Fatalf("Setup(IncludeAllNetworks: false) left override=%v stack=%v",
			includeAllNetworksRequested.Load(), sing_tun.IncludeAllNetworks)
	}

	// The setting lives on the tunnel configuration and only changes with a reconnect, so a
	// Setup that flips it while a core is running is a caller error, like RuntimeProfile.
	activeCoreCount.Add(1)
	t.Cleanup(func() { activeCoreCount.Add(-1) })
	err := Setup(options(true))
	if err == nil || !strings.Contains(err.Error(), "IncludeAllNetworks") || !strings.Contains(err.Error(), "restart") {
		t.Fatalf("flipping IncludeAllNetworks under an active core: err = %v; want a restart-required refusal", err)
	}
	if err := Setup(options(false)); err != nil {
		t.Fatalf("Setup with the unchanged value under an active core must still pass: %v", err)
	}
}

// The passthrough is only worth anything if sing-tun really refuses the two stacks under the
// setting. This pins the upstream contract the loud-failure half relies on.
func TestSingTunRefusesSystemAndMixedUnderIncludeAllNetworks(t *testing.T) {
	for _, stack := range []string{"system", "mixed"} {
		_, err := tun.NewStack(stack, tun.StackOptions{IncludeAllNetworks: true})
		if !errors.Is(err, tun.ErrIncludeAllNetworks) {
			t.Fatalf("NewStack(%q) under IncludeAllNetworks: err = %v; want ErrIncludeAllNetworks", stack, err)
		}
	}
}
