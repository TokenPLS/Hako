package hako

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
)

func TestReloadSetupOptionsKeepsTheRunningCore(t *testing.T) {
	opts := testOptions(t)
	opts.MemoryLimit = 50 << 20
	if err := Setup(opts); err != nil {
		t.Fatal(err)
	}
	service, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	if err := service.Start(helloYAML); err != nil {
		t.Fatal(err)
	}
	decode := func() map[string]any {
		var diagnostics map[string]any
		if err := json.Unmarshal([]byte(service.RuntimeDiagnosticsJSON()), &diagnostics); err != nil {
			t.Fatal(err)
		}
		return diagnostics
	}
	before := decode()
	if err := ReloadSetupOptions(&RuntimeSetupOptions{
		SoftMemoryLimit: 32 << 20,
		GCPercent:       20,
		LogMaxLines:     200,
	}); err != nil {
		t.Fatal(err)
	}
	after := decode()
	for _, key := range []string{"processIdentifier", "startTimeUnix", "inboundCount", "outboundCount"} {
		if before[key] != after[key] {
			t.Fatalf("live reload changed %s from %v to %v", key, before[key], after[key])
		}
	}
	if after["running"] != true {
		t.Fatalf("live reload stopped core: %#v", after)
	}
}

func TestReloadSetupOptionsAppliesSafeLiveFields(t *testing.T) {
	opts := testOptions(t)
	opts.MemoryLimit = 50 << 20
	if err := Setup(opts); err != nil {
		t.Fatal(err)
	}

	want := &RuntimeSetupOptions{
		SoftMemoryLimit: 48 << 20,
		GCPercent:       25,
		LogMaxLines:     250,
	}
	if err := ReloadSetupOptions(want); err != nil {
		t.Fatal(err)
	}
	got := runtimeSetupSnapshot()
	if got.softMemoryLimit != want.SoftMemoryLimit || got.gcPercent != want.GCPercent || got.logMaxLines != want.LogMaxLines {
		t.Fatalf("runtime setup = %#v, want %#v", got, want)
	}

	for i := 0; i < 300; i++ {
		recentLogs.add("line")
	}
	if got := len(recentLogs.snapshot()); got != want.LogMaxLines {
		t.Fatalf("live log cap retained %d lines, want %d", got, want.LogMaxLines)
	}
}

func TestReloadSetupOptionsRejectsRestartOnlyFields(t *testing.T) {
	if err := Setup(testOptions(t)); err != nil {
		t.Fatal(err)
	}
	tests := []RuntimeSetupOptions{
		{BasePath: "/new/base"},
		{WorkingPath: "/new/work"},
		{TempPath: "/new/temp"},
		{TimeZone: "UTC"},
		{MaxProcs: 2},
		{TunMTU: 1500},
		{ClashAPISocketPath: "/new/socket"},
		{CoreIdentity: "second-core"},
	}
	for _, options := range tests {
		if err := ReloadSetupOptions(&options); err == nil || !strings.Contains(err.Error(), "requires restart") {
			t.Fatalf("restart-only options %#v returned %v", options, err)
		}
	}
}

func TestReloadSetupOptionsValidationRollsBackAllFields(t *testing.T) {
	if err := Setup(testOptions(t)); err != nil {
		t.Fatal(err)
	}
	baseline := &RuntimeSetupOptions{SoftMemoryLimit: 32 << 20, GCPercent: 20, LogMaxLines: 200}
	if err := ReloadSetupOptions(baseline); err != nil {
		t.Fatal(err)
	}
	want := runtimeSetupSnapshot()

	tests := []*RuntimeSetupOptions{
		nil,
		{SoftMemoryLimit: minReloadSoftMemoryLimit - 1},
		{SoftMemoryLimit: maxReloadSoftMemoryLimit + 1},
		{GCPercent: minReloadGCPercent - 1},
		{GCPercent: maxReloadGCPercent + 1},
		{LogMaxLines: minReloadLogMaxLines - 1},
		{LogMaxLines: maxReloadLogMaxLines + 1},
		{SoftMemoryLimit: 64 << 20, GCPercent: maxReloadGCPercent + 1},
	}
	for _, invalid := range tests {
		if err := ReloadSetupOptions(invalid); err == nil {
			t.Fatalf("invalid options %#v succeeded", invalid)
		}
		if got := runtimeSetupSnapshot(); got != want {
			t.Fatalf("invalid options %#v changed state from %#v to %#v", invalid, want, got)
		}
	}
}

func TestReloadSetupOptionsConcurrentUpdatesAreSerialized(t *testing.T) {
	if err := Setup(testOptions(t)); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			options := &RuntimeSetupOptions{
				SoftMemoryLimit: int64(32+index%4) << 20,
				GCPercent:       20 + index%4,
				LogMaxLines:     200 + index%4,
			}
			if err := ReloadSetupOptions(options); err != nil {
				t.Errorf("ReloadSetupOptions: %v", err)
			}
		}(i)
	}
	wg.Wait()
	got := runtimeSetupSnapshot()
	if got.softMemoryLimit < 32<<20 || got.softMemoryLimit > 35<<20 ||
		got.gcPercent < 20 || got.gcPercent > 23 ||
		got.logMaxLines < 200 || got.logMaxLines > 203 {
		t.Fatalf("serialized result outside submitted set: %#v", got)
	}
}
