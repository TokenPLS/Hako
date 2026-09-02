package hako

import (
	"encoding/json"
	"strings"
	"testing"
)

func decodeDeviations(t *testing.T, configContent, profile string) []configDeviation {
	t.Helper()
	box, err := ConfigDeviationsJSON(configContent, profile)
	if err != nil {
		t.Fatalf("ConfigDeviationsJSON(%s): %v", profile, err)
	}
	var payload struct {
		SchemaVersion int               `json:"schemaVersion"`
		Deviations    []configDeviation `json:"deviations"`
	}
	if err := json.Unmarshal([]byte(box.Value), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload.SchemaVersion != configDeviationSchemaVersion {
		t.Errorf("schemaVersion %d, want %d", payload.SchemaVersion, configDeviationSchemaVersion)
	}
	return payload.Deviations
}

// The whole point: an answer without a running core.
//
// The runtime endpoint describes the configuration that is running, so a field page opened
// while disconnected -- which is when the reader is deciding what to write -- had nothing to
// say. This runs the same walk over the same rules and answers from the YAML alone.
func TestDeviationsAreAnswerableWithoutStartingAnything(t *testing.T) {
	// tproxy-port has no Apple inbound at all, so it is reported wherever it is written.
	deviations := decodeDeviations(t, "tproxy-port: 7895\n", RuntimeProfileIOSPacketTunnel)
	var found *configDeviation
	for i := range deviations {
		if deviations[i].Field == "tproxy-port" {
			found = &deviations[i]
		}
	}
	if found == nil {
		t.Fatalf("tproxy-port is not reported; got %d deviations", len(deviations))
	}
	for name, value := range map[string]string{
		"given": found.Given, "effective": found.Effective,
		"category": found.Category, "reason": found.Reason, "source": found.Source,
	} {
		if strings.TrimSpace(value) == "" {
			t.Errorf("%s is empty; a row built from this would have nothing to show", name)
		}
	}
	if !strings.Contains(found.Given, "7895") {
		t.Errorf("given %q does not carry what the reader wrote", found.Given)
	}
}

// The same sentences before and after connecting, because it is the same walk. A second
// static list of these facts was the alternative, and two texts that must agree drift.
func TestTheOfflineAnswerIsTheSameWalkAsTheRunningOne(t *testing.T) {
	const content = "tproxy-port: 7895\nredir-port: 7893\n"
	offline := decodeDeviations(t, content, RuntimeProfileIOSPacketTunnel)
	live, err := collectConfigDeviations(content, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true))
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(offline) != len(live) {
		t.Fatalf("offline reported %d, the start path reports %d", len(offline), len(live))
	}
	for i := range live {
		if offline[i] != live[i] {
			t.Errorf("row %d differs:\n  offline: %+v\n  live:    %+v", i, offline[i], live[i])
		}
	}
}

// The profile decides. find-process-mode deviates where the process lookup cannot run, and
// after that is no longer the macOS packet tunnel -- a client asking with the wrong
// profile would tell a Mac reader their rule is ignored when it is honoured.
func TestTheProfileDecidesWhatDeviates(t *testing.T) {
	const content = "find-process-mode: always\n"
	has := func(profile string) bool {
		for _, deviation := range decodeDeviations(t, content, profile) {
			if deviation.Field == "find-process-mode" {
				return true
			}
		}
		return false
	}
	if !has(RuntimeProfileIOSPacketTunnel) {
		t.Error("iOS cannot resolve a connection's owner, so find-process-mode must be reported there")
	}
	if has(RuntimeProfileMacOSPacketTunnel) {
		t.Error("the macOS tunnel resolves it; reporting it here tells the reader their rule is dead when it works")
	}
}

// Nothing to report is a value, not an error and not null: a caller that cannot tell "no
// deviations" from "not asked" reports silence as health.
func TestAConfigurationWithNothingToReportAnswersEmpty(t *testing.T) {
	deviations := decodeDeviations(t, "mode: rule\n", RuntimeProfileMacOSApplication)
	if deviations == nil {
		t.Fatal("nil deviations; an empty list and an absent answer must not look the same")
	}
	box, err := ConfigDeviationsJSON("mode: rule\n", RuntimeProfileMacOSApplication)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(box.Value, `"deviations":[`) {
		t.Errorf("empty report is not an array: %s", box.Value)
	}
}

func TestAnUnknownProfileIsRefusedRatherThanGuessed(t *testing.T) {
	if _, err := ConfigDeviationsJSON("mode: rule\n", "not-a-profile"); err == nil {
		t.Fatal("an unknown profile answered instead of failing; the report would be for the wrong platform")
	}
}
