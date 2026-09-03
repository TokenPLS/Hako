package hako

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestConfigEntrypointsRejectOversizedYAML(t *testing.T) {
	const limit = 4 * 1024 * 1024
	oversized := strings.Repeat("#", limit+1)
	tests := map[string]func() error{
		"parse": func() error {
			_, err := parseConfigForIOS(oversized, true)
			return err
		},
		"plan": func() error {
			_, err := PlanResourcesForIOS(oversized)
			return err
		},
		"finalize": func() error {
			_, err := FinalizeForIOS(oversized, "{}")
			return err
		},
		"merge": func() error {
			_, err := MergeOverrideForIOS(oversized, "")
			return err
		},
		"yaml-json": func() error {
			_, err := YamlToJSON(oversized)
			return err
		},
		"platform-intent": func() error {
			_, err := PlatformConfigIntentJSON(oversized)
			return err
		},
		"format": func() error {
			_, err := FormatConfig(oversized)
			return err
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			if err := run(); err == nil || !strings.Contains(err.Error(), "exceeds 4194304 bytes") {
				t.Fatalf("oversized input error = %v", err)
			}
		})
	}
}

func TestStartRejectsOversizedConfigBeforePlatformSideEffects(t *testing.T) {
	if err := Setup(testOptions(t)); err != nil {
		t.Fatal(err)
	}
	platform := newRecordingPlatform()
	service, err := NewService(platform)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })

	err = service.Start(strings.Repeat("#", 4*1024*1024+1))
	if err == nil || !strings.Contains(err.Error(), "exceeds 4194304 bytes") {
		t.Fatalf("oversized Start error = %v", err)
	}
	if platform.monitorStarts != 0 || activeCoreCount.Load() != 0 {
		t.Fatalf("oversized Start had side effects: monitor=%d activeCore=%d", platform.monitorStarts, activeCoreCount.Load())
	}
}

func TestJSONToYamlRejectsOversizedScriptJSON(t *testing.T) {
	const limit = 16 * 1024 * 1024
	input := strings.Repeat(" ", limit+1) + "{}"
	if _, err := JSONToYaml(input); err == nil || !strings.Contains(err.Error(), "exceeds 16777216 bytes") {
		t.Fatalf("oversized script JSON error = %v", err)
	}
}

func TestConfigTransformsRejectOversizedResults(t *testing.T) {
	t.Run("script YAML result", func(t *testing.T) {
		input, err := json.Marshal(map[string]any{"payload": strings.Repeat("a", 5*1024*1024)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := JSONToYaml(string(input)); err == nil || !strings.Contains(err.Error(), "configuration result exceeds 4194304 bytes") {
			t.Fatalf("oversized YAML result error = %v", err)
		}
	})

	t.Run("script JSON result", func(t *testing.T) {
		// encoding/json escapes '<' as six bytes. The YAML stays below 4 MiB,
		// while its script representation exceeds the 16 MiB intermediate cap.
		input := "payload: " + strings.Repeat("<", 3*1024*1024) + "\n"
		if _, err := YamlToJSON(input); err == nil || !strings.Contains(err.Error(), "JSON result exceeds 16777216 bytes") {
			t.Fatalf("oversized JSON result error = %v", err)
		}
	})

	t.Run("merged YAML result", func(t *testing.T) {
		raw := "base: " + strings.Repeat("a", 3*1024*1024) + "\n"
		override, err := json.Marshal(overrideSpec{Patch: map[string]any{
			"extra": strings.Repeat("b", 2*1024*1024),
		}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := MergeOverrideForIOS(raw, string(override)); err == nil || !strings.Contains(err.Error(), "configuration result exceeds 4194304 bytes") {
			t.Fatalf("oversized merged YAML error = %v", err)
		}
	})
}
