package hako

import (
	"encoding/json"
	"testing"
)

func TestMergeFootprintIntoMemoryPayload(t *testing.T) {
	cases := []struct {
		name      string
		payload   string
		footprint int64
		wantKey   bool
		wantSame  bool
	}{
		{"merges into the upstream shape", `{"inuse":123,"oslimit":0}`, 41_000_000, true, false},
		{"zero reading passes through", `{"inuse":123,"oslimit":0}`, 0, false, true},
		{"negative reading passes through", `{"inuse":123,"oslimit":0}`, -1, false, true},
		{"invalid json passes through untouched", `not-json`, 41_000_000, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mergeFootprintIntoMemoryPayload(tc.payload, tc.footprint)
			if tc.wantSame && got != tc.payload {
				t.Fatalf("payload must pass through unchanged, got %q", got)
			}
			if !tc.wantKey {
				return
			}
			var decoded map[string]any
			if err := json.Unmarshal([]byte(got), &decoded); err != nil {
				t.Fatalf("merged payload is not JSON: %v (%q)", err, got)
			}
			if decoded["footprint"] != float64(tc.footprint) {
				t.Fatalf("footprint = %v, want %d", decoded["footprint"], tc.footprint)
			}
			if decoded["inuse"] != float64(123) || decoded["oslimit"] != float64(0) {
				t.Fatalf("upstream fields must survive verbatim: %q", got)
			}
		})
	}
}
