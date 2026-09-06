package hako

import (
	"encoding/json"
	"testing"

	"github.com/metacubex/http/httptest"
)

func TestMemorySnapshotCarriesTheFootprintJetsamCounts(t *testing.T) {
	recorder := httptest.NewRecorder()
	serveMemorySnapshot(recorder, nil)
	var payload struct {
		Inuse     uint64  `json:"inuse"`
		Footprint *uint64 `json:"footprint"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, recorder.Body.String())
	}
	if MemoryFootprint() > 0 {
		if payload.Footprint == nil || *payload.Footprint == 0 {
			t.Fatalf("this platform reports a footprint, the snapshot must carry it: %s", recorder.Body.String())
		}
	} else if payload.Footprint != nil {
		t.Fatalf("no footprint reading on this platform, the key must be absent: %s", recorder.Body.String())
	}
}
