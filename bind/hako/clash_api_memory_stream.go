package hako

import (
	"context"
	"encoding/json"
	"time"
)

// The App's live memory channel is upstream's /memory websocket, whose payload
// is {inuse, oslimit} — RSS-shaped, not the number jetsam counts. The
// footprint reading lives on the extension's snapshot route; the App never
// pulled it, and its sweep sentinel silently ran blind. The client closes the
// gap where the frames already flow: each /memory frame picks up a snapshot
// from the extension (the GET is answered in the extension process, so the
// number is the right process's) and merges the footprint key into the same
// payload. Any failure passes the original frame through — the stream never
// stops for the sake of an extra key.

const memoryFootprintFetchTimeout = time.Second

func (c *ClashAPIClient) enrichMemoryFrames(next func(string)) func(string) {
	return func(payload string) {
		next(mergeFootprintIntoMemoryPayload(payload, c.fetchSnapshotFootprint()))
	}
}

// fetchSnapshotFootprint asks the extension's snapshot route for the current
// phys_footprint. 0 means no usable reading (error, missing key, or a
// platform that reports none) — the caller passes the frame through then.
func (c *ClashAPIClient) fetchSnapshotFootprint() int64 {
	ctx, cancel := context.WithTimeout(context.Background(), memoryFootprintFetchTimeout)
	defer cancel()
	payload, err := c.requestWithContext(ctx, "GET", "/hako/v1/memory", nil)
	if err != nil {
		return 0
	}
	var snapshot struct {
		Footprint int64 `json:"footprint"`
	}
	if err := json.Unmarshal([]byte(payload), &snapshot); err != nil {
		return 0
	}
	return snapshot.Footprint
}

// mergeFootprintIntoMemoryPayload is the pure half: add the key, change
// nothing else, and hand back the original on any doubt.
func mergeFootprintIntoMemoryPayload(payload string, footprint int64) string {
	if footprint <= 0 {
		return payload
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(payload), &decoded); err != nil {
		return payload
	}
	decoded["footprint"] = footprint
	merged, err := json.Marshal(decoded)
	if err != nil {
		return payload
	}
	return string(merged)
}
