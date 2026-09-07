package hako

import (
	"context"
	"encoding/json"
	"time"
)

// Hako's producer includes the extension's footprint in each memory frame.
// Preserve those frames byte-for-byte. Older producers still need the bounded,
// session-owned snapshot request; a present but unusable field is not evidence
// of an old producer and must not trigger another request.
const memoryFootprintFetchTimeout = time.Second

func (c *ClashAPIClient) enrichMemoryFrames(ctx context.Context, next func(string)) func(string) {
	return func(payload string) {
		if ctx.Err() != nil {
			return
		}
		object, valid := memoryPayloadObject(payload)
		if valid {
			if _, present := object["footprint"]; !present {
				payload = mergeFootprintIntoMemoryObject(payload, object, c.fetchSnapshotFootprint(ctx))
			}
		}
		if ctx.Err() == nil {
			next(payload)
		}
	}
}

// fetchSnapshotFootprint asks the extension's snapshot route for the current
// phys_footprint. 0 means no usable reading (error, missing key, or a
// platform that reports none) — the caller passes the frame through then.
func (c *ClashAPIClient) fetchSnapshotFootprint(parent context.Context) int64 {
	ctx, cancel := context.WithTimeout(parent, memoryFootprintFetchTimeout)
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

func memoryPayloadObject(payload string) (map[string]json.RawMessage, bool) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal([]byte(payload), &object); err != nil || object == nil {
		return nil, false
	}
	return object, true
}

// The legacy merge preserves other JSON values, including integers that cannot
// round-trip through float64. Non-objects and existing fields pass through.
func mergeFootprintIntoMemoryPayload(payload string, footprint int64) string {
	object, valid := memoryPayloadObject(payload)
	if !valid {
		return payload
	}
	return mergeFootprintIntoMemoryObject(payload, object, footprint)
}

func mergeFootprintIntoMemoryObject(payload string, object map[string]json.RawMessage, footprint int64) string {
	if footprint <= 0 || object == nil {
		return payload
	}
	if _, present := object["footprint"]; present {
		return payload
	}
	encoded, _ := json.Marshal(footprint)
	object["footprint"] = encoded
	merged, err := json.Marshal(object)
	if err != nil {
		return payload
	}
	return string(merged)
}
