package hako

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func memoryFixtureClient(t *testing.T, snapshot string) (*ClashAPIClient, *atomic.Int32) {
	t.Helper()
	c := lifecycleClient(t, &lifecycleHandler{})
	calls := new(atomic.Int32)
	c.httpClient.Transport = lifecycleRoundTripper(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if r.URL.Path != "/hako/v1/memory" {
			t.Errorf("unexpected request %s", r.URL.Path)
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(snapshot)), Request: r}, nil
	})
	return c, calls
}

func TestMemoryStreamCompleteFramesSkipSnapshot(t *testing.T) {
	for _, value := range []string{"42", "0", "null", "-1", "1.5", `"bad"`, "9223372036854775808"} {
		t.Run(value, func(t *testing.T) {
			c, calls := memoryFixtureClient(t, `{"footprint":99}`)
			original := ` { "inuse":0, "footprint":` + value + `, "extra":9007199254740993 } `
			var received []string
			deliver := c.enrichMemoryFrames(context.Background(), func(s string) { received = append(received, s) })
			for range 3 {
				deliver(original)
			}
			if calls.Load() != 0 {
				t.Errorf("complete frames caused %d fallback GETs", calls.Load())
			}
			if len(received) != 3 {
				t.Fatalf("callbacks=%d", len(received))
			}
			for _, got := range received {
				if got != original {
					t.Errorf("frame changed: %s", got)
				}
			}
		})
	}
}

func TestMemoryStreamNonObjectsDoNotFetchOrPanic(t *testing.T) {
	for _, original := range []string{"null", "[]", "1", `"text"`, "not-json"} {
		t.Run(original, func(t *testing.T) {
			defer func() {
				if p := recover(); p != nil {
					t.Errorf("semantic frame panicked: %v", p)
				}
			}()
			c, calls := memoryFixtureClient(t, `{"footprint":99}`)
			got := ""
			c.enrichMemoryFrames(context.Background(), func(s string) { got = s })(original)
			if calls.Load() != 0 {
				t.Errorf("non-object caused %d GETs", calls.Load())
			}
			if got != original {
				t.Errorf("non-object changed to %q", got)
			}
		})
	}
}

func TestMemoryStreamLegacyFallbackPreservesPreciseFields(t *testing.T) {
	c, calls := memoryFixtureClient(t, `{"footprint":99}`)
	got := ""
	c.enrichMemoryFrames(context.Background(), func(s string) { got = s })(`{"inuse":7,"oslimit":0,"extra":9007199254740993}`)
	if calls.Load() != 1 {
		t.Fatalf("legacy GET count=%d", calls.Load())
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal([]byte(got), &decoded); err != nil {
		t.Fatal(err)
	}
	if string(decoded["extra"]) != "9007199254740993" {
		t.Errorf("rounded unknown integer: %s", got)
	}
	if string(decoded["footprint"]) != "99" || string(decoded["inuse"]) != "7" {
		t.Errorf("legacy merge: %s", got)
	}
}

func TestMemoryStreamCanceledAdmissionDoesNoWork(t *testing.T) {
	for _, original := range []string{`{"inuse":1,"footprint":2}`, `{"inuse":1}`} {
		c, calls := memoryFixtureClient(t, `{"footprint":99}`)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		callbacks := 0
		c.enrichMemoryFrames(ctx, func(string) { callbacks++ })(original)
		if calls.Load() != 0 || callbacks != 0 {
			t.Errorf("canceled frame: requests=%d callbacks=%d", calls.Load(), callbacks)
		}
	}
}

func TestMemoryStreamLegacyFallbackTimeoutPassesOriginal(t *testing.T) {
	c := lifecycleClient(t, &lifecycleHandler{})
	c.httpClient.Transport = lifecycleRoundTripper(func(r *http.Request) (*http.Response, error) {
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	original := `{"inuse":42}`
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	got := ""
	start := time.Now()
	c.enrichMemoryFrames(ctx, func(s string) { got = s })(original)
	if got != original {
		t.Fatalf("timeout did not preserve RSS frame: %q", got)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("fallback exceeded own bound: %s", elapsed)
	}
}
