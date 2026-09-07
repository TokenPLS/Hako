package hako

import (
	"context"
	"encoding/json"
	"github.com/coder/websocket"
	"github.com/TokenPLS/Hako/hub/route"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

type memoryFrameHandler struct {
	lifecycleHandler
	frames chan string
}

func (h *memoryFrameHandler) WriteMemory(frame string) {
	select {
	case h.frames <- frame:
	default:
	}
}

func TestMemoryRouteAndClientNeedNoExtraSnapshots(t *testing.T) {
	address := "127.0.0.1:" + freeLoopbackPort(t)
	path := shortClashSocketPath(t)
	if err := startControlPlane(controllerConfig(t, address), path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stopClashAPI(path) })
	handler := &memoryFrameHandler{frames: make(chan string, 8)}
	options := &ClashAPIClientOptions{}
	options.AddCommand(CommandStatus)
	client, err := NewClashAPIClientWithOptions(path, handler, options)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var snapshots atomic.Int32
	transport := client.httpClient.Transport
	client.httpClient.Transport = lifecycleRoundTripper(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/hako/v1/memory" {
			snapshots.Add(1)
		}
		return transport.RoundTrip(r)
	})
	if err := client.Connect(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		frame := lifecycleWait(t, handler.frames)
		var payload struct {
			Inuse     int64  `json:"inuse"`
			Footprint *int64 `json:"footprint"`
		}
		if err := json.Unmarshal([]byte(frame), &payload); err != nil {
			t.Fatal(err)
		}
		if payload.Footprint == nil || *payload.Footprint < 0 {
			t.Errorf("missing or negative same-frame footprint: %s", frame)
		}
		if i == 0 && payload.Inuse != 0 {
			t.Errorf("first-frame RSS compatibility changed: %s", frame)
		}
	}
	if got := snapshots.Load(); got != 0 {
		t.Errorf("three production memory frames caused %d extra GETs", got)
	}
	snapshot, err := client.GetMemory()
	if err != nil {
		t.Fatalf("legacy GET removed: %v", err)
	}
	var legacy map[string]json.RawMessage
	if err := json.Unmarshal([]byte(snapshot), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy["inuse"] == nil || legacy["oslimit"] == nil {
		t.Errorf("legacy GET shape: %s", snapshot)
	}
	if got := snapshots.Load(); got != 1 {
		t.Errorf("only explicit legacy GET should run, got %d", got)
	}
}

// Inspect the actual wire before the App client can enrich it.
func TestMemoryRouteOptionalReaderAndUnknownSample(t *testing.T) {
	address := "127.0.0.1:" + freeLoopbackPort(t)
	path := shortClashSocketPath(t)
	if err := startControlPlane(controllerConfig(t, address), path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stopClashAPI(path); route.SetMemoryFootprintReader(MemoryFootprint) })
	var reentrant func() int64
	reentrant = func() int64 { route.SetMemoryFootprintReader(reentrant); return 42 }
	cases := []struct {
		name   string
		reader func() int64
		want   *int64
	}{
		{"upstream without registration", nil, nil},
		{"supported but unavailable", func() int64 { return -1 }, new(int64)},
		{"explicit zero", func() int64 { return 0 }, new(int64)},
		{"reader runs outside registration lock", reentrant, func() *int64 { v := int64(42); return &v }()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			route.SetMemoryFootprintReader(tc.reader)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, _, err := websocket.Dial(ctx, "ws://"+address+"/memory", nil)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.CloseNow()
			_, frame, err := conn.Read(ctx)
			if err != nil {
				t.Fatal(err)
			}
			var payload map[string]json.RawMessage
			if err := json.Unmarshal(frame, &payload); err != nil {
				t.Fatal(err)
			}
			value, exists := payload["footprint"]
			if tc.want == nil {
				if exists {
					t.Errorf("unregistered upstream shape gained footprint: %s", frame)
				}
				return
			}
			var got int64
			if !exists || json.Unmarshal(value, &got) != nil || got != *tc.want {
				t.Errorf("footprint want %d, got frame %s", *tc.want, frame)
			}
		})
	}
}
