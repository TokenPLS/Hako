package resource

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/common/utils"
	P "github.com/TokenPLS/Hako/constant/provider"
)

// A remote provider with nothing on disk used to be downloaded inside Initial, on
// the Start path, twenty seconds per attempt. On a phone that is the tunnel not
// coming up because a rule set's host is unreachable. With DeferRemoteInitialFetch
// the provider starts empty -- the same shape upstream leaves it in when the
// download fails -- and a background loop fetches it with backoff until it lands,
// whatever the interval says; the pull loop, if the interval asks for one, takes
// over from there.

type scriptedVehicle struct {
	path     string
	failures int32
	reads    atomic.Int32
	payload  []byte
	written  atomic.Int32
	block    chan struct{}
}

func (v *scriptedVehicle) Read(ctx context.Context, oldHash utils.HashType) ([]byte, utils.HashType, error) {
	n := v.reads.Add(1)
	if v.block != nil {
		select {
		case <-v.block:
		case <-ctx.Done():
			return nil, utils.HashType{}, ctx.Err()
		}
	}
	if n <= v.failures {
		return nil, utils.HashType{}, errors.New("scripted failure")
	}
	return v.payload, utils.MakeHash(v.payload), nil
}
func (v *scriptedVehicle) Write(buf []byte) error {
	v.written.Add(1)
	return os.WriteFile(v.path, buf, 0o600)
}
func (v *scriptedVehicle) Path() string        { return v.path }
func (v *scriptedVehicle) Url() string         { return "https://example.invalid/list" }
func (v *scriptedVehicle) Proxy() string       { return "" }
func (v *scriptedVehicle) Type() P.VehicleType { return P.HTTP }

func withDeferredFetch(t *testing.T, min, max time.Duration) {
	t.Helper()
	prevDefer, prevMin, prevMax := DeferRemoteInitialFetch, deferredFirstLoadMinBackoff, deferredFirstLoadMaxBackoff
	DeferRemoteInitialFetch, deferredFirstLoadMinBackoff, deferredFirstLoadMaxBackoff = true, min, max
	t.Cleanup(func() {
		DeferRemoteInitialFetch, deferredFirstLoadMinBackoff, deferredFirstLoadMaxBackoff = prevDefer, prevMin, prevMax
	})
}

func newDeferredFetcher(t *testing.T, vehicle *scriptedVehicle, interval time.Duration) (*Fetcher[string], *[]string, *sync.Mutex) {
	t.Helper()
	var mu sync.Mutex
	var updates []string
	parser := func(buf []byte) (string, error) { return string(buf), nil }
	fetcher := NewFetcher[string]("scripted", interval, vehicle, nil, parser, func(s string) {
		mu.Lock()
		defer mu.Unlock()
		updates = append(updates, s)
	})
	t.Cleanup(func() { _ = fetcher.Close() })
	return fetcher, &updates, &mu
}

func waitFor(t *testing.T, what string, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestDeferredInitialReturnsAtOnceAndLoadsInTheBackground(t *testing.T) {
	withDeferredFetch(t, 20*time.Millisecond, 100*time.Millisecond)
	vehicle := &scriptedVehicle{path: filepath.Join(t.TempDir(), "list"), failures: 2, payload: []byte("payload")}
	fetcher, updates, mu := newDeferredFetcher(t, vehicle, 0)

	started := time.Now()
	_, err := fetcher.Initial()
	if !errors.Is(err, ErrRemoteFetchDeferred) {
		t.Fatalf("Initial err = %v, want ErrRemoteFetchDeferred", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("Initial took %s; it must not wait on the network", elapsed)
	}
	waitFor(t, "the background load", 5*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(*updates) == 1 && (*updates)[0] == "payload"
	})
	if reads := vehicle.reads.Load(); reads != 3 {
		t.Fatalf("reads = %d, want 3 (two scripted failures, then success)", reads)
	}
	if vehicle.written.Load() != 1 {
		t.Fatalf("the loaded payload must be written to the vehicle path for the next start")
	}
	// interval 0: the first load is the only load.
	time.Sleep(300 * time.Millisecond)
	if reads := vehicle.reads.Load(); reads != 3 {
		t.Fatalf("interval 0 kept fetching after the first success: reads = %d", reads)
	}
}

func TestDeferredFirstLoadHandsOverToThePullLoop(t *testing.T) {
	withDeferredFetch(t, 20*time.Millisecond, 100*time.Millisecond)
	vehicle := &scriptedVehicle{path: filepath.Join(t.TempDir(), "list"), payload: []byte("payload")}
	fetcher, _, _ := newDeferredFetcher(t, vehicle, 150*time.Millisecond)
	if _, err := fetcher.Initial(); !errors.Is(err, ErrRemoteFetchDeferred) {
		t.Fatalf("Initial err = %v", err)
	}
	waitFor(t, "the pull loop's second read", 5*time.Second, func() bool { return vehicle.reads.Load() >= 2 })
}

func TestDeferredFirstLoadStopsWhenTheFetcherCloses(t *testing.T) {
	withDeferredFetch(t, 20*time.Millisecond, 100*time.Millisecond)
	vehicle := &scriptedVehicle{path: filepath.Join(t.TempDir(), "list"), failures: 1 << 20, payload: []byte("payload")}
	fetcher, _, _ := newDeferredFetcher(t, vehicle, 0)
	if _, err := fetcher.Initial(); !errors.Is(err, ErrRemoteFetchDeferred) {
		t.Fatalf("Initial err = %v", err)
	}
	waitFor(t, "a couple of failed attempts", 5*time.Second, func() bool { return vehicle.reads.Load() >= 2 })
	_ = fetcher.Close()
	settled := vehicle.reads.Load()
	time.Sleep(300 * time.Millisecond)
	if vehicle.reads.Load() != settled {
		t.Fatalf("the loop kept reading after Close: %d -> %d", settled, vehicle.reads.Load())
	}
}

func TestWithoutTheKnobInitialStillFetchesSynchronously(t *testing.T) {
	prev := DeferRemoteInitialFetch
	DeferRemoteInitialFetch = false
	t.Cleanup(func() { DeferRemoteInitialFetch = prev })
	vehicle := &scriptedVehicle{path: filepath.Join(t.TempDir(), "list"), failures: 1, payload: []byte("payload")}
	fetcher, _, _ := newDeferredFetcher(t, vehicle, 0)
	if _, err := fetcher.Initial(); err == nil || errors.Is(err, ErrRemoteFetchDeferred) {
		t.Fatalf("upstream shape: Initial reports the download error itself, got %v", err)
	}
	if vehicle.reads.Load() != 1 {
		t.Fatalf("synchronous Initial should have read once, got %d", vehicle.reads.Load())
	}
}

func TestALocalFileIsStillUsedBeforeAnyDeferral(t *testing.T) {
	withDeferredFetch(t, 20*time.Millisecond, 100*time.Millisecond)
	path := filepath.Join(t.TempDir(), "list")
	if err := os.WriteFile(path, []byte("cached"), 0o600); err != nil {
		t.Fatal(err)
	}
	vehicle := &scriptedVehicle{path: path, payload: []byte("fresh")}
	fetcher, _, _ := newDeferredFetcher(t, vehicle, 0)
	contents, err := fetcher.Initial()
	if err != nil || contents != "cached" {
		t.Fatalf("Initial = %q, %v; want the cached file, no error", contents, err)
	}
	if vehicle.reads.Load() != 0 {
		t.Fatalf("a cached provider must not touch the network at Initial")
	}
}

func TestRemoteSizeLimitDefaultsWhenTheProfileNamesNone(t *testing.T) {
	prev := DefaultRemoteSizeLimit
	DefaultRemoteSizeLimit = 1234
	t.Cleanup(func() { DefaultRemoteSizeLimit = prev })
	if got := NewHTTPVehicle("https://example.invalid", filepath.Join(t.TempDir(), "x"), "", nil, time.Second, 0).sizeLimit; got != 1234 {
		t.Fatalf("size limit = %d, want the default 1234", got)
	}
	if got := NewHTTPVehicle("https://example.invalid", filepath.Join(t.TempDir(), "x"), "", nil, time.Second, 99).sizeLimit; got != 99 {
		t.Fatalf("a profile's own limit must win, got %d", got)
	}
}
