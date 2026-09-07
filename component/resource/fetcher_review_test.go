package resource

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/common/utils"
)

// Four findings from the 2026-09-05 read-only audit of the deferred first load
// each verified against this file before it was fixed:
//
//   F01  a side update from the app loaded the provider, and the background first
//        load went on retrying its own download anyway -- it only ever recognised
//        its own success, on its own private backoff;
//   F02  Update read f.hash with no lock while loadBuf wrote it under one, and the
//        first-load loop plus a side update is a real concurrent pair (race detector,
//        production tags, exit 1);
//   F03  the executor's five-slot provider-load bound covers Initial only; a deferred
//        Initial returns at once and the actual download and parse ran outside it,
//        so N deferred providers meant N bodies and N parses in flight;
//   F04  the 16 MiB default cap read exactly 16 MiB and called it a success -- a
//        rule set one byte longer lost its tail and reported no error.

// --- F01 ---------------------------------------------------------------------------

func TestASideUpdateEndsTheDeferredFirstLoad(t *testing.T) {
	withDeferredFetch(t, 20*time.Millisecond, 60*time.Millisecond)
	vehicle := &scriptedVehicle{path: filepath.Join(t.TempDir(), "list"), failures: 1 << 20, payload: []byte("never")}
	fetcher, updates, mu := newDeferredFetcher(t, vehicle, 0)
	if _, err := fetcher.Initial(); !errors.Is(err, ErrRemoteFetchDeferred) {
		t.Fatalf("Initial err = %v", err)
	}
	waitFor(t, "the first failed attempt", 5*time.Second, func() bool { return vehicle.reads.Load() >= 1 })

	if _, _, err := fetcher.SideUpdate([]byte("from the app")); err != nil {
		t.Fatalf("SideUpdate: %v", err)
	}
	// One attempt may already be in flight; after it lands, the loop must be gone.
	settled := vehicle.reads.Load() + 1
	time.Sleep(400 * time.Millisecond) // > several backoff steps at 20..60ms
	if reads := vehicle.reads.Load(); reads > settled {
		t.Fatalf("the background first load kept downloading after a side update loaded the provider: reads went to %d (allowed %d)", reads, settled)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*updates) != 1 || (*updates)[0] != "from the app" {
		t.Fatalf("updates = %v, want exactly the side update", *updates)
	}
}

// A side update lands while the background attempt is in flight, and that attempt then
// succeeds too. Two paths completed the first load; exactly one pull loop may follow.
func TestBothPathsCompletingTheFirstLoadStartExactlyOnePullLoop(t *testing.T) {
	withDeferredFetch(t, 20*time.Millisecond, 60*time.Millisecond)
	const interval = 150 * time.Millisecond
	block := make(chan struct{})
	vehicle := &scriptedVehicle{path: filepath.Join(t.TempDir(), "list"), payload: []byte("same"), block: block}
	fetcher, _, _ := newDeferredFetcher(t, vehicle, interval)
	if _, err := fetcher.Initial(); !errors.Is(err, ErrRemoteFetchDeferred) {
		t.Fatalf("Initial err = %v", err)
	}
	waitFor(t, "the first attempt to enter Read", 5*time.Second, func() bool { return vehicle.reads.Load() == 1 })
	if _, _, err := fetcher.SideUpdate([]byte("same")); err != nil {
		t.Fatalf("SideUpdate: %v", err)
	}
	close(block) // the in-flight attempt now succeeds with the same payload
	waitFor(t, "the in-flight attempt to return", 5*time.Second, func() bool { return vehicle.reads.Load() >= 2 })
	// From here every read is a pull-loop tick; two loops would tick twice as often.
	before := vehicle.reads.Load()
	const window = time.Second
	time.Sleep(window)
	ticks := vehicle.reads.Load() - before
	maxForOneLoop := int32(window/interval) + 2 // + one in flight, + rounding
	if ticks == 0 {
		t.Fatal("no pull loop is running after the first load completed")
	}
	if ticks > maxForOneLoop {
		t.Fatalf("%d reads in %s at interval %s: more than one pull loop is running (one loop: at most %d)", ticks, window, interval, maxForOneLoop)
	}
}

// The download never succeeds; the side update is the only thing that ever loads the
// provider. The pull loop the interval asks for must still start -- the first-load loop
// was the only thing that would have started it.
func TestASideUpdateStillHandsOverToThePullLoopWhenTheDownloadNeverSucceeds(t *testing.T) {
	withDeferredFetch(t, 20*time.Millisecond, 60*time.Millisecond)
	vehicle := &scriptedVehicle{path: filepath.Join(t.TempDir(), "list"), failures: 1 << 20, payload: []byte("never")}
	fetcher, _, _ := newDeferredFetcher(t, vehicle, 100*time.Millisecond)
	if _, err := fetcher.Initial(); !errors.Is(err, ErrRemoteFetchDeferred) {
		t.Fatalf("Initial err = %v", err)
	}
	waitFor(t, "the first failed attempt", 5*time.Second, func() bool { return vehicle.reads.Load() >= 1 })
	if _, _, err := fetcher.SideUpdate([]byte("from the app")); err != nil {
		t.Fatalf("SideUpdate: %v", err)
	}
	// The first-load loop is gone (TestASideUpdateEndsTheDeferredFirstLoad); reads that
	// keep coming at this point are the pull loop's refreshes, which the interval asked for.
	before := vehicle.reads.Load() + 1 // one attempt may have been in flight
	waitFor(t, "the pull loop's first refresh", 5*time.Second, func() bool { return vehicle.reads.Load() > before })
}

func TestASideUpdateBeforeTheFirstAttemptSpendsNoDownload(t *testing.T) {
	withDeferredFetch(t, 200*time.Millisecond, time.Second)
	vehicle := &scriptedVehicle{path: filepath.Join(t.TempDir(), "list"), failures: 1 << 20, block: make(chan struct{})}
	fetcher, _, _ := newDeferredFetcher(t, vehicle, 0)
	if _, err := fetcher.Initial(); !errors.Is(err, ErrRemoteFetchDeferred) {
		t.Fatalf("Initial err = %v", err)
	}
	waitFor(t, "the first attempt to enter Read", 5*time.Second, func() bool { return vehicle.reads.Load() == 1 })
	if _, _, err := fetcher.SideUpdate([]byte("from the app")); err != nil {
		t.Fatalf("SideUpdate: %v", err)
	}
	close(vehicle.block) // the in-flight attempt fails now
	time.Sleep(500 * time.Millisecond)
	if reads := vehicle.reads.Load(); reads != 1 {
		t.Fatalf("a second attempt was scheduled after the side update: reads = %d", reads)
	}
}

// --- F02 ---------------------------------------------------------------------------

// The race detector is the assertion here: run the package with -race. Without the
// fix this test reports Update's read of f.hash against loadBuf's write.
func TestUpdateAndSideUpdateDoNotRaceOnTheHash(t *testing.T) {
	withDeferredFetch(t, time.Millisecond, 5*time.Millisecond)
	vehicle := &scriptedVehicle{path: filepath.Join(t.TempDir(), "list"), payload: []byte("remote")}
	fetcher, _, _ := newDeferredFetcher(t, vehicle, 2*time.Millisecond)
	if _, err := fetcher.Initial(); !errors.Is(err, ErrRemoteFetchDeferred) {
		t.Fatalf("Initial err = %v", err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_, _, _ = fetcher.SideUpdate([]byte(fmt.Sprintf("side-%d-%d", i, j)))
				_, _, _ = fetcher.Update()
			}
		}(i)
	}
	wg.Wait()
}

// --- F03 ---------------------------------------------------------------------------

func withFirstLoadConcurrency(t *testing.T, n int) {
	t.Helper()
	prev := FirstLoadConcurrency()
	SetFirstLoadConcurrency(n)
	t.Cleanup(func() { SetFirstLoadConcurrency(prev) })
}

func TestDeferredFirstLoadsShareOneAdmission(t *testing.T) {
	withDeferredFetch(t, 20*time.Millisecond, 60*time.Millisecond)
	withFirstLoadConcurrency(t, 2)
	const providers = 6
	block := make(chan struct{})
	vehicles := make([]*scriptedVehicle, providers)
	for i := range vehicles {
		vehicles[i] = &scriptedVehicle{path: filepath.Join(t.TempDir(), fmt.Sprintf("list-%d", i)), payload: []byte("payload"), block: block}
		fetcher, _, _ := newDeferredFetcher(t, vehicles[i], 0)
		if _, err := fetcher.Initial(); !errors.Is(err, ErrRemoteFetchDeferred) {
			t.Fatalf("Initial %d err = %v", i, err)
		}
	}
	inFlight := func() int32 {
		var n int32
		for _, v := range vehicles {
			n += v.reads.Load()
		}
		return n
	}
	waitFor(t, "two downloads to start", 5*time.Second, func() bool { return inFlight() == 2 })
	time.Sleep(300 * time.Millisecond)
	if n := inFlight(); n != 2 {
		t.Fatalf("%d downloads in flight with an admission of 2; the bound does not cover the background first load", n)
	}
	close(block)
	// Wait on the writes, not the reads: a read that has returned may still be
	// writing while the temp dir is torn down.
	waitFor(t, "every provider to load and write", 5*time.Second, func() bool {
		for _, v := range vehicles {
			if v.written.Load() != 1 {
				return false
			}
		}
		return true
	})
}

func TestCloseReleasesADeferredFirstLoadWaitingForAdmission(t *testing.T) {
	withDeferredFetch(t, 20*time.Millisecond, 60*time.Millisecond)
	withFirstLoadConcurrency(t, 1)
	block := make(chan struct{})
	// Which of the two wins the single slot is the scheduler's choice, not the
	// test's: the one that entered Read is the holder, the other is the waiter.
	type pair struct {
		vehicle *scriptedVehicle
		fetcher *Fetcher[string]
	}
	var pairs [2]pair
	for i := range pairs {
		vehicle := &scriptedVehicle{path: filepath.Join(t.TempDir(), fmt.Sprintf("list-%d", i)), payload: []byte("p"), block: block}
		fetcher, _, _ := newDeferredFetcher(t, vehicle, 0)
		if _, err := fetcher.Initial(); !errors.Is(err, ErrRemoteFetchDeferred) {
			t.Fatalf("Initial %d err = %v", i, err)
		}
		pairs[i] = pair{vehicle, fetcher}
	}
	waitFor(t, "one of the two to enter Read", 5*time.Second, func() bool {
		return pairs[0].vehicle.reads.Load()+pairs[1].vehicle.reads.Load() == 1
	})
	time.Sleep(100 * time.Millisecond)
	holder, waiter := pairs[0], pairs[1]
	if holder.vehicle.reads.Load() == 0 {
		holder, waiter = pairs[1], pairs[0]
	}
	if waiter.vehicle.reads.Load() != 0 {
		t.Fatal("both were admitted with an admission of 1")
	}
	_ = waiter.fetcher.Close()
	close(block)
	waitFor(t, "the holder to finish", 5*time.Second, func() bool { return holder.vehicle.written.Load() == 1 })
	time.Sleep(200 * time.Millisecond)
	if waiter.vehicle.reads.Load() != 0 {
		t.Fatal("a closed fetcher was admitted and downloaded anyway")
	}
}

func TestWithoutAnAdmissionDeferredFirstLoadsRunUnbounded(t *testing.T) {
	withDeferredFetch(t, 20*time.Millisecond, 60*time.Millisecond)
	withFirstLoadConcurrency(t, 0)
	const providers = 4
	// Never released: Cleanup's fetcher.Close cancels the context, every blocked
	// Read returns ctx.Err, and no goroutine is left writing into the temp dir
	// while it is being removed.
	block := make(chan struct{})
	vehicles := make([]*scriptedVehicle, providers)
	for i := range vehicles {
		vehicles[i] = &scriptedVehicle{path: filepath.Join(t.TempDir(), fmt.Sprintf("list-%d", i)), payload: []byte("payload"), block: block}
		fetcher, _, _ := newDeferredFetcher(t, vehicles[i], 0)
		if _, err := fetcher.Initial(); !errors.Is(err, ErrRemoteFetchDeferred) {
			t.Fatalf("Initial %d err = %v", i, err)
		}
	}
	waitFor(t, "every download to start at once (upstream's unbounded default)", 5*time.Second, func() bool {
		var n int32
		for _, v := range vehicles {
			n += v.reads.Load()
		}
		return n == providers
	})
}

// --- F04 ---------------------------------------------------------------------------

func withDefaultRemoteSizeLimit(t *testing.T, limit int64) {
	t.Helper()
	prev := DefaultRemoteSizeLimit
	DefaultRemoteSizeLimit = limit
	t.Cleanup(func() { DefaultRemoteSizeLimit = prev })
}

func sizedServer(t *testing.T, body *atomic.Pointer[[]byte]) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(*body.Load())
	}))
	t.Cleanup(server.Close)
	return server
}

func TestADefaultedSizeLimitRefusesAnOversizedBodyInsteadOfTruncatingIt(t *testing.T) {
	withDefaultRemoteSizeLimit(t, 1024)
	var body atomic.Pointer[[]byte]
	over := []byte(strings.Repeat("x", 1025))
	body.Store(&over)
	server := sizedServer(t, &body)

	vehicle := NewHTTPVehicle(server.URL, filepath.Join(t.TempDir(), "list"), "", nil, 5*time.Second, 0)
	buf, hash, err := vehicle.Read(context.Background(), utils.HashType{})
	if err == nil {
		t.Fatalf("a %d-byte body under a %d-byte default cap was accepted: got %d bytes, no error", len(over), 1024, len(buf))
	}
	if !strings.Contains(err.Error(), "1024") {
		t.Fatalf("the error must name the cap so the reader can raise it: %v", err)
	}
	if hash.IsValid() {
		t.Fatal("no hash may be reported for a body that was refused")
	}

	exact := []byte(strings.Repeat("y", 1024))
	body.Store(&exact)
	buf, _, err = vehicle.Read(context.Background(), utils.HashType{})
	if err != nil || len(buf) != 1024 {
		t.Fatalf("a body exactly at the cap must load whole: len=%d err=%v", len(buf), err)
	}
}

// Upstream's own explicit size-limit truncates and reports success
// (component/resource/vehicle.go: LimitReader then ReadAll, no overrun check). That is
// what a profile that WRITES size-limit gets from mihomo, and this build keeps it:
// changing it would be stricter than upstream for a field upstream defines, which is a
// registry decision, not a fix. Only the cap this build ADDS -- the default applied when
// the profile names none -- refuses, because there is no upstream behaviour to match
// there and "success with the tail missing" is the one outcome nobody asked for.
func TestAnExplicitSizeLimitKeepsUpstreamsTruncation(t *testing.T) {
	withDefaultRemoteSizeLimit(t, 1024)
	var body atomic.Pointer[[]byte]
	over := []byte(strings.Repeat("x", 2000))
	body.Store(&over)
	server := sizedServer(t, &body)

	vehicle := NewHTTPVehicle(server.URL, filepath.Join(t.TempDir(), "list"), "", nil, 5*time.Second, 1500)
	buf, _, err := vehicle.Read(context.Background(), utils.HashType{})
	if err != nil || len(buf) != 1500 {
		t.Fatalf("explicit size-limit is upstream's truncating semantics: len=%d err=%v", len(buf), err)
	}
}

func TestAnOversizedRefreshKeepsTheContentAlreadyLoaded(t *testing.T) {
	withDefaultRemoteSizeLimit(t, 64)
	var body atomic.Pointer[[]byte]
	small := []byte("rule-a\nrule-b\n")
	body.Store(&small)
	server := sizedServer(t, &body)

	var mu sync.Mutex
	var updates []string
	parser := func(buf []byte) (string, error) { return string(buf), nil }
	vehicle := NewHTTPVehicle(server.URL, filepath.Join(t.TempDir(), "list"), "", nil, 5*time.Second, 0)
	fetcher := NewFetcher[string]("sized", 0, vehicle, nil, parser, func(s string) {
		mu.Lock()
		defer mu.Unlock()
		updates = append(updates, s)
	})
	t.Cleanup(func() { _ = fetcher.Close() })
	if _, _, err := fetcher.Update(); err != nil {
		t.Fatalf("first load: %v", err)
	}
	loadedHash := fetcher.hash

	over := []byte(strings.Repeat("z", 65))
	body.Store(&over)
	if _, _, err := fetcher.Update(); err == nil {
		t.Fatal("an oversized refresh reported success")
	}
	if !fetcher.hash.Equal(loadedHash) {
		t.Fatal("an oversized refresh replaced the hash of the content still in use")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(updates) != 1 {
		t.Fatalf("an oversized refresh reached onUpdate: %v", updates)
	}
}
