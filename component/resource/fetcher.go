package resource

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"sync"
	"time"

	"github.com/TokenPLS/Hako/common/utils"
	"github.com/TokenPLS/Hako/component/slowdown"
	P "github.com/TokenPLS/Hako/constant/provider"
	"github.com/TokenPLS/Hako/log"

	"github.com/metacubex/fswatch"
	"github.com/samber/lo"
)

type Parser[V any] func([]byte) (V, error)
type BundleFile func() (fs.File, error)

type Fetcher[V any] struct {
	ctx          context.Context
	ctxCancel    context.CancelFunc
	resourceType string
	name         string
	vehicle      P.Vehicle
	bundleFile   BundleFile
	updatedAt    time.Time
	hash         utils.HashType
	parser       Parser[V]
	interval     time.Duration
	onUpdate     func(V)
	watcher      *fswatch.Watcher
	// loadBufMutex guards hash, updatedAt and firstLoaded. It was held for the
	// writes and not for the reads -- Update handed f.hash to the vehicle and
	// pullLoop measured against f.updatedAt with no lock -- which the race
	// detector reports against loadBuf's writes as soon as a side update and the
	// background first load run at the same time (2026-09-05 audit, F02).
	loadBufMutex sync.Mutex
	backoff      slowdown.Backoff
	// firstLoadDone is closed the first time a payload is loaded by ANY path -- the
	// pull loop, the background first load, or a side update from the app -- so the
	// background first load can stop retrying a download something else already
	// finished (F01). Closed under loadBufMutex, once; firstLoaded is the guard.
	firstLoadDone chan struct{}
	firstLoaded   bool
}

func (f *Fetcher[V]) Name() string {
	return f.name
}

func (f *Fetcher[V]) Vehicle() P.Vehicle {
	return f.vehicle
}

func (f *Fetcher[V]) VehicleType() P.VehicleType {
	return f.vehicle.Type()
}

func (f *Fetcher[V]) UpdatedAt() time.Time {
	f.loadBufMutex.Lock()
	defer f.loadBufMutex.Unlock()
	return f.updatedAt
}

// LoadedContentHash reports the MD5 of the last successfully installed payload.
// It is a cache consistency check, not an authentication primitive. A failed
// write must not endorse a partial cache file as the loaded rules.
func (f *Fetcher[V]) LoadedContentHash() string {
	f.loadBufMutex.Lock()
	defer f.loadBufMutex.Unlock()
	if !f.hash.IsValid() {
		return ""
	}
	return f.hash.String()
}

// ReadLoadedContent reads derived metadata under the same lock as installation.
// The callback must not call another Fetcher method that acquires this lock.
func (f *Fetcher[V]) ReadLoadedContent(read func(string, time.Time)) {
	f.loadBufMutex.Lock()
	defer f.loadBufMutex.Unlock()
	hash := ""
	if f.hash.IsValid() {
		hash = f.hash.String()
	}
	read(hash, f.updatedAt)
}

func (f *Fetcher[V]) Initial() (V, error) {
	if stat, fErr := os.Stat(f.vehicle.Path()); fErr == nil {
		// local file exists, use it first
		buf, err := os.ReadFile(f.vehicle.Path())
		modTime := stat.ModTime()
		contents, _, err := f.loadBuf(buf, utils.MakeHash(buf), false)
		f.loadBufMutex.Lock()
		f.updatedAt = modTime // reset updatedAt to file's modTime
		f.loadBufMutex.Unlock()

		if err == nil {
			err = f.startPullLoop(time.Since(modTime) > f.interval)
			if err != nil {
				return lo.Empty[V](), err
			}
			return contents, nil
		}
	}

	// parse local file error, fallback to bundle file
	if f.bundleFile != nil {
		// bundle file exists, use it first
		if file, fErr := f.bundleFile(); fErr == nil {
			defer file.Close()
			buf, err := io.ReadAll(file)
			var modTime time.Time
			if stat, sErr := file.Stat(); sErr == nil {
				modTime = stat.ModTime()
			}
			contents, _, err := f.loadBuf(buf, utils.MakeHash(buf), true)
			f.loadBufMutex.Lock()
			f.updatedAt = modTime // reset updatedAt to file's modTime
			f.loadBufMutex.Unlock()

			if err == nil {
				log.Infoln("[Provider] %s extract successful from bundle file", f.Name())
				err = f.startPullLoop(time.Since(modTime) > f.interval)
				if err != nil {
					return lo.Empty[V](), err
				}
				return contents, nil
			}
			log.Warnln("[Provider] %s read bundle file error: %s", f.Name(), err.Error())
		} else {
			log.Warnln("[Provider] %s read bundle file error: %s", f.Name(), fErr.Error())
		}
	}

	// parse local file error, fallback to remote
	if DeferRemoteInitialFetch && f.vehicle.Type() == P.HTTP {
		// Nothing on disk and a download to make. On the Apple binding that
		// download does not run here: Initial sits on the Start path, one attempt
		// costs the vehicle's timeout, and a profile with dozens of remote sets
		// on a network that cannot reach them would hold the tunnel for minutes.
		// The provider starts empty -- the shape upstream leaves it in when this
		// download fails -- and firstLoadLoop brings it in with backoff, whatever
		// the interval says, then hands over to the pull loop.
		go f.firstLoadLoop()
		return lo.Empty[V](), ErrRemoteFetchDeferred
	}
	contents, _, updateErr := f.Update()

	// start the pull loop even if f.Update() failed
	err := f.startPullLoop(false)
	if err != nil {
		return lo.Empty[V](), err
	}

	if updateErr != nil {
		return lo.Empty[V](), updateErr
	}

	return contents, nil
}

func (f *Fetcher[V]) Update() (V, bool, error) {
	// A snapshot, taken under the lock and released before the network: the
	// read must not race loadBuf's write, and the lock must not sit across a
	// slow download. loadBuf already handles the hash having moved in between
	// (the buf == nil branch) -- this only makes the read itself well-defined.
	f.loadBufMutex.Lock()
	oldHash := f.hash
	f.loadBufMutex.Unlock()
	buf, hash, err := f.vehicle.Read(f.ctx, oldHash)
	if err != nil {
		f.backoff.AddAttempt() // add a failed attempt to backoff
		return lo.Empty[V](), false, err
	}
	return f.loadBuf(buf, hash, f.vehicle.Type() != P.File)
}

func (f *Fetcher[V]) SideUpdate(buf []byte) (V, bool, error) {
	return f.loadBuf(buf, utils.MakeHash(buf), true)
}

func (f *Fetcher[V]) loadBuf(buf []byte, hash utils.HashType, updateFile bool) (V, bool, error) {
	f.loadBufMutex.Lock()
	defer f.loadBufMutex.Unlock()

	now := time.Now()
	if f.hash.Equal(hash) {
		if updateFile {
			_ = os.Chtimes(f.vehicle.Path(), now, now)
		}
		f.updatedAt = now
		f.backoff.Reset() // no error, reset backoff
		return lo.Empty[V](), true, nil
	}

	if buf == nil { // f.hash has been changed between f.vehicle.Read but should not happen (cause by concurrent)
		return lo.Empty[V](), true, nil
	}

	contents, err := f.parser(buf)
	if err != nil {
		f.backoff.AddAttempt() // add a failed attempt to backoff
		return lo.Empty[V](), false, err
	}
	f.backoff.Reset() // no error, reset backoff

	if updateFile {
		if err = f.vehicle.Write(buf); err != nil {
			return lo.Empty[V](), false, err
		}
	}
	f.updatedAt = now
	f.hash = hash
	if !f.firstLoaded {
		// Whichever path got here first loaded the provider; the background first
		// load, if it is still retrying, has nothing left to fetch.
		f.firstLoaded = true
		close(f.firstLoadDone)
	}

	if f.onUpdate != nil {
		f.onUpdate(contents)
	}

	return contents, false, nil
}

func (f *Fetcher[V]) Close() error {
	f.ctxCancel()
	if f.watcher != nil {
		_ = f.watcher.Close()
	}
	return nil
}

func (f *Fetcher[V]) pullLoop(forceUpdate bool) {
	f.loadBufMutex.Lock()
	updatedAt := f.updatedAt
	f.loadBufMutex.Unlock()
	initialInterval := f.interval - time.Since(updatedAt)
	if initialInterval > f.interval {
		initialInterval = f.interval
	}

	if forceUpdate {
		log.Warnln("[Provider] %s not updated for a long time, force refresh", f.Name())
		f.updateWithLog()
	}
	if attempt := f.backoff.Attempt(); attempt > 0 { // f.Update() was failed, decrease the interval from backoff to achieve fast retry
		if duration := f.backoff.ForAttempt(attempt); duration < initialInterval {
			initialInterval = duration
		}
	}

	timer := time.NewTimer(initialInterval)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			f.updateWithLog()
			interval := f.interval
			if attempt := f.backoff.Attempt(); attempt > 0 { // f.Update() was failed, decrease the interval from backoff to achieve fast retry
				if duration := f.backoff.ForAttempt(attempt); duration < interval {
					interval = duration
				}
			}
			timer.Reset(interval)
		case <-f.ctx.Done():
			return
		}
	}
}

func (f *Fetcher[V]) startPullLoop(forceUpdate bool) (err error) {
	// pull contents automatically
	if f.vehicle.Type() == P.File {
		f.watcher, err = fswatch.NewWatcher(fswatch.Options{
			Path:     []string{f.vehicle.Path()},
			Callback: f.updateCallback,
		})
		if err != nil {
			return err
		}
		err = f.watcher.Start()
		if err != nil {
			return err
		}
	} else if f.interval > 0 {
		go f.pullLoop(forceUpdate)
	}
	return
}

// DeferRemoteInitialFetch makes Initial return ErrRemoteFetchDeferred for a remote
// vehicle with no local copy instead of downloading on the caller's thread; the
// first download then runs in the background with backoff until it succeeds. Set by
// the Apple binding, where Initial runs on the tunnel's Start path under a memory and
// time budget; false keeps upstream's behaviour exactly.
var DeferRemoteInitialFetch bool

// ErrRemoteFetchDeferred is what Initial returns when DeferRemoteInitialFetch moved
// the first download into the background: the provider is empty for now, not broken.
var ErrRemoteFetchDeferred = errors.New("remote fetch deferred to the background")

// DefaultRemoteSizeLimit caps a remote download whose definition names no size-limit.
// Zero keeps upstream's behaviour (no cap). The Apple binding sets it because the
// body is read into memory inside a process with a fixed ceiling.
var DefaultRemoteSizeLimit int64

// The executor bounds provider loading to five at a time on Apple hardware
// (hub/executor/concurrent_load_apple.go), and that bound was measured against the
// thing it covers: Initial, which parses a local file. A deferred Initial returns
// before its download starts, so the slot is back in the pool while the body is still
// on the wire and the parse has not happened -- N deferred providers were N bodies and
// N parses in flight, outside the bound that exists for exactly that peak (2026-09-05
// audit, F03). This is the sibling bound for the work the first one lets go of: the
// download and parse a deferred first load does in the background. Two pools of five,
// not one shared pool of five, because the executor's runs on the Start path and this
// one runs behind it; the peak they each guard is the same shape, but the executor's
// pool is empty again by the time these fill.
//
// Zero is upstream's behaviour: no bound. The Apple binding sets it during Setup,
// beside DeferRemoteInitialFetch, which is the only thing that creates this work.
var firstLoadAdmission struct {
	sync.Mutex
	limit int
	slots chan struct{}
}

// SetFirstLoadConcurrency bounds concurrent deferred first loads process-wide; zero
// removes the bound. Loads already admitted keep their slot.
func SetFirstLoadConcurrency(n int) {
	firstLoadAdmission.Lock()
	defer firstLoadAdmission.Unlock()
	if n < 0 {
		n = 0
	}
	firstLoadAdmission.limit = n
	if n == 0 {
		firstLoadAdmission.slots = nil
		return
	}
	firstLoadAdmission.slots = make(chan struct{}, n)
}

// FirstLoadConcurrency reports the current bound; zero means none.
func FirstLoadConcurrency() int {
	firstLoadAdmission.Lock()
	defer firstLoadAdmission.Unlock()
	return firstLoadAdmission.limit
}

// The first-load backoff is its own schedule, not the pull loop's: that one is
// bounded by the interval, and an interval of zero means "never refresh", which must
// not also mean "never load".
var (
	deferredFirstLoadMinBackoff = 10 * time.Second
	deferredFirstLoadMaxBackoff = 10 * time.Minute
)

// firstLoadLoop downloads a deferred provider until it lands -- by its own download
// or by anything else that loads the provider first, a side update from the app being
// the case that happens (F01) -- then starts the pull loop if the interval asks for
// one. Every failure is logged with the wait that follows it, so a provider that never
// arrives says so in the log rather than staying silently empty.
//
// This goroutine is the only thing that starts the pull loop for a deferred provider,
// which is what makes "exactly one pull loop" hold by construction: a side update does
// not start one, it closes firstLoadDone and this loop starts it on the way out. The
// two completions can coincide -- a side update lands while this loop's own attempt is
// in flight and that attempt then succeeds -- and the loop still leaves through one
// branch, never both.
func (f *Fetcher[V]) firstLoadLoop() {
	backoff := slowdown.Backoff{Factor: 2, Min: deferredFirstLoadMinBackoff, Max: deferredFirstLoadMaxBackoff}
	for {
		select {
		case <-f.firstLoadDone:
			// Loaded by another path before this attempt was due: no download.
			f.finishFirstLoad("loaded before its background download was needed")
			return
		case <-f.ctx.Done():
			return
		default:
		}
		release, admitted := f.admitFirstLoad()
		if !admitted {
			return // closed while waiting for a slot
		}
		_, _, err := f.Update()
		release()
		if err == nil {
			f.finishFirstLoad("loaded in the background")
			return
		}
		wait := backoff.Duration()
		log.Warnln("[Provider] %s background load failed: %s; next attempt in %s", f.Name(), err.Error(), wait)
		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
		case <-f.firstLoadDone:
			timer.Stop()
			f.finishFirstLoad("loaded by a side update while its background download was still retrying")
			return
		case <-f.ctx.Done():
			timer.Stop()
			return
		}
	}
}

// finishFirstLoad is the one exit of firstLoadLoop that a loaded provider takes: it
// says how the load happened and hands over to the pull loop the interval asks for.
func (f *Fetcher[V]) finishFirstLoad(how string) {
	log.Infoln("[Provider] %s %s", f.Name(), how)
	if f.interval > 0 {
		go f.pullLoop(false)
	}
}

// admitFirstLoad takes a slot in the process-wide first-load admission, or returns
// admitted=false when the fetcher closes while waiting. With no bound configured the
// slot is free and release is a no-op. The slot covers Update whole -- the download
// and the parse -- because the parse buffer is the peak the bound exists for (F03).
func (f *Fetcher[V]) admitFirstLoad() (release func(), admitted bool) {
	firstLoadAdmission.Lock()
	slots := firstLoadAdmission.slots
	firstLoadAdmission.Unlock()
	if slots == nil {
		return func() {}, true
	}
	select {
	case slots <- struct{}{}:
		return func() { <-slots }, true
	case <-f.ctx.Done():
		return nil, false
	}
}

func (f *Fetcher[V]) updateCallback(path string) {
	f.updateWithLog()
}

func (f *Fetcher[V]) updateWithLog() {
	_, same, err := f.Update()
	if err != nil {
		log.Errorln("[Provider] %s pull error: %s", f.Name(), err.Error())
		return
	}

	if same {
		log.Debugln("[Provider] %s's content doesn't change", f.Name())
		return
	}

	log.Infoln("[Provider] %s's content update", f.Name())
	return
}

func NewFetcher[V any](name string, interval time.Duration, vehicle P.Vehicle, bundleFile BundleFile, parser Parser[V], onUpdate func(V)) *Fetcher[V] {
	ctx, cancel := context.WithCancel(context.Background())
	minBackoff := 10 * time.Second
	if interval < minBackoff {
		minBackoff = interval
	}
	return &Fetcher[V]{
		ctx:           ctx,
		ctxCancel:     cancel,
		name:          name,
		bundleFile:    bundleFile,
		vehicle:       vehicle,
		parser:        parser,
		onUpdate:      onUpdate,
		interval:      interval,
		firstLoadDone: make(chan struct{}),
		backoff: slowdown.Backoff{
			Factor: 2,
			Jitter: false,
			Min:    minBackoff,
			Max:    interval,
		},
	}
}
