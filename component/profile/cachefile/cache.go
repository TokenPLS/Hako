package cachefile

import (
	syncatomic "sync/atomic"

	"errors"
	"os"
	"sync"
	"time"

	"github.com/TokenPLS/Hako/component/profile"
	C "github.com/TokenPLS/Hako/constant"
	"github.com/TokenPLS/Hako/log"

	"github.com/metacubex/bbolt"
)

var (
	initOnce     sync.Once
	initMu       sync.Mutex
	initialized  bool
	disabled     bool
	fileMode     os.FileMode = 0o666
	defaultCache *CacheFile

	bucketSelected         = []byte("selected")
	bucketFakeip           = []byte("fakeip")
	bucketFakeip6          = []byte("fakeip6")
	bucketETag             = []byte("etag")
	bucketSubscriptionInfo = []byte("subscriptioninfo")
	bucketStorage          = []byte("storage")
)

// CacheFile store and update the cache file
type CacheFile struct {
	DB *bbolt.DB
}

// selectedObserver is told that a group's selection changed, by whoever changed it.
//
// The seam is here because this is the one function both writers reach: the embedded
// controller's PUT /proxies/{name} (hub/route/proxies.go:98) and the binding's own selection API
// (bind/hako/control.go:35), each immediately after calling SelectAble.Set. A consumer holding
// "which node is selected" as its own state cannot otherwise learn about the change it did not
// make -- which showed up as a user switching nodes in a dashboard while the app's home screen
// kept naming the old one.
//
// It fires BEFORE the persistence checks on purpose. Those two early returns are about whether
// the choice is written to disk; the choice happened either way, and an observer that went quiet
// whenever store-selected was off would be an instrument that stops reporting under a condition
// nobody would think to check. A test pins the position, and it only pins it because it sets
// StoreSelected false itself -- the first version assumed the default was false, measured it was
// true, and passed while protecting nothing.
var selectedObserver syncatomic.Pointer[func(group, selected string)]

// SetSelectedObserver installs the seam. Nil removes it.
func SetSelectedObserver(observe func(group, selected string)) {
	if observe == nil {
		selectedObserver.Store(nil)
		return
	}
	selectedObserver.Store(&observe)
}

func (c *CacheFile) SetSelected(group, selected string) {
	if observe := selectedObserver.Load(); observe != nil {
		(*observe)(group, selected)
	}
	if !profile.StoreSelected.Load() {
		return
	} else if c.DB == nil {
		return
	}

	err := c.DB.Batch(func(t *bbolt.Tx) error {
		bucket, err := t.CreateBucketIfNotExists(bucketSelected)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(group), []byte(selected))
	})
	if err != nil {
		log.Warnln("[CacheFile] write cache to %s failed: %s", c.DB.Path(), err.Error())
		return
	}
}

func (c *CacheFile) SelectedMap() map[string]string {
	if !profile.StoreSelected.Load() {
		return nil
	} else if c.DB == nil {
		return nil
	}

	mapping := map[string]string{}
	c.DB.View(func(t *bbolt.Tx) error {
		bucket := t.Bucket(bucketSelected)
		if bucket == nil {
			return nil
		}

		c := bucket.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			mapping[string(k)] = string(v)
		}
		return nil
	})
	return mapping
}

func (c *CacheFile) Close() error {
	if c == nil || c.DB == nil {
		return nil
	}
	return c.DB.Close()
}

// DisablePersistentCache configures this process to use a nil-backed cache.
// It must run before Cache. The containing iOS App uses this for dry-run
// config parsing so it cannot hold the Packet Tunnel's App Group bbolt lock.
// The Extension runs in another process and never calls this function.
func DisablePersistentCache() error {
	initMu.Lock()
	defer initMu.Unlock()
	if initialized {
		if disabled {
			return nil
		}
		return errors.New("cachefile: cache already initialized")
	}
	disabled = true
	return nil
}

func initCache() {
	initMu.Lock()
	initialized = true
	cacheDisabled := disabled
	initMu.Unlock()
	if cacheDisabled {
		defaultCache = &CacheFile{}
		return
	}
	options := bbolt.Options{Timeout: time.Second, NoStatistics: true}
	db, err := bbolt.Open(C.Path.Cache(), fileMode, &options)
	switch err {
	case bbolt.ErrInvalid, bbolt.ErrChecksum, bbolt.ErrVersionMismatch:
		if err = os.Remove(C.Path.Cache()); err != nil {
			log.Warnln("[CacheFile] remove invalid cache file error: %s", err.Error())
			break
		}
		log.Infoln("[CacheFile] remove invalid cache file and create new one")
		db, err = bbolt.Open(C.Path.Cache(), fileMode, &options)
	}
	if err != nil {
		log.Warnln("[CacheFile] can't open cache file: %s", err.Error())
	}

	defaultCache = &CacheFile{
		DB: db,
	}
}

// Cache return singleton of CacheFile
func Cache() *CacheFile {
	initOnce.Do(initCache)

	return defaultCache
}
