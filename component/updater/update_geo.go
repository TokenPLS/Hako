package updater

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/TokenPLS/Hako/common/atomic"
	"github.com/TokenPLS/Hako/common/utils"
	"github.com/TokenPLS/Hako/component/geodata"
	_ "github.com/TokenPLS/Hako/component/geodata/standard"
	"github.com/TokenPLS/Hako/component/mmdb"
	"github.com/TokenPLS/Hako/component/resource"
	C "github.com/TokenPLS/Hako/constant"
	"github.com/TokenPLS/Hako/log"

	"golang.org/x/sync/errgroup"
)

var (
	autoUpdate     bool
	updateInterval int

	updatingGeo atomic.Bool
)

func GeoAutoUpdate() bool {
	return autoUpdate
}

func GeoUpdateInterval() int {
	return updateInterval
}

func SetGeoAutoUpdate(newAutoUpdate bool) {
	autoUpdate = newAutoUpdate
}

func SetGeoUpdateInterval(newGeoUpdateInterval int) {
	updateInterval = newGeoUpdateInterval
}

// hashExistingDatabase hashes what is already on disk, through one handle and
// under the same ceiling as everything else here.
//
// Upstream read this file with os.ReadFile, for no reason but to decide
// whether the download changed anything -- so a file left oversized by a
// legacy build, a hand install or a half-written update was allocated whole
// before the bounded vehicle ever ran, which is the allocation the ceiling
// above exists to refuse. An oversized file hashes to nothing on purpose:
// it is not a database this process will open (component/mmdb/open.go refuses
// the same size), so the only useful outcome is for the next download to
// count as a change and replace it.
//
// Every failure is the same answer -- no hash known -- because that is what
// the caller does with it: ask the endpoint for the file.
func hashExistingDatabase(path string, ceiling int64) utils.HashType {
	f, err := os.Open(path)
	if err != nil {
		return utils.HashType{}
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Size() > ceiling {
		return utils.HashType{}
	}
	buf, err := io.ReadAll(io.LimitReader(f, info.Size()))
	if err != nil {
		return utils.HashType{}
	}
	return utils.MakeHash(buf)
}

// geoDatabase is one downloadable geo artifact: what it is called, where it
// comes from, where it goes, and how big it is allowed to be.
//
// The ceiling is per FORMAT and lives here so it cannot be attached at three
// call sites and forgotten at the fourth. It was one number for a while, and
// that made the updater refuse a .dat the Apple pipeline installs quite
// happily -- a file already in use that could never be refreshed.
type geoDatabase struct {
	name    string
	url     func() string
	path    func() string
	ceiling int64
}

var (
	mmdbDatabase    = geoDatabase{"MMDB", geodata.MmdbUrl, func() string { return C.Path.MMDB() }, geodata.MaxMMDBBytes}
	asnDatabase     = geoDatabase{"ASN", geodata.ASNUrl, func() string { return C.Path.ASN() }, geodata.MaxMMDBBytes}
	geoIPDatabase   = geoDatabase{"GeoIP", geodata.GeoIpUrl, func() string { return C.Path.GeoIP() }, geodata.MaxDatFileBytes}
	geoSiteDatabase = geoDatabase{"GeoSite", geodata.GeoSiteUrl, func() string { return C.Path.GeoSite() }, geodata.MaxDatFileBytes}
)

// geoVehicle is where the ceiling is attached, and the only place any geo
// download is built. One byte above the ceiling, so an oversized body comes
// back one byte too long instead of exactly full and ambiguous.
func geoVehicle(url, path string, ceiling int64) *resource.HTTPVehicle {
	return resource.NewHTTPVehicle(url, path, "", nil, defaultHttpTimeout, ceiling+1)
}

// downloadGeoDatabase is the one door every geo download goes through.
//
// Upstream built each vehicle with sizeLimit 0 -- no ceiling -- and the body
// is whatever a configured endpoint decides to send. That was already a
// full-size allocation on every platform (Read buffers the response), and the
// Windows opener now reads the published file into the heap as well, so an
// oversized database is charged two or three times over while a lookup keeps
// the old reader alive. The ceiling is the one this artifact's format sets,
// initialisation uses.
//
// io.LimitReader inside the vehicle stops at the limit instead of failing, so
// the ceiling is set one byte higher and the overflow is reported here: a
// silently truncated database would otherwise reach the verifier and be
// rejected as corrupt, which is the right outcome told the wrong way.
//
// changed is false when the endpoint returned what is already on disk; err is
// the caller's message with the database's name in it.
func downloadGeoDatabase(db geoDatabase) (data []byte, changed bool, err error) {
	name := db.name
	vehicle := geoVehicle(db.url(), db.path(), db.ceiling)
	oldHash := hashExistingDatabase(vehicle.Path(), db.ceiling)
	data, hash, err := vehicle.Read(context.Background(), oldHash)
	if err != nil {
		// The vehicle's error carries the request URL, and the reader's own
		// geox-url can hold a secret in its PATH -- which tier 1 keeps on
		// purpose, because a path is the producer's business. This is
		// the producer: the endpoint is named by its address.
		return nil, false, fmt.Errorf("can't download %s database file: %w", name, err)
	}
	if int64(len(data)) > db.ceiling {
		return nil, false, fmt.Errorf("can't download %s database file: larger than the %d MiB this accepts", name, db.ceiling>>20)
	}
	if oldHash.Equal(hash) { // same hash, ignored
		return nil, false, nil
	}
	if len(data) == 0 {
		return nil, false, fmt.Errorf("can't download %s database file: no data", name)
	}
	return data, true, nil
}

func UpdateMMDB() (err error) {
	data, changed, err := downloadGeoDatabase(mmdbDatabase)
	if err != nil || !changed {
		return err
	}

	// One transaction: staged beside the file, verified before the rename,
	// the verified reader published after it (component/mmdb/publisher.go).
	// Nothing here closes the old reader or writes over the old file: the
	// old path did both -- a nil reader panicked on Close, and
	// os.WriteFile truncated the inode a lookup was still mmap-reading.
	if err := mmdb.PublishIP(data); err != nil {
		return fmt.Errorf("can't save MMDB database file: %w", err)
	}
	return nil
}

func UpdateASN() (err error) {
	data, changed, err := downloadGeoDatabase(asnDatabase)
	if err != nil || !changed {
		return err
	}

	if err := mmdb.PublishASN(data); err != nil {
		return fmt.Errorf("can't save ASN database file: %w", err)
	}
	return nil
}

func UpdateGeoIp() (err error) {
	geoLoader, err := geodata.GetGeoDataLoader("standard")

	path := geoIPDatabase.path()
	data, changed, err := downloadGeoDatabase(geoIPDatabase)
	if err != nil || !changed {
		return err
	}

	if _, err = geoLoader.LoadIPByBytes(data, "cn"); err != nil {
		return fmt.Errorf("invalid GeoIP database file: %s", err)
	}

	defer geodata.ClearGeoIPCache()
	if err = stagedWrite(path, data); err != nil {
		return fmt.Errorf("can't save GeoIP database file: %w", err)
	}
	return nil
}

func UpdateGeoSite() (err error) {
	geoLoader, err := geodata.GetGeoDataLoader("standard")

	path := geoSiteDatabase.path()
	data, changed, err := downloadGeoDatabase(geoSiteDatabase)
	if err != nil || !changed {
		return err
	}

	if _, err = geoLoader.LoadSiteByBytes(data, "cn"); err != nil {
		return fmt.Errorf("invalid GeoSite database file: %s", err)
	}

	defer geodata.ClearGeoSiteCache()
	if err = stagedWrite(path, data); err != nil {
		return fmt.Errorf("can't save GeoSite database file: %w", err)
	}
	return nil
}

// stagedWrite replaces path with data through a temp file beside it: write,
// fsync, close, chmod to the previous mode, rename, fsync the directory. The
// .dat files are not mmap-mapped, so they need no reader transaction, but a
// loader that opens the file while safeWrite's os.WriteFile is truncating it
// reads a partial file -- and a partial GeoSite is a parse error that fails
// every rule built from it. The rename is the commit; nothing before it
// changes what a reader can open.
func stagedWrite(path string, data []byte) error {
	// Through a symlink, not over it -- including a dangling one, which is
	// what a first download looks like (component/mmdb ResolveLink). A link
	// that cannot be resolved is an error, not something to rename over.
	path, err := mmdb.ResolveLink(path)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*.staging")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	discard := func() { _ = tmp.Close(); _ = os.Remove(tmpPath) }
	if _, err := tmp.Write(data); err != nil {
		discard()
		return err
	}
	if err := tmp.Sync(); err != nil {
		discard()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	mode := os.FileMode(0o644)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// updateGeoDatabases is a variable so the gate around it can be tested
// without downloading anything.
var updateGeoDatabases = func() error {
	defer runtime.GC()

	b := errgroup.Group{}

	if geodata.GeoIpEnable() {
		if geodata.GeodataMode() {
			b.Go(UpdateGeoIp)
		} else {
			b.Go(UpdateMMDB)
		}
	}

	if geodata.ASNEnable() {
		b.Go(UpdateASN)
	}

	if geodata.GeoSiteEnable() {
		b.Go(UpdateGeoSite)
	}

	return b.Wait()
}

var ErrGetDatabaseUpdateSkip = errors.New("GEO database is updating, skip")

func UpdateGeoDatabases() error {
	log.Infoln("[GEO] Start updating GEO database")

	// One compare-and-swap, not a load followed by a store: two callers that
	// both saw false would both run, and two updates of one database racing
	// is the disorder the publisher's transaction exists to prevent.
	if !updatingGeo.CompareAndSwap(false, true) {
		return ErrGetDatabaseUpdateSkip
	}
	defer updatingGeo.Store(false)

	log.Infoln("[GEO] Updating GEO database")

	if err := updateGeoDatabases(); err != nil {
		log.Errorln("[GEO] update GEO database error: %s", err.Error())
		return err
	}

	return nil
}

func getUpdateTime() (time time.Time, err error) {
	filesToCheck := []string{
		C.Path.GeoIP(),
		C.Path.MMDB(),
		C.Path.ASN(),
		C.Path.GeoSite(),
	}

	for _, file := range filesToCheck {
		var fileInfo os.FileInfo
		fileInfo, err = os.Stat(file)
		if err == nil {
			return fileInfo.ModTime(), nil
		}
	}

	return
}

func RegisterGeoUpdater() {
	if updateInterval <= 0 {
		log.Errorln("[GEO] Invalid update interval: %d", updateInterval)
		return
	}

	go func() {
		ticker := time.NewTicker(time.Duration(updateInterval) * time.Hour)
		defer ticker.Stop()

		lastUpdate, err := getUpdateTime()
		if err != nil {
			log.Errorln("[GEO] Get GEO database update time error: %s", err.Error())
			return
		}

		log.Infoln("[GEO] last update time %s", lastUpdate)
		if lastUpdate.Add(time.Duration(updateInterval) * time.Hour).Before(time.Now()) {
			log.Infoln("[GEO] Database has not been updated for %v, update now", time.Duration(updateInterval)*time.Hour)
			if err := UpdateGeoDatabases(); err != nil {
				log.Errorln("[GEO] Failed to update GEO database: %s", err.Error())
				return
			}
		}

		for range ticker.C {
			log.Infoln("[GEO] updating database every %d hours", updateInterval)
			if err := UpdateGeoDatabases(); err != nil {
				log.Errorln("[GEO] Failed to update GEO database: %s", err.Error())
			}
		}
	}()
}
