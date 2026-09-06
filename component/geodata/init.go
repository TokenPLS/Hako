package geodata

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/TokenPLS/Hako/common/atomic"
	mihomoHttp "github.com/TokenPLS/Hako/component/http"
	"github.com/TokenPLS/Hako/component/mmdb"
	C "github.com/TokenPLS/Hako/constant"
	"github.com/TokenPLS/Hako/log"

	"github.com/metacubex/http"
)

var (
	initGeoSite bool
	initGeoIP   int
	initASN     bool

	initGeoSiteMutex sync.Mutex
	initGeoIPMutex   sync.Mutex
	initASNMutex     sync.Mutex

	geoIpEnable   atomic.Bool
	geoSiteEnable atomic.Bool
	asnEnable     atomic.Bool

	geoIpUrl   string
	mmdbUrl    string
	geoSiteUrl string
	asnUrl     string
)

func GeoIpUrl() string {
	return geoIpUrl
}

func SetGeoIpUrl(url string) {
	geoIpUrl = url
}

func MmdbUrl() string {
	return mmdbUrl
}

func SetMmdbUrl(url string) {
	mmdbUrl = url
}

func GeoSiteUrl() string {
	return geoSiteUrl
}

func SetGeoSiteUrl(url string) {
	geoSiteUrl = url
}

func ASNUrl() string {
	return asnUrl
}

func SetASNUrl(url string) {
	asnUrl = url
}

// downloadDatabase fetches a MaxMind database and hands the bytes to the
// publisher that owns that file, rather than writing the path itself.
//
// downloadToPath opens the destination with O_CREATE|O_WRONLY and streams into
// it, which writes THROUGH any live memory mapping -- the failure the staged
// transaction exists to remove. Initialisation is a second writer to
// the same two files, so it goes through the same door: the transaction
// stages, verifies, renames and publishes, and a lookup in flight keeps its
// reader until it lets go.
func downloadDatabase(url string, publish func([]byte) error) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*90)
	defer cancel()
	resp, err := mihomoHttp.HttpRequest(ctx, url, http.MethodGet, nil, nil)
	if err != nil {
		// The endpoint is the reader's own `geox-url`, and net/http wraps the
		// whole request URL into the error it returns. Tier 1 keeps ordinary
		// paths on purpose, so a path is the producer's business --
		// and this is the producer: `https://geo.example/tenant/SECRET/...`
		// would otherwise arrive in the log intact. The address says which
		// endpoint failed, which is what a reader needs.
		return err
	}
	defer resp.Body.Close()
	// A status, and a ceiling. The endpoint is configured, so the body is
	// whatever it decides to send: an error page would be published as a
	// database, and a body with no end would be read until the process died.
	// The largest real database here is about twelve megabytes.
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxMMDBBytes+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > MaxMMDBBytes {
		return fmt.Errorf("database is larger than the %d MiB this accepts", MaxMMDBBytes>>20)
	}
	return publish(data)
}

// The ceilings on what a configured endpoint may send. They are per FORMAT,
// because the formats are not the same size: an MMDB here is 9-12 MiB and the
// core will not open one past MaxMMDBBytes, while a .dat carrying the whole of
// GeoIP or GeoSite genuinely runs larger. One ceiling for both would either
// refuse real .dat files or stop bounding MMDB at the number that matters.
//
// Each is pinned to the other place that holds the same artifact to the same
// number: MaxMMDBBytes to the ceiling the core opens a file at, by
// TestTheDownloadAndOpenCeilingsAgree, and MaxDatFileBytes to the Apple
// pipeline's own limit by being the same constant.
const (
	MaxMMDBBytes    int64 = 64 << 20
	MaxDatFileBytes int64 = 128 << 20
)

// downloadToPath fetches a .dat file into path: a successful status, a
// ceiling, and a staging file that only becomes the destination once the whole
// body has arrived.
//
// Upstream opened the destination with O_CREATE|O_WRONLY and copied the body
// straight into it, checking neither the status nor the length. Three things
// came out of that. An endpoint answering 502 with an HTML page wrote the page
// into GeoSite.dat. A body with no end filled the disk, for as long as this
// context allows. And because the open carried no O_TRUNC, a shorter file left
// the tail of the previous one behind -- a .dat that parses as far as the seam
// and then does not.
//
// The staging file is beside the destination so the rename stays on one
// filesystem, and it is removed on every path that does not reach the rename.
func downloadToPath(url string, path string) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*90)
	defer cancel()
	resp, err := mihomoHttp.HttpRequest(ctx, url, http.MethodGet, nil, nil)
	if err != nil {
		// Named by its address, never printed whole -- the reader's own
		// endpoint can carry a secret in its path (see downloadDatabase).
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}

	// Through a symlink, not over it. A .dat is as likely as an MMDB to be a
	// link into a shared directory, and staging beside the LINK and renaming
	// onto it would replace the link with a regular file and leave the shared
	// target untouched -- which is the failure component/mmdb already resolves
	// this way for the databases beside it. A dangling link
	// resolves to its target, so the download lands where the link points.
	path, err = mmdb.ResolveLink(path)
	if err != nil {
		return err
	}
	staging, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.download")
	if err != nil {
		return err
	}
	stagingPath := staging.Name()
	defer func() {
		if err != nil {
			staging.Close()
			os.Remove(stagingPath)
		}
	}()

	written, err := io.Copy(staging, io.LimitReader(resp.Body, MaxDatFileBytes+1))
	if err != nil {
		return err
	}
	if written > MaxDatFileBytes {
		return fmt.Errorf("database is larger than the %d MiB this accepts", MaxDatFileBytes>>20)
	}
	if err = staging.Sync(); err != nil {
		return err
	}
	if err = staging.Close(); err != nil {
		return err
	}
	if err = os.Chmod(stagingPath, 0o644); err != nil {
		return err
	}
	return os.Rename(stagingPath, path)
}

// MarkGeoSiteVerified records that the caller has already validated the
// GeoSite file, so InitGeoSite skips its own health check.
//
// That check is not free: Verify loads the whole `CN` matcher — about ninety
// thousand domains — and the matcher singleflight retains it for the life of
// the process, whether or not any rule ever asks for CN. On an iOS Packet
// Tunnel that is ~14 MiB of a 50 MiB jetsam ceiling spent on a matcher the
// configuration may never name; both 2026-08-01 TestFlight subscriptions ask
// geosite for `gfw` alone (4,335 records) and the extension died at
// `per-process-limit` with the CN matcher aboard.
//
// The Apple pipeline validates staged geodata before publishing it
// (ValidateGeodataForIOS over immutable revisions), so its re-verification
// here is redundant. Skipping it never skips the real load: a file that
// cannot serve the requested code still fails that code's own
// LoadGeoSiteMatcher, and the configuration refuses to start with a readable
// reason. Callers that do not pre-validate keep the upstream behavior.
func MarkGeoSiteVerified() {
	initGeoSiteMutex.Lock()
	defer initGeoSiteMutex.Unlock()
	initGeoSite = true
}

func InitGeoSite() error {
	geoSiteEnable.Store(true)
	initGeoSiteMutex.Lock()
	defer initGeoSiteMutex.Unlock()
	if _, err := os.Stat(C.Path.GeoSite()); os.IsNotExist(err) {
		log.Infoln("Can't find GeoSite.dat, start download")
		if err := downloadToPath(GeoSiteUrl(), C.Path.GeoSite()); err != nil {
			return fmt.Errorf("can't download GeoSite.dat: %s", err.Error())
		}
		log.Infoln("Download GeoSite.dat finish")
		initGeoSite = false
	}
	if !initGeoSite {
		if err := Verify(C.GeositeName); err != nil {
			log.Warnln("GeoSite.dat invalid, download a replacement: %s", err)
			// The file is NOT removed first. Upstream removed it because its
			// download wrote straight into the path and wanted a clean one;
			// this one stages and renames, so the removal buys nothing -- and
			// it costs the symlink: unlinking the configured path leaves the
			// downloader nothing to resolve, so the replacement lands as a
			// regular file at the link's own path while the shared target
			// stays corrupt for everyone still reading it.
			if err := downloadToPath(GeoSiteUrl(), C.Path.GeoSite()); err != nil {
				return fmt.Errorf("can't download GeoSite.dat: %s", err.Error())
			}
			// What arrives the second time is not automatically better than
			// what arrived the first. Upstream set initGeoSite here without
			// looking, so an endpoint serving the same bad file twice left a
			// file marked good: the configuration failed later, where its
			// matcher loads, and no retry in this process could repair it
			// because the flag suppressed this check.
			if err := Verify(C.GeositeName); err != nil {
				return fmt.Errorf("downloaded GeoSite.dat is invalid: %s", err.Error())
			}
		}
		initGeoSite = true
	}
	return nil
}

func InitGeoIP() error {
	geoIpEnable.Store(true)
	initGeoIPMutex.Lock()
	defer initGeoIPMutex.Unlock()
	if GeodataMode() {
		if _, err := os.Stat(C.Path.GeoIP()); os.IsNotExist(err) {
			log.Infoln("Can't find GeoIP.dat, start download")
			if err := downloadToPath(GeoIpUrl(), C.Path.GeoIP()); err != nil {
				return fmt.Errorf("can't download GeoIP.dat: %s", err.Error())
			}
			log.Infoln("Download GeoIP.dat finish")
			initGeoIP = 0
		}

		if initGeoIP != 1 {
			if err := Verify(C.GeoipName); err != nil {
				log.Warnln("GeoIP.dat invalid, download a replacement: %s", err)
				// Not removed first, for the reason GeoSite gives above.
				if err := downloadToPath(GeoIpUrl(), C.Path.GeoIP()); err != nil {
					return fmt.Errorf("can't download GeoIP.dat: %s", err.Error())
				}
				// The replacement is checked before it counts as good, for
				// the same reason as GeoSite above.
				if err := Verify(C.GeoipName); err != nil {
					return fmt.Errorf("downloaded GeoIP.dat is invalid: %s", err.Error())
				}
			}
			initGeoIP = 1
		}
		return nil
	}

	if _, err := os.Stat(C.Path.MMDB()); os.IsNotExist(err) {
		log.Infoln("Can't find MMDB, start download")
		if err := downloadDatabase(MmdbUrl(), mmdb.PublishIP); err != nil {
			return fmt.Errorf("can't download MMDB: %s", err.Error())
		}
	}

	if initGeoIP != 2 {
		if !mmdb.Verify(C.Path.MMDB()) {
			// Not removed first: the transaction replaces the file by
			// rename, so the old one stays readable until the new one is
			// committed, and a removal here would take it out from under a
			// reader that is using it.
			log.Warnln("MMDB invalid, download a replacement")
			if err := downloadDatabase(MmdbUrl(), mmdb.PublishIP); err != nil {
				return fmt.Errorf("can't download MMDB: %s", err.Error())
			}
		}
		initGeoIP = 2
	}
	return nil
}

func InitASN() error {
	asnEnable.Store(true)
	initASNMutex.Lock()
	defer initASNMutex.Unlock()
	if _, err := os.Stat(C.Path.ASN()); os.IsNotExist(err) {
		log.Infoln("Can't find ASN.mmdb, start download")
		if err := downloadDatabase(ASNUrl(), mmdb.PublishASN); err != nil {
			return fmt.Errorf("can't download ASN.mmdb: %s", err.Error())
		}
		log.Infoln("Download ASN.mmdb finish")
		initASN = false
	}
	if !initASN {
		if !mmdb.Verify(C.Path.ASN()) {
			// See the MMDB branch: replaced by the transaction, not removed.
			log.Warnln("ASN invalid, download a replacement")
			if err := downloadDatabase(ASNUrl(), mmdb.PublishASN); err != nil {
				return fmt.Errorf("can't download ASN: %s", err.Error())
			}
		}
		initASN = true
	}
	return nil
}

func GeoIpEnable() bool {
	return geoIpEnable.Load()
}

func GeoSiteEnable() bool {
	return geoSiteEnable.Load()
}

func ASNEnable() bool {
	return asnEnable.Load()
}
