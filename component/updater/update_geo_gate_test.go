package updater

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/TokenPLS/Hako/common/utils"
	"github.com/TokenPLS/Hako/component/geodata"
)

// The gate around the database update is one compare-and-swap: a second
// caller that arrives while an update is running is told to skip, and the
// flag is released when the update returns.
func TestOnlyOneGeoUpdateRunsAtATime(t *testing.T) {
	previous := updateGeoDatabases
	t.Cleanup(func() { updateGeoDatabases = previous })
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	updateGeoDatabases = func() error {
		once.Do(func() { close(entered) })
		<-release
		return nil
	}
	first := make(chan error, 1)
	go func() { first <- UpdateGeoDatabases() }()
	<-entered
	if err := UpdateGeoDatabases(); !errors.Is(err, ErrGetDatabaseUpdateSkip) {
		t.Fatalf("a concurrent update must be skipped, got %v", err)
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	// Released: the next update may run.
	updateGeoDatabases = func() error { return nil }
	if err := UpdateGeoDatabases(); err != nil {
		t.Fatalf("after the first update returned, the next must run: %v", err)
	}
}

// The .dat files are replaced through a staging file and a rename, keeping
// the previous mode and leaving no staging file behind.
func TestStagedWriteReplacesThroughARename(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "GeoSite.dat")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := stagedWrite(path, []byte("new contents")); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "new contents" {
		t.Fatalf("read back %q, %v", got, err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o, want the previous file's 0600", info.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".staging") {
			t.Fatalf("a staging file survived: %s", e.Name())
		}
	}
	// A missing directory is created, like safeWrite did.
	nested := filepath.Join(dir, "sub", "dir", "GeoIP.dat")
	if err := stagedWrite(nested, []byte("x")); err != nil {
		t.Fatal(err)
	}
}

// A response past the ceiling is refused, and the database on disk is left
// exactly as it was.
//
// Upstream gave these vehicles no size limit, so the body a configured
// endpoint sends was read whole into memory -- and the published file is read
// into the heap again on Windows (component/mmdb/open_windows.go), where a
// replacement holds the outgoing copy and the incoming one at the same time.
// Every geo download goes through downloadGeoDatabase, so this covers the
// MMDB, ASN, GeoIP and GeoSite calls at once.
func TestADownloadPastTheCeilingIsRefusedAndLeavesTheFileAlone(t *testing.T) {
	const chunk = 1 << 20
	body := make([]byte, chunk)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// One byte past the ceiling: the vehicle's io.LimitReader stops at
		// the limit, so the overflow has to be visible in what it returns.
		for sent := int64(0); sent <= geodata.MaxMMDBBytes; sent += chunk {
			if _, err := w.Write(body); err != nil {
				return
			}
		}
	}))
	defer server.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "Country.mmdb")
	if err := os.WriteFile(path, []byte("the database that is already here"), 0o600); err != nil {
		t.Fatal(err)
	}

	data, changed, err := downloadGeoDatabase(testDatabase(server.URL, path, geodata.MaxMMDBBytes))
	if err == nil {
		t.Fatalf("an oversized body must be refused, got %d bytes changed=%v", len(data), changed)
	}
	if !strings.Contains(err.Error(), "larger than the") {
		t.Fatalf("the refusal must name the ceiling, got %v", err)
	}
	if changed || data != nil {
		t.Fatalf("a refused download hands back nothing, got %d bytes changed=%v", len(data), changed)
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil || string(got) != "the database that is already here" {
		t.Fatalf("the file on disk must be untouched, read %q %v", got, readErr)
	}
}

// The other direction: a body under the ceiling still arrives whole.
func TestADownloadUnderTheCeilingIsHandedBackWhole(t *testing.T) {
	payload := bytes.Repeat([]byte("mmdb"), 4096)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(payload)
	}))
	defer server.Close()

	path := filepath.Join(t.TempDir(), "Country.mmdb")
	data, changed, err := downloadGeoDatabase(testDatabase(server.URL, path, geodata.MaxMMDBBytes))
	if err != nil {
		t.Fatal(err)
	}
	if !changed || !bytes.Equal(data, payload) {
		t.Fatalf("got %d bytes changed=%v, want the %d that were sent", len(data), changed, len(payload))
	}
}

// A second download of what is already on disk is not a change, so nothing
// downstream republishes it.
func TestADownloadThatMatchesTheFileOnDiskIsNotAChange(t *testing.T) {
	payload := bytes.Repeat([]byte("mmdb"), 4096)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(payload)
	}))
	defer server.Close()

	path := filepath.Join(t.TempDir(), "Country.mmdb")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	data, changed, err := downloadGeoDatabase(testDatabase(server.URL, path, geodata.MaxMMDBBytes))
	if err != nil || changed || data != nil {
		t.Fatalf("same bytes must be no change, got %d bytes changed=%v err=%v", len(data), changed, err)
	}
}

// The ceiling is on the vehicle, not only on the check after it.
//
// A body that never ends is the case the check downstream cannot save: it
// only ever sees what was already read. So the assertion here is that the
// read STOPS -- exactly one byte past the ceiling -- while the endpoint is
// still sending. Without a limit on the vehicle the whole body arrives and
// this reads the difference.
func TestTheGeoVehicleStopsReadingAtTheCeiling(t *testing.T) {
	const chunk = 1 << 20
	const slack = 4 * chunk
	body := make([]byte, chunk)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for sent := int64(0); sent < geodata.MaxMMDBBytes+slack; sent += chunk {
			if _, err := w.Write(body); err != nil {
				return
			}
		}
	}))
	defer server.Close()

	path := filepath.Join(t.TempDir(), "Country.mmdb")
	data, _, err := geoVehicle(server.URL, path, geodata.MaxMMDBBytes).Read(context.Background(), utils.HashType{})
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(data)) != geodata.MaxMMDBBytes+1 {
		t.Fatalf("read %d bytes, want it to stop at the ceiling+1 (%d) -- the vehicle has no limit", len(data), geodata.MaxMMDBBytes+1)
	}
}

// The file already on disk is read under the same ceiling as the download.
//
// Upstream read it whole with os.ReadFile just to decide whether the download
// changed anything, so a file left oversized by a legacy build or a
// half-written update was allocated in full before the bounded vehicle ran.
// Above the ceiling it hashes to nothing, which is what makes the next
// download count as a change and replace it.
func TestTheFileOnDiskIsHashedOnlyUpToTheCeiling(t *testing.T) {
	dir := t.TempDir()

	ordinary := filepath.Join(dir, "Country.mmdb")
	contents := []byte("a database that is a reasonable size")
	if err := os.WriteFile(ordinary, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, want := hashExistingDatabase(ordinary, geodata.MaxMMDBBytes), utils.MakeHash(contents); !got.Equal(want) {
		t.Fatalf("an ordinary file must hash to its contents, got %v want %v", got, want)
	}

	over := filepath.Join(dir, "Huge.mmdb")
	f, err := os.Create(over)
	if err != nil {
		t.Fatal(err)
	}
	// Sparse: the point is the size the file reports, not spending the disk
	// to say it. Reading this whole would be the allocation being refused.
	if err := f.Truncate(geodata.MaxMMDBBytes + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if hash := hashExistingDatabase(over, geodata.MaxMMDBBytes); !hash.Equal(utils.HashType{}) {
		t.Fatalf("a file past the ceiling must not be hashed, got %v", hash)
	}

	// A file that is not there at all is the same answer, not a panic.
	if hash := hashExistingDatabase(filepath.Join(dir, "absent.mmdb"), geodata.MaxMMDBBytes); !hash.Equal(utils.HashType{}) {
		t.Fatalf("a missing file has no hash, got %v", hash)
	}
}

// An oversized file on disk does not stop the update that would replace it.
func TestAnOversizedFileOnDiskIsStillReplacedByTheNextDownload(t *testing.T) {
	payload := bytes.Repeat([]byte("mmdb"), 4096)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(payload)
	}))
	defer server.Close()

	path := filepath.Join(t.TempDir(), "Country.mmdb")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(geodata.MaxMMDBBytes + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()

	data, changed, err := downloadGeoDatabase(testDatabase(server.URL, path, geodata.MaxMMDBBytes))
	if err != nil || !changed || !bytes.Equal(data, payload) {
		t.Fatalf("the download must count as a change, got %d bytes changed=%v err=%v", len(data), changed, err)
	}
}

// testDatabase is one artifact aimed at a test server and a temp path.
func testDatabase(url, path string, ceiling int64) geoDatabase {
	return geoDatabase{
		name:    "MMDB",
		url:     func() string { return url },
		path:    func() string { return path },
		ceiling: ceiling,
	}
}

// Every geo download names its format's ceiling, and the update functions use
// these entries rather than building their own.
//
// A .dat and an MMDB are not the same size, and for a while they shared one
// number: the updater refused a .dat over 64 MiB while the Apple pipeline
// installs one at up to 128 MiB, so a file already in use could never be
// refreshed. Downloading a hundred megabytes to prove that would be a slow way
// to assert an integer, so what is asserted is the table the four call sites
// read from.
func TestEachGeoDownloadCarriesItsFormatsCeiling(t *testing.T) {
	for _, c := range []struct {
		db   geoDatabase
		name string
		want int64
	}{
		{mmdbDatabase, "MMDB", geodata.MaxMMDBBytes},
		{asnDatabase, "ASN", geodata.MaxMMDBBytes},
		{geoIPDatabase, "GeoIP", geodata.MaxDatFileBytes},
		{geoSiteDatabase, "GeoSite", geodata.MaxDatFileBytes},
	} {
		if c.db.name != c.name {
			t.Fatalf("entry named %q, want %q", c.db.name, c.name)
		}
		if c.db.ceiling != c.want {
			t.Fatalf("%s carries ceiling %d, want %d", c.name, c.db.ceiling, c.want)
		}
		if c.db.url == nil || c.db.path == nil {
			t.Fatalf("%s has no url or no path", c.name)
		}
	}
	if geodata.MaxDatFileBytes == geodata.MaxMMDBBytes {
		t.Fatal("the two ceilings are the same number again -- this test would then prove nothing")
	}
}
