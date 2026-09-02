package geodata

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TokenPLS/Hako/component/geodata/router"
	C "github.com/TokenPLS/Hako/constant"
)

// A .dat download replaces the file only when a whole, in-bounds body arrives
// behind a successful status.
//
// Upstream copied the response straight into the destination, checking neither
// the status nor the length: a 502 with an HTML page became GeoSite.dat, an
// endless body filled the disk, and because the open carried no O_TRUNC a
// shorter file left the tail of the previous one behind.
func TestADatDownloadOnlyReplacesTheFileOnAWholeGoodBody(t *testing.T) {
	previous := []byte("the .dat that is already here, and is longer than what follows")

	t.Run("a bad status leaves the file alone", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
			w.Write([]byte("<html><body>502 Bad Gateway</body></html>"))
		}))
		defer server.Close()

		dir := t.TempDir()
		path := filepath.Join(dir, "GeoSite.dat")
		if err := os.WriteFile(path, previous, 0o644); err != nil {
			t.Fatal(err)
		}
		err := downloadToPath(server.URL, path)
		if err == nil || !strings.Contains(err.Error(), "502") {
			t.Fatalf("a 502 must be refused by its status, got %v", err)
		}
		assertUnchanged(t, path, previous)
		assertNoLeftovers(t, dir, "GeoSite.dat")
	})

	t.Run("a body that never ends leaves the file alone", func(t *testing.T) {
		// Endless on purpose. A body that merely overshoots would be caught
		// by the length check after the copy, which is not the thing being
		// asserted: the READ has to stop, or an endpoint fills the disk for
		// as long as the context allows. Against this handler a copy with no
		// ceiling never returns.
		const chunk = 1 << 20
		block := make([]byte, chunk)
		done := make(chan struct{})
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for {
				select {
				case <-done:
					return
				default:
				}
				if _, err := w.Write(block); err != nil {
					return
				}
			}
		}))
		defer server.Close()
		defer close(done)

		dir := t.TempDir()
		path := filepath.Join(dir, "GeoSite.dat")
		if err := os.WriteFile(path, previous, 0o644); err != nil {
			t.Fatal(err)
		}
		err := downloadToPath(server.URL, path)
		if err == nil || !strings.Contains(err.Error(), "larger than") {
			t.Fatalf("an oversized body must be refused by its size, got %v", err)
		}
		assertUnchanged(t, path, previous)
		assertNoLeftovers(t, dir, "GeoSite.dat")
	})

	t.Run("a good body replaces the file whole", func(t *testing.T) {
		fresh := []byte("shorter")
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write(fresh)
		}))
		defer server.Close()

		dir := t.TempDir()
		path := filepath.Join(dir, "GeoSite.dat")
		if err := os.WriteFile(path, previous, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := downloadToPath(server.URL, path); err != nil {
			t.Fatal(err)
		}
		// Whole, not overlaid: the previous file was longer, and none of it
		// may survive past the new contents.
		got, err := os.ReadFile(path)
		if err != nil || string(got) != string(fresh) {
			t.Fatalf("read back %q, want %q (%v)", got, fresh, err)
		}
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o644 {
			t.Fatalf("mode %v, want 0644 (%v)", info.Mode().Perm(), err)
		}
		assertNoLeftovers(t, dir, "GeoSite.dat")
	})
}

func assertUnchanged(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(want) {
		t.Fatalf("the file on disk must be untouched, read %q (%v)", got, err)
	}
}

// Nothing is left beside the destination: the staging file is removed on every
// path that does not reach the rename.
func assertNoLeftovers(t *testing.T, dir, expected string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != expected {
			t.Fatalf("left behind %q beside the destination", e.Name())
		}
	}
}

// A loader that answers from the file's contents, so a test can decide what
// counts as a valid .dat without pulling in component/geodata/standard --
// which imports this package, so an in-package test cannot have it.
type contentsLoader struct{}

func (contentsLoader) LoadSiteByPath(filename, list string) ([]*router.Domain, error) {
	// The name arrives as the asset's name, not a path -- the same way the
	// standard loader receives it, and it resolves it against the home dir.
	if filename == C.GeositeName {
		filename = C.Path.GeoSite()
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return contentsLoader{}.LoadSiteByBytes(data, list)
}

func (contentsLoader) LoadSiteByBytes(geositeBytes []byte, list string) ([]*router.Domain, error) {
	if !strings.HasPrefix(string(geositeBytes), "GOOD") {
		return nil, fmt.Errorf("not a geosite file")
	}
	return []*router.Domain{{Type: router.Domain_Domain, Value: "example.com"}}, nil
}

func (contentsLoader) LoadIPByPath(filename, country string) ([]*router.CIDR, error) {
	return nil, fmt.Errorf("not used")
}

func (contentsLoader) LoadIPByBytes(geoipBytes []byte, country string) ([]*router.CIDR, error) {
	return nil, fmt.Errorf("not used")
}

// What arrives the second time is checked before it counts as initialised.
//
// Upstream removed an invalid GeoSite.dat, downloaded again, and set the flag
// without looking at what came back. An endpoint serving the same bad file
// twice therefore left a file marked good: the configuration failed later,
// where its matcher loads, and no retry in the process could repair it,
// because the flag suppressed the check that would have caught it.
func TestASecondDownloadIsVerifiedBeforeItCountsAsInitialised(t *testing.T) {
	previousLoader := geoLoaderName
	previousURL := GeoSiteUrl()
	previousHome := C.Path.HomeDir()
	t.Cleanup(func() {
		geoLoaderName = previousLoader
		SetGeoSiteUrl(previousURL)
		C.SetHomeDir(previousHome)
		initGeoSite = false
	})
	RegisterGeoDataLoaderImplementationCreator("test-contents", func() LoaderImplementation { return contentsLoader{} })
	geoLoaderName = "test-contents"

	body := "NOT A GEOSITE FILE"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	defer server.Close()
	SetGeoSiteUrl(server.URL)

	C.SetHomeDir(t.TempDir())
	initGeoSite = false
	ClearGeoSiteCache()

	if err := InitGeoSite(); err == nil {
		t.Fatal("an endpoint serving a file that does not load must not initialise")
	} else if !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("the error must say what is wrong with the download, got %v", err)
	}
	if initGeoSite {
		t.Fatal("a file that does not load must not be marked initialised")
	}

	// The other direction: a file that loads initialises, so this cannot pass
	// by refusing everything.
	body = "GOOD geosite"
	C.SetHomeDir(t.TempDir())
	initGeoSite = false
	ClearGeoSiteCache()
	if err := InitGeoSite(); err != nil {
		t.Fatalf("a file that loads must initialise: %v", err)
	}
	if !initGeoSite {
		t.Fatal("a file that loads must be marked initialised")
	}
}

// A .dat download goes THROUGH a symlink, not over it.
//
// A .dat is as likely as an MMDB to be a link into a shared directory, and
// staging beside the link and renaming onto it would replace the link with a
// regular file and leave the shared target where it was. A dangling link is
// the case that hides it: nothing is at the link's own path, so a download
// that ignores the link looks like it worked.
func TestADatDownloadFollowsASymlinkToItsTarget(t *testing.T) {
	fresh := []byte("GOOD geosite")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(fresh)
	}))
	defer server.Close()

	shared := t.TempDir()
	home := t.TempDir()
	target := filepath.Join(shared, "GeoSite.dat")
	link := filepath.Join(home, "GeoSite.dat")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	if err := downloadToPath(server.URL, link); err != nil {
		t.Fatal(err)
	}

	info, err := os.Lstat(link)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the link must still be a link, got %v (%v)", info.Mode(), err)
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != string(fresh) {
		t.Fatalf("the target must hold the download, read %q (%v)", got, err)
	}
	assertNoLeftovers(t, shared, "GeoSite.dat")
	assertNoLeftovers(t, home, "GeoSite.dat")
}

// Replacing an invalid .dat keeps the symlink too.
//
// Verify follows the link and fails on the target's contents; the recovery
// then has to replace what the link POINTS AT. Upstream removed the
// configured path first -- which leaves the downloader nothing to resolve, so
// the replacement lands as a regular file at the link's own path while the
// shared target stays corrupt for everyone still reading it. This goes
// through InitGeoSite rather than calling the downloader, because the removal
// was there and not in the downloader.
func TestReplacingAnInvalidDatKeepsTheSymlink(t *testing.T) {
	previousLoader := geoLoaderName
	previousURL := GeoSiteUrl()
	previousHome := C.Path.HomeDir()
	t.Cleanup(func() {
		geoLoaderName = previousLoader
		SetGeoSiteUrl(previousURL)
		C.SetHomeDir(previousHome)
		initGeoSite = false
	})
	RegisterGeoDataLoaderImplementationCreator("test-contents", func() LoaderImplementation { return contentsLoader{} })
	geoLoaderName = "test-contents"

	fresh := []byte("GOOD geosite, freshly downloaded")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(fresh)
	}))
	defer server.Close()
	SetGeoSiteUrl(server.URL)

	shared := t.TempDir()
	home := t.TempDir()
	target := filepath.Join(shared, "GeoSite.dat")
	if err := os.WriteFile(target, []byte("NOT A GEOSITE FILE"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(home, "GeoSite.dat")); err != nil {
		t.Fatal(err)
	}
	C.SetHomeDir(home)
	initGeoSite = false
	ClearGeoSiteCache()

	if err := InitGeoSite(); err != nil {
		t.Fatal(err)
	}

	info, err := os.Lstat(filepath.Join(home, "GeoSite.dat"))
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the link must still be a link, got %v (%v)", info.Mode(), err)
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != string(fresh) {
		t.Fatalf("the shared target must hold the replacement, read %q (%v)", got, err)
	}
	assertNoLeftovers(t, home, "GeoSite.dat")
	assertNoLeftovers(t, shared, "GeoSite.dat")
}
