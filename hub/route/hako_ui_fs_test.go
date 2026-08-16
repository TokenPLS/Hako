package route

import (
	"bytes"
	"io"
	"net"
	nethttp "net/http"
	"os"
	"path/filepath"
	"testing"

	http "github.com/metacubex/http"
)

// serveUI runs the exact handler shape server.go mounts on a real TCP
// listener — a real *net.TCPConn on the response side, so the sendfile
// upgrade path this fix defeats is genuinely in play — and returns its base
// URL. The client side is stdlib: the wire does not care which fork spoke.
func serveUI(t *testing.T, dir string) string {
	t.Helper()
	fs := http.StripPrefix("/ui", http.FileServer(hakoUserspaceFileSystem{http.Dir(dir)}))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: fs}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return "http://" + listener.Addr().String()
}

// The property that defeats the sendfile upgrade is the concrete type: net's
// fast path unwraps the io.LimitedReader ServeContent hands it and asserts
// *os.File. A file that is not one moves through the userspace copy — the same
// path every API response already uses, and the one the NE sandbox permits.
// Measured on a macOS packet tunnel: sendfile answered EPERM in ~15μs, eight
// out of eight, and every static response of 512 bytes or more died at exactly
// the sniff boundary while a 15,245-byte API response was fine.

func writeUIFixture(t *testing.T, size int) (string, []byte) {
	t.Helper()
	dir := t.TempDir()
	content := bytes.Repeat([]byte("x"), size)
	// Distinct head and tail, so a truncated or restarted copy cannot pass.
	copy(content, "HEAD")
	copy(content[size-4:], "TAIL")
	if err := os.WriteFile(filepath.Join(dir, "entry.css"), content, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir, content
}

func TestUIFilesAreNeverBareOSFiles(t *testing.T) {
	dir, _ := writeUIFixture(t, 600)

	file, err := hakoUserspaceFileSystem{http.Dir(dir)}.Open("/entry.css")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	if _, bare := file.(interface{ Fd() uintptr }); bare {
		t.Fatal("the served file still exposes an fd the sendfile upgrade can take")
	}
	if _, bare := file.(*os.File); bare {
		t.Fatal("the served file is a bare *os.File; net will upgrade its copy to sendfile")
	}
}

// Everything ServeContent needs — read, seek both ways, a second read after a
// rewind — must pass through untouched: the wrapper changes which syscall
// moves the bytes, never what they are.
func TestUserspaceFilePassesReadSeekThrough(t *testing.T) {
	dir, content := writeUIFixture(t, 600)

	file, err := hakoUserspaceFileSystem{http.Dir(dir)}.Open("/entry.css")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	sniff := make([]byte, 512)
	if _, err := io.ReadFull(file, sniff); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("the rewind ServeContent does after sniffing failed: %v", err)
	}
	full, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(full, content) {
		t.Fatalf("second read after rewind returned %d bytes, want %d", len(full), len(content))
	}
}

// End to end through the exact handler shape server.go mounts, with a file
// past the 512-byte sniff boundary — the size class that died on device.
func TestUIHandlerServesAWholeFilePastTheSniffBoundary(t *testing.T) {
	dir, content := writeUIFixture(t, 5106)

	base := serveUI(t, dir)

	response, err := nethttp.Get(base + "/ui/entry.css")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("reading past the sniff boundary failed: %v", err)
	}
	if !bytes.Equal(body, content) {
		t.Fatalf("served %d bytes, want %d — the exact on-device truncation was 512", len(body), len(content))
	}
}

// Directory listings ride Readdir; the wrapper must not lose it.
func TestUserspaceFileListsDirectories(t *testing.T) {
	dir, _ := writeUIFixture(t, 600)

	base := serveUI(t, dir)

	response, err := nethttp.Get(base + "/ui/")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte("entry.css")) {
		t.Fatalf("directory listing lost its entries: %s", body)
	}
}
