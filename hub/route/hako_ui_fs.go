package route

import http "github.com/metacubex/http"

// The dashboard's static files, served without sendfile.
//
// Inside an embedded extension the /ui file server half-works in a way nothing
// logs: every response of 512 bytes or more is cut off at exactly 512 and the
// connection closes, while every API response of any size is fine. Measured on
// a macOS packet tunnel (2026-08-14): /proxies at 15,245 bytes complete,
// a 5,106-byte stylesheet truncated to exactly 512, three out of three.
//
// The 512 is the boundary between two transmit paths, not a buffer leak.
// ServeContent sniffs the first 512 bytes for the content type and writes them
// with the header in userspace; the remainder goes through io.Copy, and when
// the source is a bare *os.File and the sink a *net.TCPConn, net upgrades that
// copy to sendfile(2). The API handlers write JSON from userspace and never
// touch that path, which is why they are immune. A sandboxed Network
// Extension is exactly where a syscall upgrade can be refused while plain
// writes are not, and Go treats a refusal other than ENOSYS/EINVAL as a copy
// error, which kills the connection mid-file.
//
// So in embed mode the file server's files are wrapped: the concrete type net
// sees is hakoUserspaceFile, the *os.File assertion inside the sendfile
// upgrade fails, and every byte moves through the ordinary userspace copy the
// API responses already use. Read, Seek and Readdir pass through untouched, so
// range requests and directory listings behave identically; the only change is
// which syscall moves the bytes. Ordinary non-embedded mihomo keeps the
// upstream fast path.
type hakoUserspaceFileSystem struct{ inner http.FileSystem }

func (fsys hakoUserspaceFileSystem) Open(name string) (http.File, error) {
	file, err := fsys.inner.Open(name)
	if err != nil {
		return nil, err
	}
	return hakoUserspaceFile{file}, nil
}

// hakoUserspaceFile hides the concrete *os.File behind a struct. Promotion
// forwards every method; the struct type is what defeats the interface probe.
type hakoUserspaceFile struct{ http.File }
