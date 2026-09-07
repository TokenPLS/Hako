package resource

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/TokenPLS/Hako/common/utils"
	mihomoHttp "github.com/TokenPLS/Hako/component/http"
	"github.com/TokenPLS/Hako/component/profile/cachefile"
	P "github.com/TokenPLS/Hako/constant/provider"

	"github.com/metacubex/http"
)

const (
	DefaultHttpTimeout = time.Second * 20

	fileMode os.FileMode = 0o666
	dirMode  os.FileMode = 0o755
)

var (
	etag = false
)

func ETag() bool {
	return etag
}

func SetETag(b bool) {
	etag = b
}

var atomicCacheDirectory atomic.Pointer[string]

// SetAtomicCacheDirectory opts one private Apple cache directory into complete
// generation replacement. Other paths retain the upstream write semantics.
func SetAtomicCacheDirectory(directory string) error {
	if directory == "" {
		atomicCacheDirectory.Store(nil)
		return nil
	}
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return err
	}
	atomicCacheDirectory.Store(&absolute)
	return nil
}

func safeWrite(path string, buf []byte) error {
	dir := filepath.Dir(path)

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, dirMode); err != nil {
			return err
		}
	}

	if root := atomicCacheDirectory.Load(); root != nil {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(*root, absolute)
		if err == nil && relative != "." && relative != ".." &&
			!strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative) {
			return writeAtomicCache(path, buf)
		}
	}
	return os.WriteFile(path, buf, fileMode)
}

func writeAtomicCache(path string, buf []byte) error {
	mode := os.FileMode(0o600)
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("provider cache is not a regular file: %s", path)
		}
		mode = info.Mode().Perm()
	} else if !os.IsNotExist(err) {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".hako-provider-cache-*")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	defer temporary.Close()
	if err = temporary.Chmod(mode); err != nil {
		return err
	}
	if _, err = temporary.Write(buf); err != nil {
		return err
	}
	if err = temporary.Sync(); err != nil {
		return err
	}
	if err = temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporary.Name(), path)
}

type FileVehicle struct {
	path string
}

func (f *FileVehicle) Type() P.VehicleType {
	return P.File
}

func (f *FileVehicle) Path() string {
	return f.path
}

func (f *FileVehicle) Url() string {
	return "file://" + f.path
}

func (f *FileVehicle) Read(ctx context.Context, oldHash utils.HashType) (buf []byte, hash utils.HashType, err error) {
	buf, err = os.ReadFile(f.path)
	if err != nil {
		return
	}
	hash = utils.MakeHash(buf)
	return
}

func (f *FileVehicle) Proxy() string {
	return ""
}

func (f *FileVehicle) Write(buf []byte) error {
	return safeWrite(f.path, buf)
}

func NewFileVehicle(path string) *FileVehicle {
	return &FileVehicle{path: path}
}

type HTTPVehicle struct {
	url       string
	path      string
	proxy     string
	header    http.Header
	timeout   time.Duration
	sizeLimit int64
	// sizeLimitDefaulted: sizeLimit came from DefaultRemoteSizeLimit, not from the
	// profile. The two limits behave differently on overrun, on purpose -- see Read.
	sizeLimitDefaulted bool
	inRead             func(response *http.Response)
	provider           P.ProxyProvider
}

func (h *HTTPVehicle) Url() string {
	return h.url
}

func (h *HTTPVehicle) Type() P.VehicleType {
	return P.HTTP
}

func (h *HTTPVehicle) Path() string {
	return h.path
}

func (h *HTTPVehicle) Proxy() string {
	return h.proxy
}

func (h *HTTPVehicle) Write(buf []byte) error {
	return safeWrite(h.path, buf)
}

func (h *HTTPVehicle) SetInRead(fn func(response *http.Response)) {
	h.inRead = fn
}

func (h *HTTPVehicle) Read(ctx context.Context, oldHash utils.HashType) (buf []byte, hash utils.HashType, err error) {
	ctx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()
	header := h.header
	setIfNoneMatch := false
	if etag && oldHash.IsValid() {
		etagWithHash := cachefile.Cache().GetETagWithHash(h.url)
		if oldHash.Equal(etagWithHash.Hash) && etagWithHash.ETag != "" {
			if header == nil {
				header = http.Header{}
			} else {
				header = header.Clone()
			}
			header.Set("If-None-Match", etagWithHash.ETag)
			setIfNoneMatch = true
		}
	}
	resp, err := mihomoHttp.HttpRequest(ctx, h.url, http.MethodGet, header, nil, mihomoHttp.WithSpecialProxy(h.proxy))
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if h.inRead != nil {
		h.inRead(resp)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		if setIfNoneMatch && resp.StatusCode == http.StatusNotModified {
			return nil, oldHash, nil
		}
		err = errors.New(resp.Status)
		return
	}
	var reader io.Reader = resp.Body
	if h.sizeLimit > 0 {
		limit := h.sizeLimit
		if h.sizeLimitDefaulted {
			// One byte past the cap is read so an overrun can be told from a body
			// that is exactly the cap. Upstream's own explicit size-limit has no
			// such byte and truncates: a body past the limit comes back cut to the
			// limit, hashed, and reported as a success. That is what a profile
			// that WRITES size-limit gets from mihomo, and this build keeps it --
			// refusing there would be stricter than upstream on a field upstream
			// defines. The cap this build ADDS, for a profile that names none, has
			// no upstream behaviour to keep, and "success with the tail missing"
			// is the one outcome nobody asked for: a rule set one byte over lost
			// its last rules and said nothing (2026-09-05 audit, F04).
			limit++
		}
		reader = io.LimitReader(reader, limit)
	}
	buf, err = io.ReadAll(reader)
	if err != nil {
		return
	}
	if h.sizeLimitDefaulted && int64(len(buf)) > h.sizeLimit {
		// Nothing is hashed, cached or written: the caller's Update fails, the
		// content already loaded stays in use, and the sentence names the cap
		// and the two ways out.
		buf = nil
		err = fmt.Errorf("response is larger than the %d-byte limit this build applies to a provider with no size-limit; set size-limit to accept it, or trim the source", h.sizeLimit)
		return
	}
	hash = utils.MakeHash(buf)
	if etag {
		cachefile.Cache().SetETagWithHash(h.url, cachefile.EtagWithHash{
			Hash: hash,
			ETag: resp.Header.Get("ETag"),
			Time: time.Now(),
		})
	}
	return
}

func NewHTTPVehicle(url string, path string, proxy string, header http.Header, timeout time.Duration, sizeLimit int64) *HTTPVehicle {
	defaulted := false
	if sizeLimit <= 0 && DefaultRemoteSizeLimit > 0 {
		sizeLimit = DefaultRemoteSizeLimit
		defaulted = true
	}
	return &HTTPVehicle{
		url:                url,
		path:               path,
		proxy:              proxy,
		header:             header,
		timeout:            timeout,
		sizeLimit:          sizeLimit,
		sizeLimitDefaulted: defaulted,
	}
}
