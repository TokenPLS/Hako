package mmdb

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/TokenPLS/Hako/log"

	"github.com/oschwald/maxminddb-golang"
)

// A geo database is replaced as a transaction, not as a file write.
//
// The update path used to be: close the package reader, os.WriteFile the new
// bytes over the old path (O_TRUNC, in place), reset the once, let the next
// lookup reopen. Three things were wrong with it at once. The old reader was
// mmap'ed on the inode that got truncated, so a lookup still holding it read
// garbage or SIGBUS; a reader that had failed to open was nil and `.Close()`
// on it panicked; and nothing verified the new file before the old one was
// gone, so a bad download left no last-known-good on disk while the process
// kept a reader to a file that no longer matched.
//
// The publisher does it in the order that cannot lose either side:
//
//	write a temp file beside the target -> fsync, close -> OPEN AND VERIFY the
//	temp file -> chmod to the old file's mode -> rename over the target (the
//	commit point) -> fsync the directory (durability only) -> publish the
//	already-open reader.
//
// "Open before rename" is load-bearing. The other order -- rename first, open
// the final path second -- has a window where the rename succeeded and the open
// failed: the last-known-good is gone from disk while the runtime still holds
// the old reader. That is not a transaction. Any failure before the rename
// closes the candidate, removes the temp file and changes nothing; after the
// rename, publishing is an in-memory swap that cannot fail.
//
// The whole transaction holds the publisher's mutex, so two updates of one
// database cannot interleave (rename(A) -> rename(B) -> publish(B) ->
// publish(A) would leave B on disk and A in memory).
//
// Readers are handed out as reference-counted snapshots: a lookup acquires the
// current snapshot, uses it, releases it; publish swaps the current snapshot
// and retires the old one, which is closed by whoever releases its last
// reference -- publish never blocks on in-flight lookups and never closes a
// reader somebody is reading.

// snapshot is one open reader and the count of lookups currently using it.
type snapshot struct {
	reader       *maxminddb.Reader
	databaseType databaseType
	refs         int
	retired      bool
	closed       bool
	close        func() // the reader's Close, replaceable by tests that count
}

// readerHolder owns the current snapshot and retires old ones by refcount.
type readerHolder struct {
	mu      sync.Mutex
	current *snapshot
}

// acquire returns the current snapshot with one more reference, or nil when
// no database is available. Every acquire must be paired with a release.
func (h *readerHolder) acquire() *snapshot {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := h.current
	if s != nil {
		s.refs++
	}
	return s
}

// release drops one reference; a retired snapshot is closed by the release
// that takes it to zero. Closing happens under the holder's lock so a
// retired snapshot cannot be closed twice by two releasers.
func (h *readerHolder) release(s *snapshot) {
	if s == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	s.refs--
	if s.retired && s.refs == 0 && !s.closed {
		s.closed = true
		s.close()
	}
}

// publish makes reader current and retires the previous snapshot, closing it
// now if nobody holds it and otherwise leaving it to its last release. An
// in-memory operation: it cannot fail.
func (h *readerHolder) publish(reader *maxminddb.Reader) {
	next := &snapshot{reader: reader, databaseType: databaseTypeOf(reader), close: func() { _ = reader.Close() }}
	h.mu.Lock()
	defer h.mu.Unlock()
	old := h.current
	h.current = next
	if old != nil {
		old.retired = true
		if old.refs == 0 && !old.closed {
			old.closed = true
			old.close()
		}
	}
}

// available reports whether a database is published; a peek, no reference.
func (h *readerHolder) available() bool {
	if h == nil {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.current != nil
}

// tempFile is the part of *os.File the publisher uses.
type tempFile interface {
	Name() string
	Write(p []byte) (int, error)
	Sync() error
	Close() error
}

// fileOps is the seam between the transaction and the file system, so each
// stage can be made to fail in a test without a file system that fails.
type fileOps interface {
	CreateTemp(dir, pattern string) (tempFile, error)
	Open(path string) (*maxminddb.Reader, error)
	FromBytes(data []byte) (*maxminddb.Reader, error)
	Stat(path string) (os.FileInfo, error)
	Chmod(path string, mode os.FileMode) error
	Rename(oldPath, newPath string) error
	SyncDir(dir string) error
	Remove(path string) error
}

type osFileOps struct{}

func (osFileOps) CreateTemp(dir, pattern string) (tempFile, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return os.CreateTemp(dir, pattern)
}

// Open is the gate the staged transaction publishes behind: maxminddb.Open,
// which parses the metadata and the tree header.
//
// It deliberately does NOT call Reader.Verify(). Verify walks the whole
// database and, among other things, demands a non-empty description -- which
// mihomo's own `Meta-geoip0` database does not have. The real shipped
// geoip.metadb fails it ("description - Expected: non-empty slice Actual:
// map[]"), so a transaction gated on Verify rejects the product's default
// GeoIP database and every update of it. Measured before deciding: Open on
// its own already rejects empty bytes, garbage, and truncation at any point
// (a MaxMind DB keeps its metadata at the END of the file, so losing even the
// last byte fails the parse), which is what a bad download looks like. Verify
// therefore adds nothing this needs and costs the databases this ships.
// Upstream's own bar is the same one -- mmdb.Verify(path) is "does it open".
func (osFileOps) Open(path string) (*maxminddb.Reader, error) {
	// Mapped where a rename over a mapped file is safe, read into memory where
	// it is not (open_windows.go / open_other.go).
	return openDatabaseFile(path)
}

func (osFileOps) FromBytes(data []byte) (*maxminddb.Reader, error) { return maxminddb.FromBytes(data) }

func (osFileOps) Stat(path string) (os.FileInfo, error)     { return os.Stat(path) }
func (osFileOps) Chmod(path string, mode os.FileMode) error { return os.Chmod(path, mode) }
func (osFileOps) Rename(oldPath, newPath string) error      { return os.Rename(oldPath, newPath) }
func (osFileOps) Remove(path string) error                  { return os.Remove(path) }
func (osFileOps) SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// LoadError says which stage of the transaction failed. Nothing was published
// and, unless the stage was the rename itself, nothing on disk changed.
type LoadError struct {
	Database string
	Stage    string
	Err      error
}

func (e *LoadError) Error() string { return e.Database + ": " + e.Stage + ": " + e.Err.Error() }
func (e *LoadError) Unwrap() error { return e.Err }

// publisher replaces one database file and its reader as a transaction.
type publisher struct {
	name string
	path func() string
	ops  fileOps
	mu   sync.Mutex
	// Whether something authoritative is in the holder, and whether the disk
	// has already been tried. Both are guarded by mu, and both are set only
	// by something that SUCCEEDED -- a failed first update used to mark the
	// database "seeded" and strand the good file on disk (Codex round
	// 6). They are separate because a disk open that fails must not be
	// retried on every lookup (rules/common/geoip.go calls IPInstance per
	// match), while a failed publish or adopt leaves the disk untried.
	published     bool
	diskAttempted bool
	holder        *readerHolder
}

func newPublisher(name string, path func() string) *publisher {
	return &publisher{name: name, path: path, ops: osFileOps{}, holder: &readerHolder{}}
}

// resolveLink returns the path a replacement should be written to: the target
// of a symlink, or the path itself.
//
// The path may be a link into a shared directory, and the code this replaced
// wrote with os.WriteFile, which follows one; a rename onto the link would
// replace it with a regular file and detach that arrangement without saying
// so. filepath.EvalSymlinks cannot be used on its own here because it fails
// when the link is DANGLING -- which is exactly the first-download case, the
// target not there yet -- and failing meant renaming over the link after all.
// Readlink answers regardless of whether the target exists. The chain is
// followed to a bounded depth, and anything that is not a link, or that
// cannot be read, ends the walk on the path itself.
// ResolveLink is resolveLink for other packages that replace a file in place.
func ResolveLink(path string) (string, error) { return resolveLink(path) }

func resolveLink(path string) (string, error) {
	// Bounded, and it FAILS rather than handing back something still a link:
	// returning the last path after the bound meant renaming over a symlink
	// after all -- the exact outcome this exists to prevent -- and a cycle
	// (`a -> b -> a`) reaches the bound the same way. Eight is the depth a
	// sane arrangement stays under; more than that is a mistake worth
	// reporting rather than resolving.
	const maxDepth = 8
	for i := 0; i < maxDepth; i++ {
		info, err := os.Lstat(path)
		if err != nil {
			// "Not there" is a first download, and the path as given is what
			// the caller means. Anything ELSE -- EIO, EACCES, a mount going
			// away for a moment -- is an inspection that did not happen, and
			// treating it as "not a symlink" is how a rename lands on the
			// link itself: the shared target keeps the old database while
			// memory publishes the new one, and nothing ever reconciles them.
			// An error here fails the transaction; the next update retries.
			if errors.Is(err, fs.ErrNotExist) {
				return path, nil
			}
			return "", fmt.Errorf("cannot inspect %s: %w", path, err)
		}
		if info.Mode()&os.ModeSymlink == 0 {
			return path, nil
		}
		target, err := os.Readlink(path)
		if err != nil {
			return "", fmt.Errorf("cannot read the symlink at %s: %w", path, err)
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(path), target)
		}
		path = target
	}
	return "", fmt.Errorf("more than %d symlinks deep, or a loop, at %s", maxDepth, path)
}

// defaultFileMode is what a database file gets when there is no previous one
// whose mode could be kept.
const defaultFileMode os.FileMode = 0o644

// Publish writes data beside the database's path, verifies it, renames it
// into place and publishes the verified reader. See the file comment for the
// order and why it is the order.
// EnsureSeeded opens the database from disk the first time a lookup needs
// one. The disk is tried once: a lookup happens per rule match, so a missing
// file must not mean an open syscall per packet. A publish or an adopt that
// lands later still replaces whatever this did or did not find.
func (p *publisher) EnsureSeeded() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.published || p.diskAttempted {
		return nil
	}
	p.diskAttempted = true
	reader, err := p.ops.Open(p.path())
	if err != nil {
		return &LoadError{Database: p.name, Stage: "open", Err: err}
	}
	p.holder.publish(reader)
	p.published = true
	return nil
}

// Adopt seeds the reader from bytes already in memory -- upstream's
// LoadFromBytes, whose contract is that the first load wins. Under the same
// mutex as everything else, and it counts as seeded only if the bytes parse:
// they used to complete the once before being parsed, so garbage handed in
// here stranded the valid database on disk for the life of the process.
func (p *publisher) Adopt(data []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.published {
		return nil
	}
	// The same ceiling the file on disk is held to (open.go). These bytes
	// arrive from a bounded download, but "the caller already checked" is
	// how a door stops being a door.
	if err := checkDatabaseSize(p.name, int64(len(data))); err != nil {
		return &LoadError{Database: p.name, Stage: "size", Err: err}
	}
	reader, err := p.ops.FromBytes(data)
	if err != nil {
		return &LoadError{Database: p.name, Stage: "parse", Err: err}
	}
	p.holder.publish(reader)
	p.published = true
	return nil
}

// Reopen opens the database already at the publisher's path -- through the
// same Open the transaction uses, under the same mutex -- and
// publishes it. It is what first use and an explicit reload go through, and
// the mutex is the point: a reopen that ran beside Publish could open the old
// file, pause, and publish it over the new one Publish had just verified and
// renamed into place. Serialized, it either runs first (and Publish's reader
// replaces its) or after (and opens what Publish committed). A file that will
// not open or verify leaves the current reader in place and is the error.
func (p *publisher) Reopen() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	reader, err := p.ops.Open(p.path())
	if err != nil {
		return &LoadError{Database: p.name, Stage: "open", Err: err}
	}
	p.holder.publish(reader)
	p.published = true
	return nil
}

func (p *publisher) Publish(data []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(data) == 0 {
		return &LoadError{Database: p.name, Stage: "stage", Err: errors.New("no data")}
	}
	// Through a symlink, not over it -- see resolveLink.
	final, err := resolveLink(p.path())
	if err != nil {
		return &LoadError{Database: p.name, Stage: "resolve", Err: err}
	}
	dir := filepath.Dir(final)

	tmp, err := p.ops.CreateTemp(dir, filepath.Base(final)+".*.staging")
	if err != nil {
		return &LoadError{Database: p.name, Stage: "create temp file", Err: err}
	}
	tmpPath := tmp.Name()
	discard := func() { _ = tmp.Close(); _ = p.ops.Remove(tmpPath) }

	if _, err := tmp.Write(data); err != nil {
		discard()
		return &LoadError{Database: p.name, Stage: "write", Err: err}
	}
	if err := tmp.Sync(); err != nil {
		discard()
		return &LoadError{Database: p.name, Stage: "fsync", Err: err}
	}
	if err := tmp.Close(); err != nil {
		_ = p.ops.Remove(tmpPath)
		return &LoadError{Database: p.name, Stage: "close", Err: err}
	}

	// Opened once, and this is the reader that gets published. It verifies the
	// candidate AND it is the candidate: on the mapping platforms the rename
	// carries the inode this reader holds, and on Windows openDatabaseFile has
	// already read the bytes and let the file go (open_windows.go), so nothing
	// is holding the file the rename replaces.
	//
	// It used to be opened here, closed, and opened AGAIN after the rename --
	// and that second open is a fallible step after the commit. When it
	// failed, disk had moved and memory had not, and the recovery depended on
	// a later open succeeding; if that one failed too, the publisher stayed on
	// the old database for the life of the process while every hash-compare
	// said the file was up to date. There is no step after the commit that can
	// fail that way now.
	candidate, err := p.ops.Open(tmpPath)
	if err != nil {
		_ = p.ops.Remove(tmpPath)
		return &LoadError{Database: p.name, Stage: "verify", Err: err}
	}

	mode := defaultFileMode
	if info, err := p.ops.Stat(final); err == nil {
		mode = info.Mode().Perm()
	}
	if err := p.ops.Chmod(tmpPath, mode); err != nil {
		_ = candidate.Close()
		_ = p.ops.Remove(tmpPath)
		return &LoadError{Database: p.name, Stage: "chmod", Err: err}
	}

	if err := p.ops.Rename(tmpPath, final); err != nil {
		_ = candidate.Close()
		_ = p.ops.Remove(tmpPath)
		return &LoadError{Database: p.name, Stage: "rename", Err: err}
	}
	// The commit happened. A directory fsync that fails is a durability
	// warning -- the file is in place and the reader is good -- not a reason
	// to run on the old reader against the new file.
	if err := p.ops.SyncDir(dir); err != nil {
		log.Warnln("[GEO] %s: directory fsync after rename failed: %v", p.name, err)
	}
	// The type is named in the log rather than enforced. A role check here
	// would mean an allow-list of DatabaseType strings, and the databases
	// people actually feed this are many vendors' (`Meta-geoip0`,
	// `sing-geoip`, `GeoLite2-*`, `DBIP-*`, ...): the list would reject
	// valid ones, which is a worse and likelier failure than the one it
	// would catch. Upstream's own gate is the same maxminddb open and no
	// more (component/updater UpdateASN). Saying the type out loud makes a
	// misconfigured URL -- an ASN slot fed a country database -- readable
	// the first time it publishes, which is what a reader needs to fix it.
	log.Infoln("[GEO] %s: published %s", p.name, candidate.Metadata.DatabaseType)
	p.holder.publish(candidate)
	p.published = true
	return nil
}

func databaseTypeOf(reader *maxminddb.Reader) databaseType {
	if reader == nil {
		return typeMaxmind
	}
	switch reader.Metadata.DatabaseType {
	case "sing-geoip":
		return typeSing
	case "Meta-geoip0":
		return typeMetaV0
	default:
		return typeMaxmind
	}
}
