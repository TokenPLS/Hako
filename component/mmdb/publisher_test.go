package mmdb

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func newTestPublisher(t *testing.T) (*publisher, string) {
	t.Helper()
	dir := t.TempDir()
	final := filepath.Join(dir, "Country.mmdb")
	p := newPublisher("MMDB", func() string { return final })
	return p, final
}

func lookup(t *testing.T, h *readerHolder) []string {
	t.Helper()
	return IPReader{holder: h}.LookupCode(net.ParseIP("1.0.0.1"))
}

// The fixtures differ on one prefix, so one lookup says which file is live.
func TestPublishReplacesTheFileAndTheReaderTogether(t *testing.T) {
	p, final := newTestPublisher(t)
	if err := p.Publish(fixture(t, "country-a.mmdb")); err != nil {
		t.Fatal(err)
	}
	if got := lookup(t, p.holder); len(got) != 1 || got[0] != "aa" {
		t.Fatalf("after publishing A: %v", got)
	}
	if err := p.Publish(fixture(t, "country-b.mmdb")); err != nil {
		t.Fatal(err)
	}
	if got := lookup(t, p.holder); len(got) != 1 || got[0] != "bb" {
		t.Fatalf("after publishing B: %v", got)
	}
	// Disk and memory agree: the file on the final path is the one being read.
	onDisk, err := maxminddb.Open(final)
	if err != nil {
		t.Fatal(err)
	}
	defer onDisk.Close()
	var rec struct {
		Country struct {
			ISO string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	_ = onDisk.Lookup(net.ParseIP("1.0.0.1"), &rec)
	if rec.Country.ISO != "BB" {
		t.Fatalf("the file on disk answers %q, the reader answers bb", rec.Country.ISO)
	}
	// Nothing staged is left behind.
	entries, _ := os.ReadDir(filepath.Dir(final))
	for _, e := range entries {
		if strings.Contains(e.Name(), ".staging") {
			t.Fatalf("a staging file survived: %s", e.Name())
		}
	}
}

// The old reader is closed by whoever releases its last reference, never by
// publish: a lookup in flight across a publish finishes on the reader it
// started with, and publish does not wait for it.
func TestAnInFlightLookupKeepsTheOldReaderOpenUntilItLetsGo(t *testing.T) {
	p, _ := newTestPublisher(t)
	if err := p.Publish(fixture(t, "country-a.mmdb")); err != nil {
		t.Fatal(err)
	}
	closed := 0
	old := p.holder.acquire() // a lookup in flight
	old.close = func() { closed++ }
	if err := p.Publish(fixture(t, "country-b.mmdb")); err != nil {
		t.Fatal(err)
	}
	if closed != 0 {
		t.Fatal("publish closed a reader that a lookup still holds")
	}
	if !old.retired {
		t.Fatal("the old snapshot was not retired by the publish")
	}
	if got := lookupCode(old.reader, old.databaseType, net.ParseIP("1.0.0.1")); len(got) != 1 || got[0] != "aa" {
		t.Fatalf("the in-flight lookup no longer reads its own reader: %v", got)
	}
	if got := lookup(t, p.holder); len(got) != 1 || got[0] != "bb" {
		t.Fatalf("new lookups do not see the new reader: %v", got)
	}
	p.holder.release(old)
	if closed != 1 {
		t.Fatalf("the last release must close the retired reader once, closed %d times", closed)
	}
	p.holder.release(p.holder.acquire()) // a reader with no retired marker is not closed by releases
	if closed != 1 {
		t.Fatal("a live reader was closed by a release")
	}
}

// A snapshot retired with no holders is closed by the publish itself, once.
func TestAnUnheldOldReaderIsClosedByThePublish(t *testing.T) {
	p, _ := newTestPublisher(t)
	if err := p.Publish(fixture(t, "country-a.mmdb")); err != nil {
		t.Fatal(err)
	}
	closed := 0
	p.holder.current.close = func() { closed++ }
	if err := p.Publish(fixture(t, "country-b.mmdb")); err != nil {
		t.Fatal(err)
	}
	if closed != 1 {
		t.Fatalf("closed %d times, want 1", closed)
	}
}

// failingOps is the real file system except for one stage made to fail.
type failingOps struct {
	osFileOps
	failAt string
	err    error
	order  []string
	mu     sync.Mutex
}

type failingTemp struct {
	tempFile
	ops *failingOps
}

func (f *failingOps) note(stage string) error {
	f.mu.Lock()
	f.order = append(f.order, stage)
	f.mu.Unlock()
	if stage == f.failAt {
		return f.err
	}
	return nil
}

func (f *failingOps) CreateTemp(dir, pattern string) (tempFile, error) {
	if err := f.note("create"); err != nil {
		return nil, err
	}
	tmp, err := f.osFileOps.CreateTemp(dir, pattern)
	if err != nil {
		return nil, err
	}
	return &failingTemp{tempFile: tmp, ops: f}, nil
}
func (t *failingTemp) Write(p []byte) (int, error) {
	if err := t.ops.note("write"); err != nil {
		return 0, err
	}
	return t.tempFile.Write(p)
}
func (t *failingTemp) Sync() error {
	if err := t.ops.note("fsync"); err != nil {
		return err
	}
	return t.tempFile.Sync()
}
func (t *failingTemp) Close() error {
	if err := t.ops.note("close"); err != nil {
		return err
	}
	return t.tempFile.Close()
}
func (f *failingOps) Open(path string) (*maxminddb.Reader, error) {
	if err := f.note("verify"); err != nil {
		return nil, err
	}
	return f.osFileOps.Open(path)
}
func (f *failingOps) Chmod(path string, mode os.FileMode) error {
	if err := f.note("chmod"); err != nil {
		return err
	}
	return f.osFileOps.Chmod(path, mode)
}
func (f *failingOps) Rename(oldPath, newPath string) error {
	if err := f.note("rename"); err != nil {
		return err
	}
	return f.osFileOps.Rename(oldPath, newPath)
}
func (f *failingOps) SyncDir(dir string) error {
	if err := f.note("syncdir"); err != nil {
		return err
	}
	return f.osFileOps.SyncDir(dir)
}

func stagingFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, _ := os.ReadDir(dir)
	var out []string
	for _, e := range entries {
		if strings.Contains(e.Name(), ".staging") {
			out = append(out, e.Name())
		}
	}
	return out
}

// Every stage before the rename fails closed: the error names the stage, the
// last-known-good file and reader are untouched, and the staging file is gone.
func TestEveryStageBeforeTheRenameFailsClosed(t *testing.T) {
	for _, stage := range []string{"create", "write", "fsync", "close", "verify", "chmod", "rename"} {
		t.Run(stage, func(t *testing.T) {
			p, final := newTestPublisher(t)
			if err := p.Publish(fixture(t, "country-a.mmdb")); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(final)
			injected := errors.New("injected " + stage + " failure")
			p.ops = &failingOps{failAt: stage, err: injected}

			err := p.Publish(fixture(t, "country-b.mmdb"))
			var loadErr *LoadError
			if !errors.As(err, &loadErr) || !errors.Is(err, injected) {
				t.Fatalf("want a LoadError wrapping the injected error, got %v", err)
			}
			if !strings.Contains(loadErr.Stage, stage) && !(stage == "create" && loadErr.Stage == "create temp file") {
				t.Fatalf("the error names stage %q, want %q", loadErr.Stage, stage)
			}
			if got := lookup(t, p.holder); len(got) != 1 || got[0] != "aa" {
				t.Fatalf("the reader changed on a failed publish: %v", got)
			}
			after, _ := os.ReadFile(final)
			if string(after) != string(before) {
				t.Fatal("the last-known-good file changed on a failed publish")
			}
			if left := stagingFiles(t, filepath.Dir(final)); len(left) != 0 {
				t.Fatalf("staging files left behind: %v", left)
			}
		})
	}
}

// The check opens the CANDIDATE, not the final path, and it happens before
// the rename -- so bytes that are not a database never reach the final path
// at all. Bytes that are not a database make the point without a fake.
func TestAFileThatDoesNotOpenNeverReachesTheFinalPath(t *testing.T) {
	p, final := newTestPublisher(t)
	if err := p.Publish(fixture(t, "country-a.mmdb")); err != nil {
		t.Fatal(err)
	}
	ops := &failingOps{}
	p.ops = ops
	err := p.Publish([]byte("this is not a database"))
	var loadErr *LoadError
	if !errors.As(err, &loadErr) || loadErr.Stage != "verify" {
		t.Fatalf("want a verify LoadError, got %v", err)
	}
	if got := lookup(t, p.holder); len(got) != 1 || got[0] != "aa" {
		t.Fatalf("the reader changed: %v", got)
	}
	if _, err := maxminddb.Open(final); err != nil {
		t.Fatalf("the last-known-good file on disk no longer opens: %v", err)
	}
	joined := strings.Join(ops.order, ",")
	if !strings.Contains(joined, "verify") || strings.Contains(joined, "rename") {
		t.Fatalf("verify must run and the rename must not: %s", joined)
	}
}

// The directory fsync is durability, not correctness: its failure is a
// warning, the file is in place and the verified reader is published.
func TestADirectoryFsyncFailureIsAWarningNotARollback(t *testing.T) {
	p, _ := newTestPublisher(t)
	if err := p.Publish(fixture(t, "country-a.mmdb")); err != nil {
		t.Fatal(err)
	}
	p.ops = &failingOps{failAt: "syncdir", err: errors.New("injected syncdir failure")}
	if err := p.Publish(fixture(t, "country-b.mmdb")); err != nil {
		t.Fatalf("a directory fsync failure must not fail the publish: %v", err)
	}
	if got := lookup(t, p.holder); len(got) != 1 || got[0] != "bb" {
		t.Fatalf("the verified reader was not published: %v", got)
	}
}

// The stages run in the order the transaction needs: open-and-verify the
// candidate BEFORE the rename, the rename before the directory fsync, and
// NOTHING FALLIBLE AFTER THE RENAME.
//
// That last part is what the absence of a second "verify" says. The candidate
// is opened once and that reader is what gets published: after the rename --
// the commit -- there is no step left that can fail and leave disk ahead of
// memory. There used to be one, and the split it made repaired itself only if
// a later open succeeded.
func TestTheStagesRunInTheOrderThatCannotLoseTheLastKnownGood(t *testing.T) {
	p, _ := newTestPublisher(t)
	ops := &failingOps{}
	p.ops = ops
	if err := p.Publish(fixture(t, "country-a.mmdb")); err != nil {
		t.Fatal(err)
	}
	want := "create,write,fsync,close,verify,chmod,rename,syncdir"
	if got := strings.Join(ops.order, ","); got != want {
		t.Fatalf("stage order %s, want %s", got, want)
	}
}

// The mode of the previous file is kept; with no previous file the default
// applies.
func TestTheFileModeIsKeptAcrossAPublish(t *testing.T) {
	p, final := newTestPublisher(t)
	if err := p.Publish(fixture(t, "country-a.mmdb")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(final, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := p.Publish(fixture(t, "country-b.mmdb")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(final)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o, want the previous file's 0600", info.Mode().Perm())
	}
}

// blockingOps parks a publish inside the transaction so the test can look at
// the lock while it is in there.
type blockingOps struct {
	osFileOps
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *blockingOps) CreateTemp(dir, pattern string) (tempFile, error) {
	b.once.Do(func() { close(b.entered) })
	<-b.release
	return b.osFileOps.CreateTemp(dir, pattern)
}

// The whole transaction runs under the publisher's mutex: while one publish is
// parked inside it the lock cannot be taken, and when it returns the lock is
// free again. Deterministic -- the lock is inspected, not a race timed --
// and it is what keeps rename(A) -> rename(B) -> publish(B) -> publish(A)
// from leaving B on disk and A in memory.
func TestTheTransactionHoldsTheMutexEndToEnd(t *testing.T) {
	p, _ := newTestPublisher(t)
	ops := &blockingOps{entered: make(chan struct{}), release: make(chan struct{})}
	p.ops = ops
	done := make(chan error, 1)
	go func() { done <- p.Publish(fixture(t, "country-a.mmdb")) }()
	<-ops.entered
	if p.mu.TryLock() {
		p.mu.Unlock()
		t.Fatal("the publisher's mutex is free while a publish is inside the transaction")
	}
	close(ops.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !p.mu.TryLock() {
		t.Fatal("the mutex was not released after the publish returned")
	}
	p.mu.Unlock()
	p.ops = osFileOps{}
	if err := p.Publish(fixture(t, "country-b.mmdb")); err != nil {
		t.Fatal(err)
	}
	if got := lookup(t, p.holder); len(got) != 1 || got[0] != "bb" {
		t.Fatalf("the later publish must win: %v", got)
	}
}

// Empty bytes are refused before anything is touched.
func TestEmptyDataIsRefused(t *testing.T) {
	p, _ := newTestPublisher(t)
	if err := p.Publish(nil); err == nil {
		t.Fatal("empty data must be refused")
	}
}

// The ASN side goes through the same machinery.
func TestASNPublishAnswersFromTheNewFile(t *testing.T) {
	dir := t.TempDir()
	final := filepath.Join(dir, "ASN.mmdb")
	p := newPublisher("ASN", func() string { return final })
	if err := p.Publish(fixture(t, "asn-a.mmdb")); err != nil {
		t.Fatal(err)
	}
	if number, org := (ASNReader{holder: p.holder}).LookupASN(net.ParseIP("1.0.0.1")); number != "64500" || org != "Fixture A" {
		t.Fatalf("A: %q %q", number, org)
	}
	if err := p.Publish(fixture(t, "asn-b.mmdb")); err != nil {
		t.Fatal(err)
	}
	if number, org := (ASNReader{holder: p.holder}).LookupASN(net.ParseIP("1.0.0.1")); number != "64501" || org != "Fixture B" {
		t.Fatalf("B: %q %q", number, org)
	}
}

// blockingOpenOps parks Open: it is how a test holds a Reopen inside the
// publisher while it inspects the mutex and runs a Publish beside it.
type blockingOpenOps struct {
	osFileOps
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

// Only the first Open parks -- the one the reopen under test makes; an update
// that runs beside it opens its candidate without waiting.
func (b *blockingOpenOps) Open(path string) (*maxminddb.Reader, error) {
	first := false
	b.once.Do(func() { first = true; close(b.entered) })
	if first {
		<-b.release
	}
	return b.osFileOps.Open(path)
}

type failingOpenOps struct{ osFileOps }

func (failingOpenOps) Open(string) (*maxminddb.Reader, error) {
	return nil, errors.New("not a database")
}

// Reopen runs under the publisher's mutex like Publish does. Proven the same
// way: while a reopen is parked inside Open the lock cannot be taken; when it
// returns the lock is free. Without this, ReloadIP beside an update could open
// the old file, pause, and publish it over the reader the update had verified
// and renamed into place.
func TestReopenHoldsTheMutex(t *testing.T) {
	p, final := newTestPublisher(t)
	if err := os.WriteFile(final, fixture(t, "country-a.mmdb"), 0o644); err != nil {
		t.Fatal(err)
	}
	ops := &blockingOpenOps{entered: make(chan struct{}), release: make(chan struct{})}
	p.ops = ops
	done := make(chan error, 1)
	go func() { done <- p.Reopen() }()
	<-ops.entered
	if p.mu.TryLock() {
		p.mu.Unlock()
		t.Fatal("the publisher's mutex is free while a reopen is inside Open")
	}
	close(ops.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !p.mu.TryLock() {
		t.Fatal("the publisher's mutex is still held after Reopen returned")
	}
	p.mu.Unlock()
	if got := lookup(t, p.holder); len(got) != 1 || got[0] != "aa" {
		t.Fatalf("reopen did not publish the file on disk: %v", got)
	}
}

// The interleaving itself: a reopen has opened the OLD file and is parked
// before publishing; an update publishes the NEW file meanwhile. Serialized,
// the update cannot start until the reopen is done, so the new database is
// what ends up in memory. (Unserialized, the update would finish during the
// pause and the reopen would then publish the old reader over it.)
func TestAReopenParkedBeforePublishCannotShadowAnUpdate(t *testing.T) {
	p, final := newTestPublisher(t)
	if err := os.WriteFile(final, fixture(t, "country-a.mmdb"), 0o644); err != nil {
		t.Fatal(err)
	}
	ops := &blockingOpenOps{entered: make(chan struct{}), release: make(chan struct{})}
	p.ops = ops
	reopened := make(chan error, 1)
	go func() { reopened <- p.Reopen() }()
	<-ops.entered // the reopen has the old file open and is parked

	published := make(chan error, 1)
	go func() { published <- p.Publish(fixture(t, "country-b.mmdb")) }()
	// Give the update a real chance to have raced ahead if the mutex were
	// missing, then let the reopen finish.
	select {
	case err := <-published:
		t.Fatalf("the update completed while a reopen was inside the transaction: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(ops.release)
	if err := <-reopened; err != nil {
		t.Fatal(err)
	}
	if err := <-published; err != nil {
		t.Fatal(err)
	}
	if got := lookup(t, p.holder); len(got) != 1 || got[0] != "bb" {
		t.Fatalf("the reader in memory is not the update that ran last: %v", got)
	}
}

// A file that does not open is not published: the current reader stays, and
// the failure is the error.
func TestReopenKeepsTheCurrentReaderWhenTheFileDoesNotOpen(t *testing.T) {
	p, _ := newTestPublisher(t)
	if err := p.Publish(fixture(t, "country-a.mmdb")); err != nil {
		t.Fatal(err)
	}
	// (The file is not rewritten in place here on purpose: the published
	// reader memory-maps it, and overwriting a mapped file changes what the
	// old reader answers -- the very reason Publish renames a new inode in.)
	p.ops = failingOpenOps{}
	err := p.Reopen()
	var le *LoadError
	if !errors.As(err, &le) || le.Stage != "open" {
		t.Fatalf("want a LoadError at the open stage, got %v", err)
	}
	if got := lookup(t, p.holder); len(got) != 1 || got[0] != "aa" {
		t.Fatalf("a reopen that failed to open replaced the reader: %v", got)
	}
}

// The fixtures are generated with a pinned build epoch (testdata/gen), so
// regenerating them yields the same bytes; this pins the value the reader
// sees, which is the half of that claim a test can check without the
// generator.
func TestFixturesCarryThePinnedBuildEpoch(t *testing.T) {
	const pinnedBuildEpoch = 1_700_000_000
	for _, name := range []string{"country-a.mmdb", "country-b.mmdb", "asn-a.mmdb", "asn-b.mmdb", "metav0-no-description.mmdb", "metav0-mixed-record.mmdb", "ipinfo-short-asn.mmdb"} {
		reader, err := maxminddb.FromBytes(fixture(t, name))
		if err != nil {
			t.Fatal(err)
		}
		if reader.Metadata.BuildEpoch != pinnedBuildEpoch {
			t.Fatalf("%s: build epoch %d, want the pinned %d -- regenerate with testdata/gen", name, reader.Metadata.BuildEpoch, pinnedBuildEpoch)
		}
		_ = reader.Close()
	}
}

// The database this product ships by default is mihomo's `Meta-geoip0`, and it
// carries no description -- so Reader.Verify() rejects it ("description -
// Expected: non-empty slice Actual: map[]"). A transaction gated on Verify
// therefore refused the real geoip.metadb and every update of it, while the
// fixtures (written WITH a description) passed: the fixture had been shaped to
// fit the code instead of the artifact. This pins the artifact's shape.
func TestTheTransactionAcceptsADatabaseWithNoDescription(t *testing.T) {
	data := fixture(t, "metav0-no-description.mmdb")

	// The shape is the point: this is what makes the real database fail Verify.
	probe, err := maxminddb.FromBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(probe.Metadata.Description) != 0 {
		t.Fatalf("the fixture no longer has the shape it is here for: description=%v", probe.Metadata.Description)
	}
	if probe.Verify() == nil {
		t.Fatal("the fixture passes Reader.Verify(), so it cannot pin the case that Verify rejects")
	}
	_ = probe.Close()

	p, final := newTestPublisher(t)
	if err := p.Publish(data); err != nil {
		t.Fatalf("the transaction refused a database with no description -- this is the real geoip.metadb: %v", err)
	}
	// Read as a Meta-geoip0 database, which is a list of codes -- the
	// database type decides the record shape, and getting that wrong is the
	// other half of "the fixture must be what the kernel really reads".
	if got := lookup(t, p.holder); len(got) != 2 || got[0] != "cc" || got[1] != "dd" {
		t.Fatalf("the published reader does not answer from the new database: %v", got)
	}
	if _, err := os.Stat(final); err != nil {
		t.Fatalf("the database was not committed to the final path: %v", err)
	}

	// And the other way in: first use / reload opens the same file.
	q := newPublisher("MMDB", func() string { return final })
	if err := q.Reopen(); err != nil {
		t.Fatalf("reopening a committed database with no description failed: %v", err)
	}
	if got := lookup(t, q.holder); len(got) != 2 || got[0] != "cc" {
		t.Fatalf("the reopened reader does not answer: %v", got)
	}
}

// A first update that fails must not strand the database already on disk.
// PublishIP used to complete ipOnce before the transaction ran, so an update
// that arrived before anything had looked an address up -- a refresh at
// startup -- marked "seeded" and then failed on its own bytes; every later
// IPInstance took the no-op once and the valid file was never opened, so
// GEOIP matched nothing for the life of the process.
func TestAFailedFirstUpdateLeavesTheDatabaseOnDiskReachable(t *testing.T) {
	dir := t.TempDir()
	final := filepath.Join(dir, "Country.mmdb")
	if err := os.WriteFile(final, fixture(t, "country-a.mmdb"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A fresh process: nothing has been looked up, nothing seeded.
	savedPublisher := ipPublisher
	defer func() { ipPublisher = savedPublisher }()
	ipPublisher = newPublisher("MMDB", func() string { return final })

	if err := PublishIP([]byte("not a database, but not empty either")); err == nil {
		t.Fatal("the transaction accepted bytes that are not a database")
	}
	if got := IPInstance().LookupCode(net.ParseIP("1.0.0.1")); len(got) != 1 || got[0] != "aa" {
		t.Fatalf("a failed update stranded the valid database on disk: lookup answered %v, want [aa]", got)
	}
	// And a later good update still lands.
	if err := PublishIP(fixture(t, "country-b.mmdb")); err != nil {
		t.Fatal(err)
	}
	if got := IPInstance().LookupCode(net.ParseIP("1.0.0.1")); len(got) != 1 || got[0] != "bb" {
		t.Fatalf("the good update did not take: %v", got)
	}
}

// LoadFromBytes seeds from memory and the first load wins -- but bytes that do
// not parse are not a load. They used to complete the same sync.Once the disk
// path used, so garbage handed to LoadFromBytes stranded the valid database on
// disk for the life of the process, exactly like a failed first update did.
func TestLoadFromBytesThatDoesNotParseSeedsNothing(t *testing.T) {
	dir := t.TempDir()
	final := filepath.Join(dir, "Country.mmdb")
	if err := os.WriteFile(final, fixture(t, "country-a.mmdb"), 0o644); err != nil {
		t.Fatal(err)
	}
	saved := ipPublisher
	defer func() { ipPublisher = saved }()
	ipPublisher = newPublisher("MMDB", func() string { return final })

	LoadFromBytes([]byte("not a database"))
	if got := IPInstance().LookupCode(net.ParseIP("1.0.0.1")); len(got) != 1 || got[0] != "aa" {
		t.Fatalf("bytes that do not parse stranded the database on disk: %v, want [aa]", got)
	}
}

// And a load that DOES parse wins over the file on disk, and stays won.
func TestLoadFromBytesWinsAndTheFirstOneWins(t *testing.T) {
	dir := t.TempDir()
	final := filepath.Join(dir, "Country.mmdb")
	if err := os.WriteFile(final, fixture(t, "country-a.mmdb"), 0o644); err != nil {
		t.Fatal(err)
	}
	saved := ipPublisher
	defer func() { ipPublisher = saved }()
	ipPublisher = newPublisher("MMDB", func() string { return final })

	LoadFromBytes(fixture(t, "country-b.mmdb"))
	if got := IPInstance().LookupCode(net.ParseIP("1.0.0.1")); len(got) != 1 || got[0] != "bb" {
		t.Fatalf("the in-memory load did not win: %v", got)
	}
	LoadFromBytes(fixture(t, "country-a.mmdb"))
	if got := IPInstance().LookupCode(net.ParseIP("1.0.0.1")); len(got) != 1 || got[0] != "bb" {
		t.Fatalf("a second load overwrote the first: %v", got)
	}
	// An update still replaces it -- that is not a "load".
	if err := PublishIP(fixture(t, "country-a.mmdb")); err != nil {
		t.Fatal(err)
	}
	if got := IPInstance().LookupCode(net.ParseIP("1.0.0.1")); len(got) != 1 || got[0] != "aa" {
		t.Fatalf("an update after an in-memory load did not take: %v", got)
	}
}

// A disk open that fails is attempted once, not once per lookup: a lookup
// happens per rule match, so a missing file must not mean a syscall per packet.
func TestAMissingDatabaseIsOpenedOnceNotPerLookup(t *testing.T) {
	p, _ := newTestPublisher(t)
	counter := &countingOps{}
	p.ops = counter
	for i := 0; i < 5; i++ {
		_ = p.EnsureSeeded()
	}
	if counter.opens != 1 {
		t.Fatalf("the disk was opened %d times, want 1", counter.opens)
	}
}

type countingOps struct {
	osFileOps
	opens int
}

func (c *countingOps) Open(path string) (*maxminddb.Reader, error) {
	c.opens++
	return c.osFileOps.Open(path)
}

// A database path may be a symlink into a shared directory. The old code
// wrote with os.WriteFile, which follows one; a rename onto the link would
// replace it with a regular file and detach the arrangement without saying
// so. The transaction lands on the real file and leaves the link a link.
func TestPublishingThroughASymlinkKeepsTheLink(t *testing.T) {
	root := t.TempDir()
	shared := filepath.Join(root, "shared")
	if err := os.MkdirAll(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(shared, "Country.mmdb")
	if err := os.WriteFile(real, fixture(t, "country-a.mmdb"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "Country.mmdb")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	p := newPublisher("MMDB", func() string { return link })
	if err := p.Publish(fixture(t, "country-b.mmdb")); err != nil {
		t.Fatal(err)
	}

	info, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("the transaction replaced the symlink with a regular file")
	}
	got, err := os.ReadFile(real)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(fixture(t, "country-b.mmdb")) {
		t.Fatal("the update did not land on the file the link points at")
	}
	if got := lookup(t, p.holder); len(got) != 1 || got[0] != "bb" {
		t.Fatalf("the published reader is not the new database: %v", got)
	}
	// Nothing left beside either end of the link.
	for _, dir := range []string{root, shared} {
		names, _ := os.ReadDir(dir)
		for _, n := range names {
			if strings.Contains(n.Name(), ".staging") {
				t.Fatalf("a staging file was left in %s: %s", dir, n.Name())
			}
		}
	}
}

// A dangling symlink is what a first download looks like: the link is there,
// its target is not yet. EvalSymlinks fails on one, and falling back to the
// link's own path renamed over the link -- so the arrangement was lost in
// exactly the case it was set up for.
func TestPublishingThroughADanglingSymlinkKeepsTheLink(t *testing.T) {
	root := t.TempDir()
	shared := filepath.Join(root, "shared")
	if err := os.MkdirAll(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(shared, "Country.mmdb") // nothing here yet
	link := filepath.Join(root, "Country.mmdb")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	p := newPublisher("MMDB", func() string { return link })
	if err := p.Publish(fixture(t, "country-a.mmdb")); err != nil {
		t.Fatal(err)
	}

	info, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("the transaction replaced a dangling symlink with a regular file")
	}
	if _, err := os.Stat(real); err != nil {
		t.Fatalf("the database did not land on the link's target: %v", err)
	}
	if got := lookup(t, p.holder); len(got) != 1 || got[0] != "aa" {
		t.Fatalf("the published reader is not the new database: %v", got)
	}
}

// A relative link, and a chain of links, resolve the same way.
func TestResolveLinkFollowsRelativeAndChainedLinks(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real.mmdb")
	if err := os.WriteFile(real, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(root, "first.mmdb")
	if err := os.Symlink("real.mmdb", first); err != nil { // relative
		t.Fatal(err)
	}
	second := filepath.Join(root, "second.mmdb")
	if err := os.Symlink(first, second); err != nil { // chained
		t.Fatal(err)
	}
	for _, path := range []string{first, second} {
		got, err := resolveLink(path)
		if err != nil || got != real {
			t.Fatalf("resolveLink(%q) = %q, %v; want %q", path, got, err, real)
		}
	}
	plain := filepath.Join(root, "plain.mmdb")
	if got, err := resolveLink(plain); err != nil || got != plain {
		t.Fatalf("a path that is not a link must come back unchanged: %q, %v", got, err)
	}
}

// Past the depth bound, and around a loop, resolution FAILS rather than
// handing back something that is still a link: renaming over that path is
// exactly what the resolution exists to prevent.
func TestResolveLinkFailsClosedOnADeepChainAndALoop(t *testing.T) {
	root := t.TempDir()
	// A chain longer than the bound.
	deepest := filepath.Join(root, "real.mmdb")
	if err := os.WriteFile(deepest, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	previous := deepest
	for i := 0; i < 9; i++ {
		link := filepath.Join(root, "link"+strconv.Itoa(i)+".mmdb")
		if err := os.Symlink(previous, link); err != nil {
			t.Fatal(err)
		}
		previous = link
	}
	if got, err := resolveLink(previous); err == nil {
		t.Fatalf("a chain past the bound resolved to %q instead of failing", got)
	}
	// A loop.
	a, b := filepath.Join(root, "a.mmdb"), filepath.Join(root, "b.mmdb")
	if err := os.Symlink(b, a); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(a, b); err != nil {
		t.Fatal(err)
	}
	if got, err := resolveLink(a); err == nil {
		t.Fatalf("a loop resolved to %q instead of failing", got)
	}
	// And a publish through such a path is refused, leaving the reader alone.
	p := newPublisher("MMDB", func() string { return a })
	if err := p.Publish(fixture(t, "country-a.mmdb")); err == nil {
		t.Fatal("a publish through a symlink loop was accepted")
	}
}

// A database can be structurally valid -- it opens, so the transaction
// publishes it -- and still carry a record the lookup code did not expect.
// An unchecked type assertion or a slice past the end is a panic, and inside
// the packet tunnel that is the process dying with no crash report, which
// already ruled out for geo data. A record like this is no match.
func TestARecordTheLookupDidNotExpectIsNoMatchNotAPanic(t *testing.T) {
	t.Run("a Meta-geoip0 list with a non-string element", func(t *testing.T) {
		p, _ := newTestPublisher(t)
		if err := p.Publish(fixture(t, "metav0-mixed-record.mmdb")); err != nil {
			t.Fatal(err)
		}
		got := IPReader{holder: p.holder}.LookupCode(net.ParseIP("1.0.0.1"))
		if len(got) != 1 || got[0] != "us" {
			t.Fatalf("the strings in a mixed record should still answer: %v", got)
		}
	})
	t.Run("an ipinfo record whose asn is too short for its prefix", func(t *testing.T) {
		p, _ := newTestPublisher(t)
		if err := p.Publish(fixture(t, "ipinfo-short-asn.mmdb")); err != nil {
			t.Fatal(err)
		}
		asn, name := ASNReader{holder: p.holder}.LookupASN(net.ParseIP("1.0.0.1"))
		if asn != "" || name != "Fixture" {
			t.Fatalf("a short asn should answer empty, not panic: %q, %q", asn, name)
		}
	})
}

// Nothing after the commit can fail, so memory cannot be left behind disk.
//
// The transaction used to open the file again after the rename, and when that
// open failed -- EMFILE is enough -- disk was the new database and memory was
// still the old one. The repair depended on a LATER open succeeding; if that
// one failed too, the publisher stayed on the old database for the life of the
// process while every hash-compare told the updater the file was up to date.
// Here every open after the candidate's fails, and the publish still has to
// land: the reader it publishes is the one it already verified.
func TestNothingAfterTheCommitCanStrandMemoryBehindDisk(t *testing.T) {
	p, final := newTestPublisher(t)
	if err := p.Publish(fixture(t, "country-a.mmdb")); err != nil {
		t.Fatal(err)
	}
	if got := lookup(t, p.holder); len(got) != 1 || got[0] != "aa" {
		t.Fatalf("setup: %v", got)
	}

	ops := &failingAfterFirstOpenOps{}
	p.ops = ops
	if err := p.Publish(fixture(t, "country-b.mmdb")); err != nil {
		t.Fatalf("a publish must not depend on an open after the rename: %v", err)
	}
	if data, err := os.ReadFile(final); err != nil || string(data) != string(fixture(t, "country-b.mmdb")) {
		t.Fatalf("the commit did not happen: %v", err)
	}
	if got := lookup(t, p.holder); len(got) != 1 || got[0] != "bb" {
		t.Fatalf("memory did not follow disk: %v", got)
	}
	if ops.opens != 1 {
		t.Fatalf("the transaction opened the database %d times; the candidate is the published reader, so it opens once", ops.opens)
	}
}

// failingAfterFirstOpenOps lets the candidate's open through and fails every
// open after it.
type failingAfterFirstOpenOps struct {
	osFileOps
	opens int
}

func (f *failingAfterFirstOpenOps) Open(path string) (*maxminddb.Reader, error) {
	f.opens++
	if f.opens >= 2 {
		return nil, errors.New("injected open failure after the candidate")
	}
	return f.osFileOps.Open(path)
}

// Replacement works with the current reader still live and still answering.
//
// This is the property Windows costs the most: a reader that MAPS the file
// stops the rename there, so on that platform the database is read into
// memory instead (open_windows.go). The test is the same on every platform --
// publish A, hold a lookup-capable reader on it, publish B, and both the new
// answer and the old reader have to work.
func TestAReplacementLandsWhileTheCurrentReaderIsStillLive(t *testing.T) {
	p, _ := newTestPublisher(t)
	if err := p.Publish(fixture(t, "country-a.mmdb")); err != nil {
		t.Fatal(err)
	}
	// A reader held across the replacement, the way a lookup in flight holds one.
	live := p.holder.acquire()
	if live == nil {
		t.Fatal("no snapshot after the first publish")
	}
	defer p.holder.release(live)

	if err := p.Publish(fixture(t, "country-b.mmdb")); err != nil {
		t.Fatalf("a replacement failed while a reader was live: %v", err)
	}
	if got := lookup(t, p.holder); len(got) != 1 || got[0] != "bb" {
		t.Fatalf("the new database is not what answers now: %v", got)
	}
	// And the one held across it still answers from the database it opened.
	if got := lookupCode(live.reader, live.databaseType, net.ParseIP("1.0.0.1")); len(got) != 1 || got[0] != "aa" {
		t.Fatalf("the reader held across the replacement stopped answering: %v", got)
	}
	// A third replacement, to catch a platform that only fails after the first.
	if err := p.Publish(fixture(t, "country-a.mmdb")); err != nil {
		t.Fatalf("a later replacement failed: %v", err)
	}
	if got := lookup(t, p.holder); len(got) != 1 || got[0] != "aa" {
		t.Fatalf("the third database is not what answers: %v", got)
	}
}

// A database larger than the ceiling is not opened at all.
//
// On Windows that read is heap, and a replacement holds the outgoing copy and
// the incoming one at once (open_windows.go); mapping elsewhere is cheaper but
// still spends address space and a metadata walk. The updater bounds the
// download that produces these files, and this is the same bound from the
// other side: a file already on disk, however it got there.
func TestADatabaseLargerThanTheCeilingIsNotOpened(t *testing.T) {
	dir := t.TempDir()

	over := filepath.Join(dir, "over.mmdb")
	f, err := os.Create(over)
	if err != nil {
		t.Fatal(err)
	}
	// Sparse: the test cares about the size the file reports, not about
	// spending sixty-four megabytes of disk to say it.
	if err := f.Truncate(MaxDatabaseBytes + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()

	reader, err := openDatabaseFile(over)
	if err == nil {
		reader.Close()
		t.Fatal("a file past the ceiling must not open")
	}
	if !strings.Contains(err.Error(), "larger than the") {
		t.Fatalf("the refusal must name the ceiling, got %v", err)
	}

	// The other direction: a file AT the ceiling is not refused for its
	// size. It is not a database either, so it fails -- on the parse, which
	// is a different sentence. Without this the test would pass just as
	// happily if the ceiling were zero.
	at := filepath.Join(dir, "at.mmdb")
	g, err := os.Create(at)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Truncate(MaxDatabaseBytes); err != nil {
		t.Fatal(err)
	}
	g.Close()

	reader, err = openDatabaseFile(at)
	if err == nil {
		reader.Close()
		t.Fatal("a file of zeros is not a database")
	}
	if strings.Contains(err.Error(), "larger than the") {
		t.Fatalf("a file at the ceiling must not be refused for its size, got %v", err)
	}
}

// writeOversizedButValidDatabase writes a database that is genuinely valid --
// maxminddb opens it and answers lookups from it -- and one byte past the
// ceiling.
//
// A file of zeros would not do: it is refused by the size check and by the
// parse alike, so it cannot tell the two apart. This one is a real database
// with a hole punched in the middle: the copy at the front holds the search
// tree and the data section at the offsets the metadata names, and the copy at
// the end is where the metadata marker is found. It costs the size it reports
// and about two kilobytes of disk.
func writeOversizedButValidDatabase(t *testing.T, path string) {
	t.Helper()
	source, err := os.ReadFile(filepath.Join("testdata", "country-a.mmdb"))
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write(source); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(MaxDatabaseBytes+1-int64(len(source)), io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(source); err != nil {
		t.Fatal(err)
	}
}

// Verify answers exactly what the runtime open answers, for every shape.
//
// These are two doors onto one file -- initialisation asks Verify, the first
// lookup goes through openDatabaseFile -- and when they disagreed the result
// was silent: startup reported a good database, every GEOIP or IP-ASN rule
// then matched nothing, and nothing was logged because neither side thought
// anything had gone wrong. The oversized-but-valid case is the one that can
// see the disagreement; the others are here so this cannot pass by refusing
// everything.
func TestVerifyAnswersWhatTheRuntimeOpenAnswers(t *testing.T) {
	dir := t.TempDir()

	valid := filepath.Join(dir, "valid.mmdb")
	source, err := os.ReadFile(filepath.Join("testdata", "country-a.mmdb"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(valid, source, 0o644); err != nil {
		t.Fatal(err)
	}

	garbage := filepath.Join(dir, "garbage.mmdb")
	if err := os.WriteFile(garbage, []byte("not a database"), 0o644); err != nil {
		t.Fatal(err)
	}

	empty := filepath.Join(dir, "empty.mmdb")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	oversized := filepath.Join(dir, "oversized.mmdb")
	writeOversizedButValidDatabase(t, oversized)

	for _, c := range []struct {
		path string
		want bool
	}{
		{valid, true},
		{garbage, false},
		{empty, false},
		{oversized, false},
		{filepath.Join(dir, "absent.mmdb"), false},
	} {
		reader, err := openDatabaseFile(c.path)
		if err == nil {
			reader.Close()
		}
		runtimeOpens := err == nil
		verified := Verify(c.path)
		if verified != runtimeOpens {
			t.Fatalf("%s: Verify says %v, the runtime open says %v -- initialisation and the first lookup must agree",
				filepath.Base(c.path), verified, runtimeOpens)
		}
		if verified != c.want {
			t.Fatalf("%s: both doors say %v, want %v", filepath.Base(c.path), verified, c.want)
		}
	}
}

// Bytes are held to the same ceiling as a file.
func TestAdoptRefusesABufferPastTheCeiling(t *testing.T) {
	p := newPublisher("MMDB", func() string { return filepath.Join(t.TempDir(), "Country.mmdb") })
	if err := p.Adopt(make([]byte, MaxDatabaseBytes+1)); err == nil {
		t.Fatal("a buffer past the ceiling must not be adopted")
	} else if !strings.Contains(err.Error(), "larger than the") {
		t.Fatalf("the refusal must name the ceiling, got %v", err)
	}
	if p.published {
		t.Fatal("a refused buffer must not count as published")
	}
}

// An inspection that did not happen is not "no symlink here".
//
// resolveLink used to treat every Lstat failure as a first download and hand
// back the path as given -- so a transient EIO or EACCES on a symlinked
// database meant the rename landed on the LINK, leaving the shared target on
// the old database while memory published the new one, with nothing to
// reconcile them afterwards. Only "not there" is a first download.
func TestAnUnreadableSymlinkFailsTheResolveRatherThanPassingItThrough(t *testing.T) {
	dir := t.TempDir()

	// A directory with no execute bit: Lstat inside it fails with EACCES
	// rather than ENOENT.
	locked := filepath.Join(dir, "locked")
	if err := os.Mkdir(locked, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(locked, "Country.mmdb")
	if err := os.WriteFile(target, fixture(t, "country-a.mmdb"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })

	if _, err := resolveLink(target); err == nil {
		t.Fatal("an unreadable path must fail the resolve, not pass through")
	} else if !strings.Contains(err.Error(), "cannot inspect") {
		t.Fatalf("the failure must say the inspection did not happen, got %v", err)
	}

	// The other direction: a path that is genuinely absent is still a first
	// download and resolves to itself.
	absent := filepath.Join(dir, "absent.mmdb")
	if got, err := resolveLink(absent); err != nil || got != absent {
		t.Fatalf("a missing file is a first download, got %q %v", got, err)
	}
}
