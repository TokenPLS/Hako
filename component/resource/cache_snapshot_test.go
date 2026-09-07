package resource

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/common/utils"
)

func TestAtomicCacheWriteKeepsReadersOnACompleteGeneration(t *testing.T) {
	dir := t.TempDir()
	SetAtomicCacheDirectory(dir)
	t.Cleanup(func() { SetAtomicCacheDirectory("") })
	path := filepath.Join(dir, "rules.yaml")
	old := []byte("payload:\n  - 203.0.113.0/24\n")
	next := []byte("payload:\n  - 192.0.2.0/24\n  - 198.51.100.0/24\n")
	if err := os.WriteFile(path, old, 0o600); err != nil {
		t.Fatal(err)
	}
	reader, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if err := safeWrite(path, next); err != nil {
		t.Fatal(err)
	}
	seen, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if string(seen) != string(old) {
		t.Fatal("a reader holding the previous cache generation observed rewritten bytes")
	}
	seen, err = os.ReadFile(path)
	if err != nil || string(seen) != string(next) {
		t.Fatalf("next generation = %q, %v", seen, err)
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 1 {
		t.Fatalf("temporary cache files leaked: %v, %v", files, err)
	}
}

func TestAtomicCachePolicyDoesNotChangeOtherProviderPaths(t *testing.T) {
	dir := t.TempDir()
	SetAtomicCacheDirectory(filepath.Join(dir, "private-cache"))
	t.Cleanup(func() { SetAtomicCacheDirectory("") })
	path := filepath.Join(dir, "ordinary")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	reader, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if err := safeWrite(path, []byte("new")); err != nil {
		t.Fatal(err)
	}
	seen, err := io.ReadAll(reader)
	if err != nil || string(seen) != "new" {
		t.Fatalf("ordinary upstream write changed: %q, %v", seen, err)
	}
}

type failedCacheVehicle struct {
	*scriptedVehicle
	fail bool
}

func (v *failedCacheVehicle) Write(buf []byte) error {
	if v.fail {
		_ = os.WriteFile(v.path, buf[:len(buf)/2], 0o600)
		return errors.New("interrupted cache write")
	}
	return v.scriptedVehicle.Write(buf)
}

func TestLoadedContentHashRejectsPartialFailedCacheWrites(t *testing.T) {
	v := &failedCacheVehicle{scriptedVehicle: &scriptedVehicle{path: filepath.Join(t.TempDir(), "rules")}}
	f := NewFetcher("rules", 0, v, nil, func(b []byte) (string, error) { return string(b), nil }, nil)
	t.Cleanup(func() { _ = f.Close() })
	if f.LoadedContentHash() != "" {
		t.Fatal("unloaded provider claimed a content hash")
	}
	old := []byte("previous complete payload")
	if _, _, err := f.SideUpdate(old); err != nil {
		t.Fatal(err)
	}
	if got := f.LoadedContentHash(); got != utils.MakeHash(old).String() {
		t.Fatalf("loaded hash = %q", got)
	}
	v.fail = true
	if _, _, err := f.SideUpdate([]byte("next incomplete payload")); err == nil {
		t.Fatal("write unexpectedly succeeded")
	}
	partial, err := os.ReadFile(v.path)
	if err != nil {
		t.Fatal(err)
	}
	if f.LoadedContentHash() == utils.MakeHash(partial).String() {
		t.Fatal("partial failed write was reported as loaded")
	}
	if f.LoadedContentHash() != utils.MakeHash(old).String() {
		t.Fatal("failed write replaced last successful content identity")
	}
}

func TestLoadedContentHashCanRaceWithUpdates(t *testing.T) {
	v := &scriptedVehicle{path: filepath.Join(t.TempDir(), "rules")}
	f, _, _ := newDeferredFetcher(t, v, 0)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			_ = f.LoadedContentHash()
		}
	}()
	for i := 0; i < 50; i++ {
		if _, _, err := f.SideUpdate([]byte{byte(i)}); err != nil {
			t.Error(err)
		}
	}
	wg.Wait()
}

func TestLoadedContentSnapshotDuringInitial(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules")
	if err := os.WriteFile(path, []byte("complete"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := NewFetcher("rules", 0, NewFileVehicle(path), nil, func(b []byte) (string, error) { return string(b), nil }, nil)
	t.Cleanup(func() { _ = f.Close() })
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			f.ReadLoadedContent(func(string, time.Time) {})
		}
	}()
	if _, err := f.Initial(); err != nil {
		t.Error(err)
	}
	wg.Wait()
}

func TestAtomicCacheRejectsSymlinksAndPreservesPermissions(t *testing.T) {
	dir := t.TempDir()
	if err := SetAtomicCacheDirectory(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = SetAtomicCacheDirectory("") })
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("old"), 0o640); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := safeWrite(link, []byte("new")); err == nil {
		t.Fatal("symlink target accepted")
	}
	bytes, err := os.ReadFile(target)
	if err != nil || string(bytes) != "old" {
		t.Fatalf("failed write changed target: %q, %v", bytes, err)
	}
	before, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := safeWrite(target, []byte("new")); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(target)
	if err != nil || after.Mode().Perm() != before.Mode().Perm() {
		t.Fatalf("existing permissions changed: %v, %v", after, err)
	}
	fresh := filepath.Join(dir, "fresh")
	if err := safeWrite(fresh, []byte("new")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(fresh)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("fresh cache permissions: %v, %v", info, err)
	}
}
