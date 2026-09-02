package compiled

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TokenPLS/Hako/component/trie"
)

func sampleSet(t *testing.T, domains ...string) (*trie.DomainSet, int) {
	t.Helper()
	tree := trie.New[struct{}]()
	for _, domain := range domains {
		if err := tree.Insert(domain, struct{}{}); err != nil {
			t.Fatal(err)
		}
	}
	return tree.NewDomainSet(), len(domains)
}

func TestCompiledSetRoundTrips(t *testing.T) {
	set, count := sampleSet(t, "+.example.com", "+.qq.com")
	var buffer bytes.Buffer
	if err := Write(&buffer, set, count, nil); err != nil {
		t.Fatal(err)
	}
	restored, restoredCount, _, err := Read(bytes.NewReader(buffer.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if restoredCount != count {
		t.Fatalf("count = %d, want %d", restoredCount, count)
	}
	for _, hit := range []string{"example.com", "www.example.com", "qq.com"} {
		if !restored.Has(hit) {
			t.Fatalf("restored set does not match %q", hit)
		}
	}
	if restored.Has("example.net") {
		t.Fatal("restored set matches a domain it was not given")
	}
}

// The name reaches this package from a configuration file, so a category that
// names a path is a write outside the directory unless it is refused. Cleaning
// is not enough: "cn/../../x" cleans to something legal-looking and still
// escapes when joined by a caller that trusts the result.
func TestPathRefusesNamesThatEscapeTheDirectory(t *testing.T) {
	for _, name := range []string{
		"../evil", "cn/../../evil", `..\evil`, "sub/dir", "", "   ",
		"cn;rm -rf /", "cn\x00", "café",
	} {
		if path, err := Path("/base", name); err == nil {
			t.Fatalf("category %q was accepted as %q", name, path)
		}
	}
	for _, name := range []string{"cn", "geolocation-!cn", "cn@ads", "private", "CN"} {
		path, err := Path("/base", name)
		if err != nil {
			t.Fatalf("category %q was refused: %v", name, err)
		}
		if filepath.Dir(path) != "/base" {
			t.Fatalf("category %q resolved outside the directory: %s", name, path)
		}
		if strings.ToLower(name) != strings.TrimSuffix(filepath.Base(path), ".mrs") {
			t.Fatalf("category %q became %q", name, filepath.Base(path))
		}
	}
}

func TestLoadReportsAbsenceSeparatelyFromFailure(t *testing.T) {
	directory := t.TempDir()
	if _, _, _, err := Load(directory, "cn"); !errors.Is(err, ErrNotCompiled) {
		t.Fatalf("absent artifact reported as %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, "cn.mrs"), []byte("not a rule set"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, _, err := Load(directory, "cn")
	if err == nil || errors.Is(err, ErrNotCompiled) {
		t.Fatalf("a corrupt artifact was reported as absent: %v", err)
	}
}

// A tunnel reads this directory while the App writes it. A reader that can see
// a partially written file cannot tell it from a corrupt one, and would take
// the tunnel down over a cache.
func TestStoreIsAtomicAndLeavesNoDebris(t *testing.T) {
	directory := t.TempDir()
	set, count := sampleSet(t, "+.example.com")
	if err := Store(directory, "CN", set, count, nil); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "cn.mrs" {
		var names []string
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf("directory holds %v, want exactly cn.mrs", names)
	}
	restored, restoredCount, _, err := Load(directory, "cn")
	if err != nil {
		t.Fatal(err)
	}
	if restoredCount != count || !restored.Has("www.example.com") {
		t.Fatal("the stored artifact does not answer for what it was given")
	}
}

func TestStoreRefusesUnsafeCategoryBeforeTouchingDisk(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "not-yet-there")
	set, count := sampleSet(t, "+.example.com")
	if err := Store(directory, "../escape", set, count, nil); err == nil {
		t.Fatal("an escaping category name was written")
	}
	if _, err := os.Stat(directory); !os.IsNotExist(err) {
		t.Fatal("a refused category still created the directory")
	}
}
