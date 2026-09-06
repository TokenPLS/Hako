package geodata

import (
	"fmt"
	"testing"

	"github.com/TokenPLS/Hako/component/geodata/router"
)

// Counts how many times a list is decoded, so "the cache was dropped" is
// observed as a second read rather than inferred from a heap number that
// moves with unrelated allocation.
type countingLoader struct {
	reads *int
	list  []*router.Domain
}

func (l countingLoader) LoadSiteByPath(_, _ string) ([]*router.Domain, error) {
	*l.reads++
	return l.list, nil
}

func (l countingLoader) LoadSiteByBytes([]byte, string) ([]*router.Domain, error) {
	return nil, fmt.Errorf("not used")
}

func (l countingLoader) LoadIPByPath(string, string) ([]*router.CIDR, error) {
	return nil, fmt.Errorf("not used")
}

func (l countingLoader) LoadIPByBytes([]byte, string) ([]*router.CIDR, error) {
	return nil, fmt.Errorf("not used")
}

func stageCountingLoader(t *testing.T, name string) *int {
	t.Helper()
	reads := 0
	domains := make([]*router.Domain, 0, 64)
	for index := 0; index < 64; index++ {
		domains = append(domains, &router.Domain{
			Type:  router.Domain_Domain,
			Value: fmt.Sprintf("host%d.example.com", index),
		})
	}
	RegisterGeoDataLoaderImplementationCreator(name, func() LoaderImplementation {
		return countingLoader{reads: &reads, list: domains}
	})
	previousLoader := geoLoaderName
	previousMode := geoMode
	SetLoader(name)
	SetGeodataMode(true)
	t.Cleanup(func() {
		geoLoaderName = previousLoader
		geoMode = previousMode
		delete(loaders, name)
	})
	return &reads
}

// The list a matcher is built from is scaffolding, and singleflight's
// StoreResult keeps it for the life of the process. Under memconservative —
// the mode the packet tunnel runs in, where the reader has said they would
// rather re-read the file than hold it — that retention is what put startup
// over the 50 MiB jetsam ceiling while parsing a configuration whose DNS
// nameserver-policy names geosite:cn.
func TestMemConservativeDoesNotRetainTheDecodedList(t *testing.T) {
	// Registered under the real mode name: the branch under test keys off it.
	reads := stageCountingLoader(t, "memconservative")

	if _, err := LoadGeoSiteMatcher("retention-cn"); err != nil {
		t.Fatal(err)
	}
	if *reads != 1 {
		t.Fatalf("first build read the list %d times, want 1", *reads)
	}
	// A different matcher over the same list: with the list still cached this
	// costs nothing, which is exactly the retention being paid for.
	if _, err := LoadGeoSiteMatcher("retention-cn@ads"); err != nil {
		t.Fatal(err)
	}
	if *reads != 2 {
		t.Fatalf("the decoded list was still cached: reads=%d, want a second read", *reads)
	}
}

// The other half of the trade, so the gate cannot be satisfied by dropping the
// cache everywhere: with a heap to spare, holding the list is the right call
// and upstream's behaviour stands.
func TestStandardLoaderKeepsTheDecodedList(t *testing.T) {
	reads := stageCountingLoader(t, "standard-retention-probe")

	if _, err := LoadGeoSiteMatcher("kept-cn"); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadGeoSiteMatcher("kept-cn@ads"); err != nil {
		t.Fatal(err)
	}
	if *reads != 1 {
		t.Fatalf("reads=%d, want the list read once and reused", *reads)
	}
}
