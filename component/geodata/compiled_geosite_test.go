package geodata

import (
	"os"
	"testing"

	"github.com/TokenPLS/Hako/component/geodata/compiled"
	"github.com/TokenPLS/Hako/component/geodata/router"
	"github.com/TokenPLS/Hako/component/trie"
	C "github.com/TokenPLS/Hako/constant"
)

func stageCompiledHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	previous := C.Path.HomeDir()
	C.SetHomeDir(home)
	t.Cleanup(func() { C.SetHomeDir(previous) })
	ClearGeoSiteCache()
	t.Cleanup(ClearGeoSiteCache)
	return CompiledGeoSiteDir()
}

func writeCompiledCategory(t *testing.T, directory, category string, domains ...string) {
	t.Helper()
	tree := trie.New[struct{}]()
	for _, domain := range domains {
		if err := tree.Insert(domain, struct{}{}); err != nil {
			t.Fatal(err)
		}
	}
	if err := compiled.Store(directory, category, tree.NewDomainSet(), len(domains), nil); err != nil {
		t.Fatal(err)
	}
}

// The compiled artifact has to win, or the saving is theoretical: the loader
// that would otherwise run is the one that peaks at 72.7 MiB.
func TestCompiledCategoryIsPreferredOverSource(t *testing.T) {
	directory := stageCompiledHome(t)
	reads := stageCountingLoader(t, "compiled-preference-probe")
	writeCompiledCategory(t, directory, "prefer-cn", "+.example.com")

	matcher, err := LoadGeoSiteMatcher("prefer-cn")
	if err != nil {
		t.Fatal(err)
	}
	if *reads != 0 {
		t.Fatalf("source was decoded %d times despite a compiled artifact", *reads)
	}
	if !matcher.ApplyDomain("www.example.com") {
		t.Fatal("the compiled category does not answer for what it holds")
	}
}

// The rule a reader lives by: a category this process cannot afford to build is
// a category that matches nothing, not a tunnel that refuses to start. Their
// configuration was killed by the alternative.
func TestCompiledOnlyRuntimeDegradesInsteadOfDecoding(t *testing.T) {
	stageCompiledHome(t)
	reads := stageCountingLoader(t, "compiled-only-probe")
	previous := CompiledGeoSiteOnly()
	SetCompiledGeoSiteOnly(true)
	t.Cleanup(func() { SetCompiledGeoSiteOnly(previous) })

	matcher, err := LoadGeoSiteMatcher("absent-cn")
	if err != nil {
		t.Fatalf("a missing compiled category refused to load: %v", err)
	}
	if *reads != 0 {
		t.Fatalf("a compiled-only runtime decoded source %d times", *reads)
	}
	if matcher == nil {
		t.Fatal("no matcher was returned")
	}
	if matcher.ApplyDomain("www.example.com") {
		t.Fatal("a category that was never loaded matched a domain")
	}
	if matcher.Count() != 0 {
		t.Fatalf("count = %d, want 0 for a category that did not load", matcher.Count())
	}
}

// The same absence off the constrained runtime still decodes: this is a memory
// policy for one process, not a change to what the core supports.
func TestUnconstrainedRuntimeStillDecodesSource(t *testing.T) {
	stageCompiledHome(t)
	reads := stageCountingLoader(t, "unconstrained-probe")
	SetCompiledGeoSiteOnly(false)

	if _, err := LoadGeoSiteMatcher("decoded-cn"); err != nil {
		t.Fatal(err)
	}
	if *reads != 1 {
		t.Fatalf("source reads = %d, want 1", *reads)
	}
}

// Compiling is the expensive direction and has to leave an artifact the cheap
// direction can read, or the App would pay the peak on every launch and the
// tunnel would still have nothing.
func TestCompileGeoSiteWritesAnArtifactTheLoaderThenUses(t *testing.T) {
	directory := stageCompiledHome(t)
	reads := stageCountingLoader(t, "compile-probe")
	SetCompiledGeoSiteOnly(false)

	if err := CompileGeoSite("compile-cn"); err != nil {
		t.Fatal(err)
	}
	if *reads != 1 {
		t.Fatalf("compiling read source %d times, want 1", *reads)
	}
	path, err := compiled.Path(directory, "compile-cn")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("compiling left no artifact: %v", err)
	}

	// A fresh process, constrained, with only the artifact to work from.
	ClearGeoSiteCache()
	SetCompiledGeoSiteOnly(true)
	t.Cleanup(func() { SetCompiledGeoSiteOnly(false) })
	before := *reads
	matcher, err := LoadGeoSiteMatcher("compile-cn")
	if err != nil {
		t.Fatal(err)
	}
	if *reads != before {
		t.Fatal("the constrained runtime decoded source despite the artifact")
	}
	if !matcher.ApplyDomain("host0.example.com") {
		t.Fatal("the compiled artifact does not answer for what the source held")
	}
}

// The defect this exists to stop, reproduced exactly as it happened on a
// device: the App's preflight parses as the tunnel would — CheckConfig passes
// underNetworkExtension true — so compiled-only is ON in the App's own process
// and every category it declines to decode leaves an empty matcher in the
// loader's cache, which stores results for the life of the process. Compiling
// afterwards must not take that empty matcher for the category.
//
// It did. Three categories "compiled", nothing was written, and the tunnel
// started with geosite:cn matching nothing while reporting records: 0.
func TestCompilingIgnoresAnEmptyMatcherLeftByAConstrainedPreflight(t *testing.T) {
	directory := stageCompiledHome(t)
	reads := stageCountingLoader(t, "poisoned-cache-probe")

	// The preflight: constrained, so the category degrades and is memoised.
	SetCompiledGeoSiteOnly(true)
	preflight, err := LoadGeoSiteMatcher("poisoned-cn")
	if err != nil {
		t.Fatal(err)
	}
	if preflight.Count() != 0 || *reads != 0 {
		t.Fatalf("the preflight did not degrade: count=%d reads=%d", preflight.Count(), *reads)
	}

	// The compile step that follows it, in the same process.
	SetCompiledGeoSiteOnly(false)
	t.Cleanup(func() { SetCompiledGeoSiteOnly(false) })
	if err := CompileGeoSite("poisoned-cn"); err != nil {
		t.Fatalf("compiling refused after a constrained preflight: %v", err)
	}
	if *reads != 1 {
		t.Fatalf("compiling read source %d times, want 1 — it used the cached empty matcher", *reads)
	}

	_, count, _, err := compiled.Load(directory, "poisoned-cn")
	if err != nil {
		t.Fatalf("no artifact was written: %v", err)
	}
	if count == 0 {
		t.Fatal("an empty artifact was written, which the tunnel would trust")
	}
}

// A negated rule reads the same artifact as the plain spelling: negation is
// applied at match time, never baked into the file. Compiling under the raw
// spelling wrote !cn.mrs while the loader reads cn.mrs; under compiled-only the
// missing artifact degraded to an empty matcher, and the negation then turned
// "not in cn" into "every domain there is".
func TestNegatedCategoryReadsTheArtifactItCompiled(t *testing.T) {
	stageCompiledHome(t)
	reads := stageCountingLoader(t, "negation-probe")
	SetCompiledGeoSiteOnly(false)

	if err := CompileGeoSite("!negated-cn"); err != nil {
		t.Fatal(err)
	}

	// A fresh process, constrained, with only the artifact to work from.
	ClearGeoSiteCache()
	SetCompiledGeoSiteOnly(true)
	t.Cleanup(func() { SetCompiledGeoSiteOnly(false) })
	before := *reads
	matcher, err := LoadGeoSiteMatcher("!negated-cn")
	if err != nil {
		t.Fatal(err)
	}
	if *reads != before {
		t.Fatal("the constrained runtime decoded source despite the artifact")
	}
	if matcher.ApplyDomain("host0.example.com") {
		t.Fatal("a domain inside the negated category matched")
	}
	if !matcher.ApplyDomain("unrelated.example.net") {
		t.Fatal("a domain outside the negated category did not match")
	}
}

// A category with several attributes compiles under the exact name the loader
// asks for. The raw spelling keeps '@' between attributes while the loader
// prints them comma-joined; the compiled key must be the loader's, or the
// artifact is written once and never read.
func TestAttributedCategoryReadsTheArtifactItCompiled(t *testing.T) {
	stageCompiledHome(t)
	reads := 0
	boolAttr := func(key string) *router.Domain_Attribute {
		return &router.Domain_Attribute{
			Key:        key,
			TypedValue: &router.Domain_Attribute_BoolValue{BoolValue: true},
		}
	}
	domains := []*router.Domain{
		{Type: router.Domain_Domain, Value: "plain.example.com"},
		{Type: router.Domain_Domain, Value: "ads-only.example.com",
			Attribute: []*router.Domain_Attribute{boolAttr("ads")}},
		{Type: router.Domain_Domain, Value: "ads-apple.example.com",
			Attribute: []*router.Domain_Attribute{boolAttr("ads"), boolAttr("apple")}},
	}
	RegisterGeoDataLoaderImplementationCreator("attribute-probe", func() LoaderImplementation {
		return countingLoader{reads: &reads, list: domains}
	})
	previousLoader := geoLoaderName
	SetLoader("attribute-probe")
	t.Cleanup(func() {
		geoLoaderName = previousLoader
		delete(loaders, "attribute-probe")
	})
	SetCompiledGeoSiteOnly(false)

	if err := CompileGeoSite("attr-cn@ads@apple"); err != nil {
		t.Fatal(err)
	}

	ClearGeoSiteCache()
	SetCompiledGeoSiteOnly(true)
	t.Cleanup(func() { SetCompiledGeoSiteOnly(false) })
	matcher, err := LoadGeoSiteMatcher("attr-cn@ads@apple")
	if err != nil {
		t.Fatal(err)
	}
	if !matcher.ApplyDomain("ads-apple.example.com") {
		t.Fatal("the entry carrying both attributes did not match")
	}
	if matcher.ApplyDomain("ads-only.example.com") {
		t.Fatal("an entry missing one requested attribute matched")
	}
	if matcher.ApplyDomain("plain.example.com") {
		t.Fatal("an unattributed entry matched")
	}
}

// A category the set cannot fully hold still compiles, and still matches what
// the source matched. geosite:private carries one regex among 131 entries; the
// first version of this refused the whole category over it, so private compiled
// to nothing and matched nothing.
func TestResidualEntriesSurviveCompilation(t *testing.T) {
	directory := stageCompiledHome(t)
	reads := 0
	domains := []*router.Domain{
		{Type: router.Domain_Domain, Value: "example.com"},
		{Type: router.Domain_Full, Value: "exact.example.org"},
		{Type: router.Domain_Regex, Value: `^intranet\..*\.corp$`},
		{Type: router.Domain_Plain, Value: "keyword-bit"},
	}
	RegisterGeoDataLoaderImplementationCreator("residual-probe", func() LoaderImplementation {
		return countingLoader{reads: &reads, list: domains}
	})
	previousLoader := geoLoaderName
	SetLoader("residual-probe")
	t.Cleanup(func() {
		geoLoaderName = previousLoader
		delete(loaders, "residual-probe")
	})
	SetCompiledGeoSiteOnly(false)

	if err := CompileGeoSite("residual-cn"); err != nil {
		t.Fatal(err)
	}
	_, count, residual, err := compiled.Load(directory, "residual-cn")
	if err != nil {
		t.Fatal(err)
	}
	if count != len(domains) {
		t.Fatalf("count = %d, want %d", count, len(domains))
	}
	if len(residual) != 2 {
		t.Fatalf("residual = %+v, want the regex and the keyword", residual)
	}

	// And the tunnel's side: read it back constrained, and every kind of entry
	// the source held still answers.
	ClearGeoSiteCache()
	SetCompiledGeoSiteOnly(true)
	t.Cleanup(func() { SetCompiledGeoSiteOnly(false) })
	matcher, err := LoadGeoSiteMatcher("residual-cn")
	if err != nil {
		t.Fatal(err)
	}
	for _, hit := range []string{
		"www.example.com", "exact.example.org",
		"intranet.finance.corp", "host-keyword-bit.example.net",
	} {
		if !matcher.ApplyDomain(hit) {
			t.Fatalf("the compiled category no longer matches %q", hit)
		}
	}
	if matcher.ApplyDomain("unrelated.example.net") {
		t.Fatal("the compiled category matches something the source did not")
	}
}
