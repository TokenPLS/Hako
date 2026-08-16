package hako

import (
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/component/geodata"
	"github.com/TokenPLS/Hako/component/geodata/compiled"
	C "github.com/TokenPLS/Hako/constant"
)

// The two spellings a reader's configuration uses, and the near-misses that
// must not be mistaken for them. The DNS key is the one that killed a reader's
// tunnel, and it names three categories in a single token — reading only the
// first would have left two uncompiled and the tunnel still dead.
func TestGeoSiteCategoriesInFindsBothSpellings(t *testing.T) {
	for name, testCase := range map[string]struct {
		content string
		want    []string
	}{
		"dns policy names several at once": {
			content: "dns:\n  nameserver-policy:\n    \"geosite:cn,apple,private\": [223.5.5.5]\n",
			want:    []string{"cn", "apple", "private"},
		},
		"a rule names one and then a target": {
			content: "rules:\n  - GEOSITE,cn,DIRECT\n  - GEOSITE,youtube,PROXY\n",
			want:    []string{"cn", "youtube"},
		},
		"negation and attributes stay attached": {
			content: "rules:\n  - GEOSITE,geolocation-!cn,PROXY\n  - GEOSITE,cn@ads,REJECT\n",
			want:    []string{"geolocation-!cn", "cn@ads"},
		},
		"case does not matter": {
			content: "rules:\n  - GeoSite,CN,DIRECT\n",
			want:    []string{"cn"},
		},
		"the same category twice is one job": {
			content: "rules:\n  - GEOSITE,cn,DIRECT\ndns:\n  nameserver-policy:\n    \"geosite:cn\": [1.1.1.1]\n",
			want:    []string{"cn"},
		},
		"a longer word is not a reference": {
			content: "rules:\n  - DOMAIN,notgeosite:cn.example.com,DIRECT\n  - DOMAIN-SUFFIX,mygeosite,DIRECT\n",
			want:    nil,
		},
		"geoip is a different loader": {
			content: "rules:\n  - GEOIP,CN,DIRECT\n",
			want:    nil,
		},
		"nothing at all": {
			content: "rules: []\n",
			want:    nil,
		},
		"a rule may breathe after its commas": {
			content: "rules:\n  - GEOSITE, cn, DIRECT\n",
			want:    []string{"cn"},
		},
		"a policy key may breathe after its commas": {
			content: "dns:\n  nameserver-policy:\n    \"geosite:cn, apple\": [1.1.1.1]\n",
			want:    []string{"cn", "apple"},
		},
		"the fallback filter names bare categories": {
			content: "dns:\n  fallback-filter:\n    geoip: true\n    geosite:\n      - cn\n      - gfw\n",
			want:    []string{"cn", "gfw"},
		},
		"an inline fallback filter list": {
			content: "dns:\n  fallback-filter:\n    geosite: [cn]\n",
			want:    []string{"cn"},
		},
		"prose around a reference is not a category": {
			content: "# the geosite:cn database is documented elsewhere\n",
			want:    nil,
		},
		"a rule may breathe before its comma too": {
			content: "rules:\n  - GEOSITE , cn, DIRECT\n",
			want:    []string{"cn"},
		},
		"a logic rule wraps a reference in parentheses": {
			content: "rules:\n  - AND,((GEOSITE,cn),(DST-PORT,443)),DIRECT\n",
			want:    []string{"cn"},
		},
		"nested logic keeps every reference": {
			content: "rules:\n  - OR,((GEOSITE,apple),(NOT,((GEOSITE,cn)))),PROXY\n",
			want:    []string{"apple", "cn"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			got := GeoSiteCategoriesIn(testCase.content)
			if !reflect.DeepEqual(got, testCase.want) {
				t.Fatalf("categories = %#v, want %#v", got, testCase.want)
			}
		})
	}
}

// A hostile payload is still a legal payload: provider bodies arrive from the
// network at up to 16 MiB, and the App scans them at activation. A scan that
// rereads to the end of the line for every marker turns one crafted line of
// repeated markers into quadratic work — measured 13s for 352 KiB before the
// cursor learned to skip what it had already consumed, which extrapolates to
// hours at the size limit, all spent on the activation path.
func TestGeoSiteCategoriesInStaysLinearOnRepeatedMarkers(t *testing.T) {
	line := strings.Repeat("geosite,cn,", 32*1024)
	start := time.Now()
	got := GeoSiteCategoriesIn(line)
	elapsed := time.Since(start)
	if !reflect.DeepEqual(got, []string{"cn"}) {
		t.Fatalf("categories = %#v, want [cn]", got)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("scanning %d bytes of repeated markers took %v", len(line), elapsed)
	}
}

// A downloaded classical provider payload is scanned with this same function:
// its entries are GEOSITE,cn lines in text form or a YAML payload list. The
// App hands the materialised payload to PrepareGeoSiteCache after download —
// that is the whole plan for providers, so the shape is pinned here; breaking
// it strands every GEOSITE rule inside a provider as an empty matcher on the
// tunnel.
func TestGeoSiteCategoriesInReadsClassicalProviderPayloads(t *testing.T) {
	text := "DOMAIN-SUFFIX,example.com\nGEOSITE,cn\n"
	if got := GeoSiteCategoriesIn(text); !reflect.DeepEqual(got, []string{"cn"}) {
		t.Fatalf("text payload categories = %#v, want [cn]", got)
	}
	yamlPayload := "payload:\n  - GEOSITE,apple\n  - DOMAIN,x.com\n"
	if got := GeoSiteCategoriesIn(yamlPayload); !reflect.DeepEqual(got, []string{"apple"}) {
		t.Fatalf("yaml payload categories = %#v, want [apple]", got)
	}
}

// A rule's category ends at the comma; the target after it is a proxy group,
// not something to compile. Pinned separately because collecting it would look
// harmless — a failed compile, a warning — while quietly telling a reader their
// proxy group is a missing geosite category.
func TestGeoSiteCategoriesInDoesNotCollectRuleTargets(t *testing.T) {
	got := GeoSiteCategoriesIn("rules:\n  - GEOSITE,cn,节点选择\n  - GEOSITE,apple,DIRECT\n")
	want := []string{"cn", "apple"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("categories = %#v, want %#v", got, want)
	}
}

// Switching profiles runs this every time. Recompiling a category whose source
// has not changed would put the whole 72.7 MiB build back into every switch,
// which is the cost this work exists to remove — so the second run must do
// nothing, and "nothing" is observable as an artifact that was not rewritten.
func TestPrepareGeoSiteCacheReusesAnArtifactThatIsStillCurrent(t *testing.T) {
	options := testOptions(t)
	if err := os.MkdirAll(options.WorkingPath, 0o755); err != nil {
		t.Fatal(err)
	}
	stageBundledGeodata(t, options.WorkingPath)
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	C.SetHomeDir(options.WorkingPath)
	geodata.SetGeodataMode(true)
	geodata.SetLoader("memconservative")
	t.Cleanup(geodata.ClearGeoSiteCache)

	const content = "rules:\n  - GEOSITE,cn,DIRECT\n"
	if _, err := PrepareGeoSiteCache(content); err != nil {
		t.Fatal(err)
	}
	path, err := compiled.Path(geodata.CompiledGeoSiteDir(), "cn")
	if err != nil {
		t.Fatal(err)
	}
	first, err := os.Stat(path)
	if err != nil {
		t.Fatalf("nothing was compiled: %v", err)
	}

	if _, err := PrepareGeoSiteCache(content); err != nil {
		t.Fatal(err)
	}
	second, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !second.ModTime().Equal(first.ModTime()) {
		t.Fatal("a current artifact was rebuilt on the next activation")
	}

	// Staged geodata is what invalidates it: a newer source has to win, or a
	// reader who updated their geosite would keep matching yesterday's.
	refreshed := first.ModTime().Add(2 * time.Second)
	if err := os.Chtimes(C.Path.GeoSite(), refreshed, refreshed); err != nil {
		t.Fatal(err)
	}
	geodata.ClearGeoSiteCache()
	if _, err := PrepareGeoSiteCache(content); err != nil {
		t.Fatal(err)
	}
	third, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !third.ModTime().After(first.ModTime()) {
		t.Fatal("a newer geosite source did not rebuild the artifact")
	}
}

// Being newer than the source is not the same as being an answer.
//
// The freshness check compared timestamps and nothing else, so any file sitting
// in the right place with a recent mtime was treated as a compiled category and
// the real compile never ran again. A truncated write, a half-copied container,
// an artifact from a build whose format has moved on — each of them would have
// been trusted forever, and the tunnel would have matched nothing while
// reporting that everything was current.
func TestPrepareGeoSiteCacheReplacesAnUnreadableArtifact(t *testing.T) {
	options := testOptions(t)
	if err := os.MkdirAll(options.WorkingPath, 0o755); err != nil {
		t.Fatal(err)
	}
	stageBundledGeodata(t, options.WorkingPath)
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	C.SetHomeDir(options.WorkingPath)
	geodata.SetGeodataMode(true)
	geodata.SetLoader("memconservative")
	t.Cleanup(geodata.ClearGeoSiteCache)

	directory := geodata.CompiledGeoSiteDir()
	path, err := compiled.Path(directory, "cn")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("newer than the source, and not a rule set"), 0o600); err != nil {
		t.Fatal(err)
	}

	summary, err := PrepareGeoSiteCache("rules:\n  - GEOSITE,cn,DIRECT\n")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(summary, "1 compiled") {
		t.Fatalf("an unreadable artifact was treated as current: %s", summary)
	}
	count, err := compiled.EntryCount(directory, "cn")
	if err != nil {
		t.Fatalf("the replacement is not readable either: %v", err)
	}
	if count == 0 {
		t.Fatal("the replacement holds nothing")
	}

	// And the other direction: a real artifact is not rebuilt on every switch.
	second, err := PrepareGeoSiteCache("rules:\n  - GEOSITE,cn,DIRECT\n")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(second, "1 current") {
		t.Fatalf("a valid artifact was rebuilt: %s", second)
	}
}

// Newer than the source and opening with a plausible header is still not an
// answer. An artifact cut off after its count — a kill mid-copy, a full disk,
// power loss before the data blocks were flushed — used to pass the
// header-only freshness check and be reported current forever, while the
// tunnel's full read failed into a category that matches nothing under
// compiled-only. Current has to mean the whole artifact reads back.
func TestPrepareGeoSiteCacheReplacesATruncatedArtifact(t *testing.T) {
	options := testOptions(t)
	if err := os.MkdirAll(options.WorkingPath, 0o755); err != nil {
		t.Fatal(err)
	}
	stageBundledGeodata(t, options.WorkingPath)
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	C.SetHomeDir(options.WorkingPath)
	geodata.SetGeodataMode(true)
	geodata.SetLoader("memconservative")
	t.Cleanup(geodata.ClearGeoSiteCache)

	const content = "rules:\n  - GEOSITE,cn,DIRECT\n"
	if _, err := PrepareGeoSiteCache(content); err != nil {
		t.Fatal(err)
	}
	path, err := compiled.Path(geodata.CompiledGeoSiteDir(), "cn")
	if err != nil {
		t.Fatal(err)
	}
	whole, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Keep the head, lose the tail: the truncated file still decodes far
	// enough to answer a header probe, and its mtime is newer than the source.
	if err := os.WriteFile(path, whole[:len(whole)*3/4], 0o600); err != nil {
		t.Fatal(err)
	}
	geodata.ClearGeoSiteCache()

	summary, err := PrepareGeoSiteCache(content)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(summary, "1 compiled") {
		t.Fatalf("a truncated artifact was treated as current: %s", summary)
	}
	if _, count, _, err := compiled.Load(geodata.CompiledGeoSiteDir(), "cn"); err != nil || count == 0 {
		t.Fatalf("the replacement does not read back whole: count=%d err=%v", count, err)
	}
}

// geox-url.geosite is the one place upstream's schema puts a bare `geosite:`
// YAML key whose value is NOT a category reference -- it is a URL
// (config.go:391-396 RawGeoXUrl, a typed field upstream reads separately from
// every category site: nameserver-policy prefix matching at config.go:1398 and
// the GEOSITE rule parser). Upstream cannot confuse the two by construction;
// this text scanner can, and did: an unquoted URL's scheme was collected as
// category "https", the extension then found an uncompiled named category at
// startup,'s no-download rule killed it before it wrote one log
// line (NEVPNConnectionErrorDomain code=12). Quoting was the accident that
// hid it -- and the script round trip legally drops quotes.
func TestGeoxURLGeositeIsAURLNotACategory(t *testing.T) {
	unquoted := `
geox-url:
  geosite: https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat
  geoip: https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat
rules:
  - GEOSITE,cn,DIRECT
dns:
  nameserver-policy:
    "geosite:gfw": ["8.8.8.8"]
`
	got := GeoSiteCategoriesIn(unquoted)
	for _, name := range got {
		if name == "https" || name == "http" {
			t.Fatalf("a URL scheme was collected as a category: %v", got)
		}
	}
	want := map[string]bool{"cn": false, "gfw": false}
	for _, name := range got {
		if _, ok := want[name]; ok {
			want[name] = true
		}
	}
	for name, seen := range want {
		if !seen {
			t.Fatalf("real category %q lost while excluding the URL: %v", name, got)
		}
	}
}

// The three spellings of the same document must agree: quotes are YAML style,
// not meaning, and the script round trip (YamlToJSON -> JSONToYaml) legally
// rewrites style. The defect lived exactly in this gap.
func TestQuotingStyleDoesNotChangeTheCategorySet(t *testing.T) {
	shapes := map[string]string{
		"unquoted":      "geox-url:\n  geosite: https://e.test/geosite.dat\nrules:\n  - GEOSITE,cn,DIRECT\n",
		"double quoted": "geox-url:\n  geosite: \"https://e.test/geosite.dat\"\nrules:\n  - GEOSITE,cn,DIRECT\n",
		"single quoted": "geox-url:\n  geosite: 'https://e.test/geosite.dat'\nrules:\n  - GEOSITE,cn,DIRECT\n",
	}
	var first []string
	var firstName string
	for name, doc := range shapes {
		got := GeoSiteCategoriesIn(doc)
		if first == nil {
			first, firstName = got, name
			continue
		}
		if len(got) != len(first) {
			t.Fatalf("%s yields %v but %s yields %v", name, got, firstName, first)
		}
		for i := range got {
			if got[i] != first[i] {
				t.Fatalf("%s yields %v but %s yields %v", name, got, firstName, first)
			}
		}
	}
	if len(first) != 1 || first[0] != "cn" {
		t.Fatalf("want exactly [cn], got %v", first)
	}
}

// An unquoted nameserver-policy key also ends its segment at a colon --
// `geosite:cn: 1.1.1.1` -- and that colon is NOT followed by `//`. The URL
// exclusion must be the signature `://`, never "segment ended at a colon".
func TestUnquotedPolicyKeyStillCollects(t *testing.T) {
	doc := "dns:\n  nameserver-policy:\n    geosite:cn: [\"223.5.5.5\"]\n"
	got := GeoSiteCategoriesIn(doc)
	if len(got) != 1 || got[0] != "cn" {
		t.Fatalf("unquoted policy key lost: %v", got)
	}
}

// The geoip twin already embodies this lesson from the other direction: its
// colon form collides with upstream's `geoip:` boolean key, so it dropped the
// colon form entirely (geoip_cache.go "Only the comma form"). Pin that the
// URL shape stays inert there too, so the two scanners cannot drift apart
// silently.
func TestGeoIPTwinStaysInertOnGeoxURL(t *testing.T) {
	doc := "geox-url:\n  geoip: https://e.test/geoip.dat\n"
	if got := GeoIPCountriesIn(doc); len(got) != 0 {
		t.Fatalf("geoip scanner collected from a URL: %v", got)
	}
}
