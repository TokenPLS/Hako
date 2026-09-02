package hako

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/TokenPLS/Hako/config"
)

// unnamedShareLinks is one link per scheme with no #fragment, which is how a
// person's clipboard often arrives. The list is per scheme on purpose. The
// defect these tests were written for lived in makeProxyImportNameUnique, and
// writing the gate around its call sites would have been writing it around
// today's implementation -- three call sites that could become one tomorrow
// without changing anything a person can see. A scheme is what is being
// tested; a call site is how it currently happens.
//
// Three lanes each sampled a different slice of this list on 2026-08-28 and
// each concluded something true about their slice: this tree checked anytls
// and reported that unnamed links get host:port, the iOS lane checked four and
// reported that they get "", the macOS lane checked five and found both. The
// list is exhaustive so that the next reading does not depend on which rows
// somebody happened to pick.
var unnamedShareLinks = map[string]string{
	"ss":        "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwd2Q@e.example:1080",
	"trojan":    "trojan://pw@e.example:443",
	"vless":     "vless://11111111-1111-1111-1111-111111111111@e.example:443",
	"anytls":    "anytls://pw@e.example:443",
	"hysteria2": "hysteria2://pw@e.example:443",
	"tuic":      "tuic://11111111-1111-1111-1111-111111111111:pw@e.example:443",
	"socks5":    "socks5://dXNlcjpwYXNz@e.example:1080",
	"http":      "http://dXNlcjpwYXNz@e.example:8080",
	"snell":     "snell://cHNr@e.example:443",
	"ssh":       "ssh://user:pw@e.example:22",
}

func sortedSchemes() []string {
	schemes := make([]string, 0, len(unnamedShareLinks))
	for scheme := range unnamedShareLinks {
		schemes = append(schemes, scheme)
	}
	sort.Strings(schemes)
	return schemes
}

// Two links with no name of their own still produce two nodes the kernel will
// load.
//
// Five of these ten schemes reached makeProxyImportNameUnique with an empty
// name and were returned unchanged, so pasting the same unnamed link twice
// produced a configuration mihomo refused outright: `proxy  is the duplicate
// name`. The person got a profile that would not load, and nothing in the
// import report said why -- the import had reported success.
//
// The kernel's own parser is the judge here rather than an assertion about
// names, because that is the thing that was failing.
func TestTwoUnnamedLinksOfEverySchemeProduceALoadableConfiguration(t *testing.T) {
	for _, scheme := range sortedSchemes() {
		t.Run(scheme, func(t *testing.T) {
			link := unnamedShareLinks[scheme]
			payload := []byte(link + "\n" + link)

			box, err := ConvertProxiesForIOS(payload)
			if err != nil {
				t.Fatalf("two unnamed %s links did not convert: %v", scheme, err)
			}
			if _, err := config.Parse([]byte(box.Value + "\nproxy-groups: []\nrules:\n  - MATCH,DIRECT\n")); err != nil {
				t.Fatalf("the kernel refuses what this importer produced from two unnamed %s links: %v", scheme, err)
			}

			report := readImportReport(t, payload)
			if len(report.Proxies) != 2 {
				t.Fatalf("expected two nodes, got %d", len(report.Proxies))
			}
			first, second := importedNodeName(report.Proxies[0]), importedNodeName(report.Proxies[1])
			if first == "" || second == "" {
				t.Fatalf("an imported node has no name: %q and %q", first, second)
			}
			if first == second {
				t.Fatalf("two imported nodes share the name %q, which the kernel rejects", first)
			}
		})
	}
}

// Every field this build could not honour names the node it belonged to, by the
// name that node ends up with.
//
// The association has to survive renaming, and renaming is what makes it hard:
// the notices are produced while the link is being read and the final name is
// assigned afterwards, so a notice stamped with the name from the link sends
// every same-named node's notices to whichever one came first. Two identical
// links are the smallest case that tells the difference.
func TestAFieldNoticeNamesTheNodeItBelongsTo(t *testing.T) {
	for _, scheme := range sortedSchemes() {
		unhonourable, ok := map[string]string{
			"ss": "security=1", "trojan": "mux=1", "vless": "mux=1", "anytls": "keepalive=9",
			"hysteria2": "keepalive=9", "tuic": "pbk=aaaa", "socks5": "sni=x.example",
			"http": "pbk=aaaa", "snell": "alpn=h2", "ssh": "keepalive=9",
		}[scheme]
		if !ok {
			t.Fatalf("no unhonourable field known for %s, so this scheme would pass untested", scheme)
		}
		t.Run(scheme, func(t *testing.T) {
			link := unnamedShareLinks[scheme] + "?" + unhonourable
			report := readImportReport(t, []byte(link+"\n"+link))
			if len(report.Proxies) != 2 {
				t.Fatalf("expected two nodes, got %d: %#v", len(report.Proxies), report)
			}
			if len(report.NotHonoured) != 2 {
				t.Fatalf("expected one notice per node, got %d: %#v", len(report.NotHonoured), report.NotHonoured)
			}
			named := map[string]bool{}
			for _, proxy := range report.Proxies {
				named[importedNodeName(proxy)] = true
			}
			seen := map[string]bool{}
			for _, notice := range report.NotHonoured {
				if notice.Proxy == "" {
					t.Fatalf("a notice names no node: %#v", notice)
				}
				if !named[notice.Proxy] {
					t.Fatalf("a notice names %q, which is not among the imported nodes %v", notice.Proxy, named)
				}
				if seen[notice.Proxy] {
					t.Fatalf("both notices were filed against %q; the second node's notice was lost", notice.Proxy)
				}
				seen[notice.Proxy] = true
			}
		})
	}
}

// A link that is skipped carries its own field notices instead of filing them
// against a node that does not exist.
func TestASkippedLinkCarriesItsOwnFieldNotices(t *testing.T) {
	// The port is out of range, which is fatal to the record, and alpn on the
	// same link is a field snell has nowhere to put.
	//
	// The fixture used to be an unbuildable plugin name. That stopped being a
	// skip on 2026-08-28 -- upstream drops the plugin and the kernel loads the
	// node, so refusing was stricter than the chain below us -- and the test
	// went red rather than quietly asserting nothing, which is what it is for.
	link := "snell://cHNr@e.example:99999?alpn=h2&version=4#N"
	report := readImportReport(t, []byte(link))
	if len(report.Proxies) != 0 || len(report.Skipped) != 1 {
		t.Fatalf("expected the link to be skipped: %#v", report)
	}
	if len(report.NotHonoured) != 0 {
		t.Fatalf("a notice was filed against a node that was never imported: %#v", report.NotHonoured)
	}
	var carried bool
	for _, also := range report.Skipped[0].AlsoNotHonoured {
		if strings.Contains(also, "alpn") {
			carried = true
		}
	}
	if !carried {
		t.Fatalf("the skipped link dropped its own field notices: %#v", report.Skipped[0])
	}
}

func readImportReport(t *testing.T, payload []byte) decodedImportReport {
	t.Helper()
	box, err := InspectProxyPayloadForIOS(payload, "nodeBundle")
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	var report decodedImportReport
	if err := json.Unmarshal([]byte(box.Value), &report); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return report
}

type decodedImportReport struct {
	Proxies     []map[string]any `json:"proxies"`
	Skipped     []decodedIssue   `json:"skipped"`
	Identities  []string         `json:"identities"`
	NotHonoured []decodedIssue   `json:"notHonoured"`
}

type decodedIssue struct {
	Scheme          string   `json:"scheme"`
	Code            string   `json:"code"`
	Message         string   `json:"message"`
	Proxy           string   `json:"proxy"`
	AlsoNotHonoured []string `json:"alsoNotHonoured"`
}

func importedNodeName(proxy map[string]any) string {
	name, _ := proxy["name"].(string)
	return name
}

// The report says which pasted links describe the same node, and the four cases
// that decide it are all here.
//
// Collapsing duplicates is the client's, because this pass sees only what was
// pasted just now while the duplicate a person actually meets is the one
// already in their profile. What is not the client's is knowing whether two
// links describe the same node, which needs to know what each field means to an
// outbound. So the kernel answers that and nothing else.
//
// The two orderings that make this work pull opposite ways, and both are
// asserted here because getting either backwards silently produces the wrong
// answer rather than an error:
//
//   - the identity is computed BEFORE renaming, or the second "HK" is already
//     "HK-01" and no two nodes are ever alike;
//   - a field notice is stamped AFTER renaming, or both notices name "HK" and
//     the second node's is lost.
func TestTheReportSaysWhichPastedLinksAreTheSameNode(t *testing.T) {
	for _, test := range []struct {
		name    string
		payload string
		same    bool
		why     string
	}{
		{
			name:    "the same link twice",
			payload: "anytls://pw@a.example:443#HK\nanytls://pw@a.example:443#HK",
			same:    true,
			why:     "nothing distinguishes them, so the person pasted one node twice",
		},
		{
			name:    "one name, two servers",
			payload: "anytls://pw@a.example:443#HK\nanytls://pw@b.example:443#HK",
			same:    false,
			why:     "an airport reuses a label across servers; these are two nodes",
		},
		{
			name:    "one server, two names",
			payload: "anytls://pw@a.example:443#HK\nanytls://pw@a.example:443#TW",
			same:    false,
			why:     "two exits behind one front door; collapsing takes away a choice the person was given",
		},
		{
			name:    "one server, two passwords",
			payload: "anytls://pw1@a.example:443#HK\nanytls://pw2@a.example:443#HK",
			same:    false,
			why:     "same address, different credentials, and only one of them may work",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			report := readImportReport(t, []byte(test.payload))
			if len(report.Proxies) != 2 {
				t.Fatalf("expected two nodes, got %d: %#v", len(report.Proxies), report)
			}
			if len(report.Identities) != len(report.Proxies) {
				t.Fatalf("%d identities for %d nodes; the two arrays must be built together",
					len(report.Identities), len(report.Proxies))
			}
			for index, identity := range report.Identities {
				if identity == "" {
					t.Fatalf("node %d has no identity, so the client cannot judge it at all", index)
				}
			}
			if same := report.Identities[0] == report.Identities[1]; same != test.same {
				t.Fatalf("identities equal = %v, want %v -- %s", same, test.same, test.why)
			}
		})
	}
}
