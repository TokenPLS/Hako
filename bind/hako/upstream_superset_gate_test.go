package hako

//
//

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/TokenPLS/Hako/common/convert"
)

// upstreamParses reports whether mihomo's own converter turns this single line
// into at least one proxy. It is the oracle: not our reading of what upstream
// supports, but upstream's function, on this exact input.
func upstreamParses(link string) bool {
	proxies, err := convert.ConvertsV2Ray([]byte(link))
	return err == nil && len(proxies) > 0
}

// oursParse runs the subscription-context side of the comparison: that is
// the path whose tolerance must never fall below upstream's, because a
// payload it cannot read is what step two of the substore plan would stage
// verbatim. The interactive path is strict on purpose and is not this gate's
// subject.
func oursParse(link string) (int, error) {
	proxies, err := convertProxyShareLinks([]byte(link), true)
	return len(proxies), err
}

func TestOurShareLinkVocabularyIsNeverNarrowerThanUpstream(t *testing.T) {
	links := shareLinkSupersetCorpus(t)
	if len(links) == 0 {
		t.Fatal("empty corpus: a superset claim proven over nothing is not proven")
	}
	// The corpus has to contain links upstream really does parse, or a green
	// run means the oracle never spoke. Counted, not assumed.
	oracleSpoke := 0
	var narrower []string
	for _, link := range links {
		if !upstreamParses(link) {
			continue
		}
		oracleSpoke++
		count, err := oursParse(link)
		if err != nil || count == 0 {
			reason := "returned no proxies"
			if err != nil {
				reason = err.Error()
			}
			narrower = append(narrower, link+"\n        -> "+reason)
		}
	}
	if oracleSpoke == 0 {
		t.Fatal("upstream parsed none of the corpus; this gate measured nothing")
	}
	t.Logf("upstream parsed %d of %d corpus links", oracleSpoke, len(links))
	for _, item := range narrower {
		t.Errorf("upstream parses this and we do not:\n        %s", item)
	}
	if len(narrower) > 0 {
		t.Errorf(
			"%d link(s) upstream can read and we cannot; staging such a payload "+
				"verbatim would hand mihomo nodes that never passed the egress strip",
			len(narrower))
	}
}

// shareLinkSupersetCorpus is the emitted Shadowrocket corpus plus links whose
// only unusual feature is a query field -- the axis a scheme-level comparison
// cannot see.
func shareLinkSupersetCorpus(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile("testdata/shadowrocket-2.2.90-3378-emitted-corpus.json")
	if err != nil {
		t.Fatalf("read the emitted corpus: %v", err)
	}
	var corpus exporterEmittedCorpus
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatalf("corpus: %v", err)
	}
	links := make([]string, 0, len(corpus.Records)+8)
	for _, record := range corpus.Records {
		links = append(links, record.Exported)
	}
	links = append(links,
		// Unknown query fields: upstream ignores what it does not know.
		"ss://YWVzLTI1Ni1nY206cGFzcw@198.51.100.10:8388?unknown-field=1#N1",
		"trojan://pass@198.51.100.11:443?sni=a.invalid&nonsense=x#N2",
		"vless://11111111-1111-1111-1111-111111111111@198.51.100.12:443?type=ws&security=tls&whatever=9#N3",
		// Casing and padding variants upstream tolerates.
		"SS://YWVzLTI1Ni1nY206cGFzcw@198.51.100.13:8388#N4",
		"hysteria2://pass@198.51.100.14:443?insecure=1&obfs=salamander&obfs-password=p#N5",
	)
	return links
}
