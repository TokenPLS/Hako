package hako

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/TokenPLS/Hako/config"
)

// The new plan-layer refusal, held against real configurations rather than
// fixtures written to exercise it.
//
// upstreamRefusedOutboundOption was added on 2026-08-27 to stop the plan
// promising a start that mihomo then refuses. Its danger runs the other way: a
// predicate that fires on something mihomo accepts is a configuration a user
// has today and loses tomorrow, and no amount of hand-written cases would
// reveal that -- they only cover what their author already suspected.
//
// So: every configuration in the corpus, which is real subscriptions people
// actually run. Whenever this predicate fires, mihomo must refuse the same
// document. If it fires and mihomo accepts, the refusal is an invention and
// the user loses a working configuration.
//
// Fixture-based tests and this one fail differently on purpose. The fixtures
// say "this input must behave this way"; this says "whatever is out there, we
// do not get ahead of upstream."
func TestNoRealConfigurationIsRefusedAheadOfUpstream(t *testing.T) {
	corpus := realSubscriptionCorpus
	entries, err := os.ReadDir(corpus)
	if err != nil {
		// Real subscriptions live in the client tree, which never ships. Skip
		// is the honest outcome there; failing would report a missing input as
		// a defect in the kernel.
		t.Skipf("the real-subscription corpus is not present in this tree: %v", err)
	}

	checked, fired, proxies := 0, 0, 0
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}
		name := entry.Name()
		t.Run(name, func(t *testing.T) {
			document, err := os.ReadFile(filepath.Join(corpus, name))
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			raw, err := config.UnmarshalRawConfig(document)
			if err != nil {
				t.Skipf("not a document this test can judge: %v", err)
			}
			checked++
			proxies += len(raw.Proxy)

			issues := upstreamRefusedOutboundOptions(raw)
			if len(issues) == 0 {
				return
			}
			fired++
			if _, err := config.ParseRawConfig(raw); err == nil {
				t.Errorf("this tree refuses %d option value(s) that mihomo accepts, so a working "+
					"configuration would stop working: %+v", len(issues), issues)
			}
		})
	}

	// The sweep has to have swept. A corpus that silently stopped being read --
	// moved, renamed, filtered to nothing -- looks exactly like a clean run.
	if checked == 0 {
		t.Fatal("no configuration was judged; the corpus path is wrong and this test proves nothing")
	}
	if proxies == 0 {
		t.Fatal("the corpus was read but carries no outbound the predicate can reach, so a green here " +
			"says nothing about it")
	}

	// What "fired on 0" is worth, stated so it is not read as more.
	//
	// Poisoning the predicate to fire on every hysteria2 outbound -- 18 of them
	// across this corpus -- turns exactly ONE document red, because a violation
	// is only counted when mihomo ACCEPTS the same document, and most of these
	// fail config.Parse standalone for reasons of their own (geodata that is not
	// staged here, providers that are not materialized). So this catches a false
	// positive on a configuration that stands on its own, and is blind to one
	// that only fires on a document mihomo rejects for an unrelated reason.
	//
	// An earlier poison aimed at `type: ss` caught nothing at all and looked
	// like the same clean result. The corpus has no ss outbound: it is
	// anytls/hysteria2/direct. A poison aimed where the data is not is not a
	// poison, and it reads identically to a gate that works.
	t.Logf("judged %d real configurations carrying %d outbounds; the predicate fired on %d",
		checked, proxies, fired)
}
