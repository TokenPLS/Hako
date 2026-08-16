package hako

import (
	"encoding/json"
	"testing"

	"github.com/metacubex/http/httptest"
	"github.com/TokenPLS/Hako/component/resolver"
	"github.com/TokenPLS/Hako/dns"
)

// The endpoint explains and does not resolve, so it is reachable whether or not the tunnel
// is up -- which is the point: a reader debugging "why does this name go there" is often
// doing it because something is wrong.
func decodeExplain(t *testing.T, target string) (map[string]any, int) {
	t.Helper()
	recorder := httptest.NewRecorder()
	serveDNSExplain(recorder, httptest.NewRequest("GET", target, nil))
	var body map[string]any
	if recorder.Body.Len() > 0 {
		if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
			t.Fatalf("response is not JSON: %s", recorder.Body.String())
		}
	}
	return body, recorder.Code
}

func TestExplainRouteRejectsAMissingDomain(t *testing.T) {
	_, status := decodeExplain(t, "/hako/v1/dns/explain")
	if status == 200 {
		t.Fatal("a request with no domain was accepted; there is nothing to explain")
	}
}

// With no resolver the honest answer is that DNS is not running, not an empty explanation
// that reads like "no policy matched".
func TestExplainRouteSaysWhenDNSIsNotRunning(t *testing.T) {
	previous := resolver.DefaultResolver
	resolver.DefaultResolver = nil
	t.Cleanup(func() { resolver.DefaultResolver = previous })

	_, status := decodeExplain(t, "/hako/v1/dns/explain?domain=example.com")
	if status == 200 {
		t.Fatal("explained a name while no resolver exists; an empty explanation would read " +
			"as 'nothing matched' rather than 'DNS is off'")
	}
}

// The route has to accept what a running core actually holds, and only this test says so.
//
// The two tests above assert the endpoint REFUSES: no domain, no resolver. Both passed
// while the endpoint refused every real core too, because nothing here ever built the
// thing hub/executor builds and asked for a 200. Asserting only the failure paths is how
// an endpoint ships that can never succeed.
//
// dns.NewResolver returns a dns.Resolvers VALUE (dns/resolver.go:581) which
// hub/executor/executor.go:335 assigns straight into resolver.DefaultResolver. Resolvers
// embeds *Resolver, and embedding is not identity: a type assertion compares the dynamic
// type exactly, so asserting *dns.Resolver against it is false forever.
func TestExplainRouteAcceptsWhatExecutorAssigns(t *testing.T) {
	previous := resolver.DefaultResolver
	t.Cleanup(func() { resolver.DefaultResolver = previous })

	// Built the way executor builds it, so the dynamic type is the real one.
	resolver.DefaultResolver = dns.NewResolver(dns.Config{
		Main: []dns.NameServer{{Net: "", Addr: "223.5.5.5:53"}},
	})

	body, status := decodeExplain(t, "/hako/v1/dns/explain?domain=example.com")
	if status != 200 {
		t.Fatalf("a running core was told its DNS is not running: status %d, body %v",
			status, body)
	}
	// The explanation has to be populated, not merely present: a 200 carrying no
	// candidates would mean the resolver was reached and then not read.
	candidates, _ := body["candidates"].([]any)
	if len(candidates) == 0 {
		t.Fatalf("explained a name with no candidate resolvers: %v", body)
	}
}

// probe is opt-in and off by default. A reader pressing the button repeatedly must not be
// sending queries they did not ask for.
func TestExplainRouteDefaultsToNoProbe(t *testing.T) {
	if probeRequested(httptest.NewRequest("GET", "/x?domain=a.com", nil)) {
		t.Fatal("probe defaulted to on")
	}
	if !probeRequested(httptest.NewRequest("GET", "/x?domain=a.com&probe=1", nil)) {
		t.Fatal("probe=1 was not honoured")
	}
	if probeRequested(httptest.NewRequest("GET", "/x?domain=a.com&probe=0", nil)) {
		t.Fatal("probe=0 was treated as on")
	}
}
