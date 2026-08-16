package hako

import (
	"strings"
	"testing"

	"github.com/TokenPLS/Hako/component/resolver"
	C "github.com/TokenPLS/Hako/constant"
	"github.com/TokenPLS/Hako/dns"

	D "github.com/miekg/dns"
)

// Everything here goes through dns.NewResolver, the constructor hub/executor uses.
//
// The endpoint shipped able to return 503 and nothing else, and four tests passed over it,
// because every one of them built its resolver by hand -- dns/explain_test.go:46 constructs
// &Resolver{main:..., policy:..., cache:...} with unexported fields, an object no running
// core has ever held. Hand-built doubles cannot catch a defect that lives in the difference
// between the double and the real thing, and that is exactly where this one lived.
//
// So these tests are not allowed to name a type. They configure the resolver the way a
// config file configures it (config/config.go:1404 builds dns.Policy the same way), install
// it the way executor installs it, and ask the endpoint the questions a reader asks.

// installResolver builds and installs a resolver through the production path and returns
// nothing, so a test cannot accidentally reach past the endpoint into the object.
func installResolver(t *testing.T, config dns.Config) {
	t.Helper()
	previous := resolver.DefaultResolver
	t.Cleanup(func() { resolver.DefaultResolver = previous })
	resolver.DefaultResolver = dns.NewResolver(config)
}

func nameservers(addresses ...string) []dns.NameServer {
	servers := make([]dns.NameServer, 0, len(addresses))
	for _, address := range addresses {
		servers = append(servers, dns.NameServer{Addr: address})
	}
	return servers
}

func explainOK(t *testing.T, target string) map[string]any {
	t.Helper()
	body, status := decodeExplain(t, target)
	if status != 200 {
		t.Fatalf("GET %s: status %d, body %v", target, status, body)
	}
	return body
}

func candidateList(t *testing.T, body map[string]any) []string {
	t.Helper()
	raw, _ := body["candidates"].([]any)
	list := make([]string, 0, len(raw))
	for _, item := range raw {
		text, _ := item.(string)
		list = append(list, text)
	}
	return list
}

// The reader's first question -- "which nameservers is this name using" -- answered for a
// name no policy claims.
func TestExplainLiveReportsMainNameserversInOrder(t *testing.T) {
	installResolver(t, dns.Config{Main: nameservers("223.5.5.5:53", "119.29.29.29:53")})

	body := explainOK(t, "/hako/v1/dns/explain?domain=example.com")
	if body["source"] != "main" {
		t.Fatalf("a name no policy claims was not attributed to main: %v", body["source"])
	}
	candidates := candidateList(t, body)
	if len(candidates) != 2 {
		t.Fatalf("two configured nameservers produced %d candidates: %v", len(candidates), candidates)
	}
	// Order is the reader's information: it is the order the race starts in.
	if !strings.Contains(candidates[0], "223.5.5.5") || !strings.Contains(candidates[1], "119.29.29.29") {
		t.Fatalf("candidates are not in configuration order: %v", candidates)
	}
}

// The second question -- "what rule caught it" -- for an exact nameserver-policy key.
func TestExplainLiveReportsAnExactPolicyKey(t *testing.T) {
	installResolver(t, dns.Config{
		Main: nameservers("223.5.5.5:53"),
		Policy: []dns.Policy{
			{Domain: "example.com", NameServers: nameservers("1.1.1.1:53")},
		},
	})

	body := explainOK(t, "/hako/v1/dns/explain?domain=example.com")
	if body["source"] != "policy" {
		t.Fatalf("a name claimed by nameserver-policy was attributed to %v", body["source"])
	}
	if body["matchedRule"] != "example.com" {
		t.Fatalf("matched rule reported as %v, not the key the config wrote", body["matchedRule"])
	}
	candidates := candidateList(t, body)
	if len(candidates) != 1 || !strings.Contains(candidates[0], "1.1.1.1") {
		t.Fatalf("policy candidates are the main nameservers, not the policy's: %v", candidates)
	}
}

// The wildcard form, which is what people actually write.
func TestExplainLiveReportsAWildcardPolicyKey(t *testing.T) {
	installResolver(t, dns.Config{
		Main: nameservers("223.5.5.5:53"),
		Policy: []dns.Policy{
			{Domain: "+.example.com", NameServers: nameservers("1.1.1.1:53")},
		},
	})

	body := explainOK(t, "/hako/v1/dns/explain?domain=api.example.com")
	if body["source"] != "policy" {
		t.Fatalf("a subdomain under a wildcard policy was attributed to %v", body["source"])
	}
	rule, _ := body["matchedRule"].(string)
	if !strings.Contains(rule, "example.com") {
		t.Fatalf("wildcard policy reported as %q, which does not name the key", rule)
	}
}

// A name outside the policy must NOT be claimed by it. Without this, a matcher that
// reported "policy" for everything would pass the two tests above.
func TestExplainLiveDoesNotClaimNamesOutsideThePolicy(t *testing.T) {
	installResolver(t, dns.Config{
		Main: nameservers("223.5.5.5:53"),
		Policy: []dns.Policy{
			{Domain: "+.example.com", NameServers: nameservers("1.1.1.1:53")},
		},
	})

	body := explainOK(t, "/hako/v1/dns/explain?domain=example.org")
	if body["source"] != "main" {
		t.Fatalf("an unrelated name was claimed by the policy: %v", body)
	}
	if body["matchedRule"] != nil && body["matchedRule"] != "" {
		t.Fatalf("an unrelated name reported a matched rule: %v", body["matchedRule"])
	}
	candidates := candidateList(t, body)
	if len(candidates) != 1 || !strings.Contains(candidates[0], "223.5.5.5") {
		t.Fatalf("an unrelated name did not fall through to main: %v", candidates)
	}
}

// Default is no probe, and that has to be visible in the body rather than inferred from an
// absent answer -- the whole reason `probed` is reported.
func TestExplainLiveSendsNothingByDefault(t *testing.T) {
	installResolver(t, dns.Config{Main: nameservers("203.0.113.1:53")})

	body := explainOK(t, "/hako/v1/dns/explain?domain=example.com")
	if body["probed"] != false {
		t.Fatalf("probed reported as %v without probe=1", body["probed"])
	}
	if body["answeredBy"] != nil && body["answeredBy"] != "" {
		t.Fatalf("named a winner without sending a query: %v", body["answeredBy"])
	}
	if body["answer"] != nil {
		t.Fatalf("returned an answer without sending a query: %v", body["answer"])
	}
	// 203.0.113.0/24 is TES and unroutable, so this test cannot pass by
	// accidentally reaching a real server.
}

// The types this must accept are NOT this route's own list -- that is the defect the
// previous version of this test had, and it passed the whole time the route was refusing
// half of what the screen offers.
//
// A test that enumerates what the code allows can only confirm the code against itself.
// The set that matters belongs to the consumer, so it is taken from upstream's own table:
// /dns/query accepts anything in D.StringToType (hub/route/dns.go:32), the two endpoints
// sit on one screen, and a reader who can ask /dns/query for MX and gets an answer must
// not have the route section silently vanish.
//
// It is also not a limit the resolver imposes. isIPRequest is A, AAAA and CNAME
// (dns/util.go:124); TXT, MX, NS, SRV and PTR all fall to the same matchPolicy and the
// same batchExchange (dns/resolver.go:270). Whatever this reports for TXT is exactly what
// it would report for MX.
func TestExplainLiveAcceptsEveryTypeTheOtherEndpointDoes(t *testing.T) {
	installResolver(t, dns.Config{Main: nameservers("223.5.5.5:53")})

	// The picker's set, named explicitly so a reader of this test can see what a screen
	// actually offers -- and every one checked against upstream's table rather than
	// assumed to exist.
	for _, queryType := range []string{"A", "AAAA", "CNAME", "TXT", "MX", "NS", "SRV", "PTR"} {
		if _, known := D.StringToType[queryType]; !known {
			t.Fatalf("%s is not a type upstream knows, so this test is asserting fiction", queryType)
		}
		body, status := decodeExplain(t, "/hako/v1/dns/explain?domain=example.com&type="+queryType)
		if status != 200 {
			t.Fatalf("asked to explain %s and got %d: %v — the route section vanishes for "+
				"this type while /dns/query answers it", queryType, status, body)
		}
		if body["type"] != queryType {
			t.Fatalf("asked for %s and was told %v", queryType, body["type"])
		}
		// A route is not always a list of resolvers. Some questions are answered ABOVE the
		// resolver -- AAAA when dns.ipv6 is off, which mihomo defaults it to -- and for
		// those the honest answer is the source with no candidates. What must never happen
		// is a 400, or a 200 that says nothing at all.
		source, _ := body["source"].(string)
		if source == "" {
			t.Fatalf("%s was accepted but explained nothing: %v", queryType, body)
		}
		if source == "main" || source == "policy" || source == "fallback" {
			if len(candidateList(t, body)) == 0 {
				t.Fatalf("%s was attributed to %s and named no resolver: %v", queryType, source, body)
			}
		}
	}
	// Omitted type defaults to A rather than failing.
	if body := explainOK(t, "/hako/v1/dns/explain?domain=example.com"); body["type"] != "A" {
		t.Fatalf("an omitted type produced %v", body["type"])
	}
	// A name upstream does not know is still refused, and for a stated reason.
	if _, status := decodeExplain(t, "/hako/v1/dns/explain?domain=example.com&type=NOTATYPE"); status == 200 {
		t.Fatal("accepted a query type that does not exist")
	}
}

// fallback-domain-filter is the shape every anti-leak config in the wild is built on, so a
// reader whose name is routed to fallback has to be told that rather than shown "main" and
// a list of nameservers that never see the query.
type explainDomainFilter struct{ suffix string }

func (f explainDomainFilter) MatchDomain(domain string) bool {
	return domain == f.suffix || strings.HasSuffix(domain, "."+f.suffix)
}

func TestExplainLiveReportsTheFallbackBranch(t *testing.T) {
	installResolver(t, dns.Config{
		Main:                 nameservers("223.5.5.5:53"),
		Fallback:             nameservers("1.1.1.1:53"),
		FallbackDomainFilter: []C.DomainMatcher{explainDomainFilter{suffix: "example.com"}},
	})

	body := explainOK(t, "/hako/v1/dns/explain?domain=api.example.com")
	if body["source"] != "fallback" {
		t.Fatalf("a name the fallback filter claims was attributed to %v", body["source"])
	}
	candidates := candidateList(t, body)
	if len(candidates) != 1 || !strings.Contains(candidates[0], "1.1.1.1") {
		t.Fatalf("fallback candidates are not the fallback nameservers: %v", candidates)
	}

	// And a name the filter does not claim must still go to main, or "fallback" would be
	// reported for everything the moment a filter exists.
	other := explainOK(t, "/hako/v1/dns/explain?domain=example.org")
	if other["source"] != "main" {
		t.Fatalf("a name outside the fallback filter was attributed to %v", other["source"])
	}
}

// The resolver a running core installs is a dns.Resolvers value; a bare *dns.Resolver comes
// from NewResolverFromClient. Both have to work, and a foreign value must not.
func TestExplainableResolverAcceptsEveryShapeThatCanBeInstalled(t *testing.T) {
	installed := dns.NewResolver(dns.Config{Main: nameservers("223.5.5.5:53")})
	if explainableResolver(installed) == nil {
		t.Fatal("rejected the dns.Resolvers value hub/executor installs")
	}
	if explainableResolver(&installed) == nil {
		t.Fatal("rejected a *dns.Resolvers")
	}
	if explainableResolver(installed.Resolver) == nil {
		t.Fatal("rejected the bare *dns.Resolver NewResolverFromClient returns")
	}
	if explainableResolver(nil) != nil {
		t.Fatal("accepted nil")
	}
	if explainableResolver((*dns.Resolvers)(nil)) != nil {
		t.Fatal("accepted a typed-nil *dns.Resolvers, which would panic on use")
	}
	if explainableResolver("not a resolver") != nil {
		t.Fatal("accepted a value that is not a resolver at all")
	}
}
