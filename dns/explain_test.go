package dns

import (
	"context"
	"testing"
	"time"

	"net/netip"

	"github.com/TokenPLS/Hako/component/resolver"
	"github.com/TokenPLS/Hako/component/trie"

	D "github.com/miekg/dns"
)

// without becoming a second way to resolve.
//
// The split that makes it possible: every "why" except the race is decided by pure
// functions. matchPolicy (resolver.go:316) reads r.policy and compares a domain;
// shouldOnlyQueryFallback (resolver.go:334) reads the filters; the rcode short-circuit is a
// type assertion. None of them touches the network, the cache, or shared state, so the
// default explanation costs nothing and cannot perturb anything.
//
// Only "who won" needs an exchange, which is why it is opt-in -- and why it must not go
// through ExchangeContext: r.group.DoChan deduplicates by question, so a probe for a name
// the tunnel is resolving would be folded into the tunnel's execution and come back with
// shared = true, at which point the winner is unknowable. The probe therefore reaches
// batchExchange directly.

// answeringClient returns a fixed answer and counts calls, so a test can tell a computed
// explanation from one that went to the network.
type answeringClient struct{ calls int }

func (c *answeringClient) ExchangeContext(_ context.Context, m *D.Msg) (*D.Msg, error) {
	c.calls++
	reply := new(D.Msg)
	reply.SetReply(m)
	reply.Answer = []D.RR{&D.A{Hdr: D.RR_Header{
		Name: m.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 300,
	}}}
	return reply, nil
}
func (c *answeringClient) Address() string  { return "answering" }
func (c *answeringClient) ResetConnection() {}

func explainResolver(t *testing.T, policy []dnsPolicy, main []dnsClient) *Resolver {
	t.Helper()
	return &Resolver{main: main, policy: policy, cache: Config{}.newCache()}
}

func questionFor(name string) *D.Msg {
	m := new(D.Msg)
	m.SetQuestion(name, D.TypeA)
	return m
}

// A domain covered by nameserver-policy reports which key matched, not merely that a
// policy existed -- a reader with several policy entries needs to know which one caught
// their name.
func TestExplainReportsTheMatchedPolicyKey(t *testing.T) {
	policyClient := &answeringClient{}
	tree := trie.New[[]dnsClient]()
	if err := tree.Insert("+.corp.internal", []dnsClient{policyClient}); err != nil {
		t.Fatal(err)
	}
	resolver := explainResolver(t,
		[]dnsPolicy{domainTriePolicy{tree}},
		[]dnsClient{&answeringClient{}})

	explanation := resolver.Explain(context.Background(), questionFor("host.corp.internal."), false)

	if explanation.Source != ExplainSourcePolicy {
		t.Fatalf("source = %q, want policy", explanation.Source)
	}
	if explanation.MatchedRule == "" {
		t.Fatal("the matched policy key is empty; 'a policy matched' without saying which " +
			"is the answer the reader already had")
	}
	if len(explanation.Candidates) == 0 {
		t.Fatal("no candidate resolvers reported")
	}
}

// A name no policy covers falls to the main group, and the explanation says so rather than
// leaving the reader to infer it from an absence.
func TestExplainReportsMainWhenNoPolicyMatches(t *testing.T) {
	main := &answeringClient{}
	resolver := explainResolver(t, nil, []dnsClient{main})

	explanation := resolver.Explain(context.Background(), questionFor("example.com."), false)

	if explanation.Source != ExplainSourceMain {
		t.Fatalf("source = %q, want main", explanation.Source)
	}
	if len(explanation.Candidates) != 1 || explanation.Candidates[0] != main.Address() {
		t.Fatalf("candidates = %v, want the main client's address", explanation.Candidates)
	}
}

// The default explanation costs no query. This is the property that lets a reader press the
// button freely, and the one that keeps the tunnel's resolve path untouched.
func TestExplainWithoutProbeSendsNothing(t *testing.T) {
	main := &answeringClient{}
	resolver := explainResolver(t, nil, []dnsClient{main})

	explanation := resolver.Explain(context.Background(), questionFor("example.com."), false)

	if main.calls != 0 {
		t.Fatalf("upstream was called %d times without probe; the default explanation is "+
			"computed from pure functions and must send nothing", main.calls)
	}
	if explanation.Answer != nil {
		t.Fatal("an answer was reported without a probe: the asymmetry is the honest signal " +
			"for whether a query happened")
	}
}

// With the probe, the winner is known and the answer comes from the same exchange that
// produced it. Reporting an address from one exchange beside a resolver from another is the
// failure this request exists to remove.
func TestExplainProbeReportsWinnerAndItsOwnAnswer(t *testing.T) {
	main := &answeringClient{}
	resolver := explainResolver(t, nil, []dnsClient{main})

	explanation := resolver.Explain(context.Background(), questionFor("example.com."), true)

	if main.calls != 1 {
		t.Fatalf("upstream called %d times, want 1", main.calls)
	}
	if explanation.AnsweredBy != main.Address() {
		t.Fatalf("answeredBy = %q, want %q", explanation.AnsweredBy, main.Address())
	}
	if explanation.Answer == nil || len(explanation.Answer.Answer) == 0 {
		t.Fatal("the probe resolved but reported no answer; withholding it would make the " +
			"client issue a second, different exchange to get one")
	}
}

// The probe must not be deduplicated into whatever the tunnel is doing. If it went through
// ExchangeContext, a concurrent resolve of the same name would swallow it and the winner
// would be unknowable -- so the probe must not populate the shared cache either, which is
// how a diagnostic would start changing what the tunnel serves.
func TestExplainProbeDoesNotDisturbTheCache(t *testing.T) {
	main := &answeringClient{}
	resolver := explainResolver(t, nil, []dnsClient{main})
	question := questionFor("example.com.")

	resolver.Explain(context.Background(), question, true)

	if _, _, hit := getMsgFromCache(resolver.cache, question.Question[0]); hit {
		t.Fatal("the probe wrote into the cache; a diagnostic that changes what the tunnel " +
			"serves next is no longer a diagnostic")
	}
}

// An rcode:// entry answers before any network client runs, and the explanation says so
// with no candidates raced.
func TestExplainReportsRcodeShortCircuit(t *testing.T) {
	resolver := explainResolver(t, nil, []dnsClient{newRCodeClient("name_error")})

	explanation := resolver.Explain(context.Background(), questionFor("blocked.example.com."), false)

	if explanation.Source != ExplainSourceRcode {
		t.Fatalf("source = %q, want rcode", explanation.Source)
	}
}

// A cached name is reported as cached, with when it expires -- and expiry can be in the
// past, because since an expired entry is still served (TTL 1) while a refresh runs.
// The reader is better served by "expired 3 minutes ago, still in use" than by a negative
// countdown.
func TestExplainReportsCacheIncludingStale(t *testing.T) {
	resolver := explainResolver(t, nil, []dnsClient{&answeringClient{}})
	question := questionFor("stale.example.com.")
	stale := new(D.Msg)
	stale.SetReply(question)
	stale.Answer = []D.RR{&D.A{Hdr: D.RR_Header{
		Name: "stale.example.com.", Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60,
	}}}
	resolver.cache.SetWithExpire(question.Question[0].String(), stale,
		time.Now().Add(-3*time.Minute))

	explanation := resolver.Explain(context.Background(), question, false)

	if explanation.Source != ExplainSourceCache {
		t.Fatalf("source = %q, want cache", explanation.Source)
	}
	if !explanation.CacheStale {
		t.Fatal("an expired entry was reported as fresh; it is served anyway, " +
			"so the reader has to be told it is old rather than shown a fresh-looking hit")
	}
	if explanation.CacheExpiresAt == nil {
		t.Fatal("no expiry reported for a cache hit")
	}
}

// fake-ip answers most names in a fake-ip configuration without the resolver being
// reached at all: newHandler puts withFakeIP above withResolver (dns/middleware.go:241),
// so naming main's four DoH servers beside that answer is a confident wrong sentence.
type fakeIPEnhancerStub struct {
	enabled  bool
	skipped  map[string]bool
	useHosts bool
	ipv6     bool
}

func (s fakeIPEnhancerStub) FakeIPEnabled() bool                    { return s.enabled }
func (s fakeIPEnhancerStub) MappingEnabled() bool                   { return false }
func (s fakeIPEnhancerStub) IsFakeIP(netip.Addr) bool               { return false }
func (s fakeIPEnhancerStub) IsFakeBroadcastIP(netip.Addr) bool      { return false }
func (s fakeIPEnhancerStub) IsExistFakeIP(netip.Addr) bool          { return false }
func (s fakeIPEnhancerStub) FindHostByIP(netip.Addr) (string, bool) { return "", false }
func (s fakeIPEnhancerStub) FlushFakeIP() error                     { return nil }
func (s fakeIPEnhancerStub) InsertHostByIP(netip.Addr, string)      {}
func (s fakeIPEnhancerStub) StoreFakePoolState()                    {}
func (s fakeIPEnhancerStub) UseHosts() bool                         { return s.useHosts }
func (s fakeIPEnhancerStub) ShouldSkipFakeIP(host string) bool      { return s.skipped[host] }
func (s fakeIPEnhancerStub) IPv6() bool                             { return s.ipv6 }

// The stub must satisfy the same interface the running core does, or it silently
// stops satisfying it after a method is added and every test here quietly starts
// exercising the aware==nil path instead. That is how the production type nearly
// shipped unasserted, and a test double can drift the same way.
var _ middlewareAware = fakeIPEnhancerStub{}

func installEnhancer(t *testing.T, stub fakeIPEnhancerStub) {
	t.Helper()
	previous := resolver.DefaultHostMapper
	resolver.DefaultHostMapper = stub
	t.Cleanup(func() { resolver.DefaultHostMapper = previous })
}

func TestExplainReportsFakeIPRatherThanResolversNobodyAsks(t *testing.T) {
	installEnhancer(t, fakeIPEnhancerStub{enabled: true})
	r := explainResolver(t, nil, []dnsClient{&answeringClient{}})

	explanation := r.Explain(context.Background(), typedQuestion("github.com", D.TypeA), false)
	if explanation.Source != ExplainSourceFakeIP {
		t.Fatalf("a name fake-ip answers was attributed to %q", explanation.Source)
	}
	if len(explanation.Candidates) != 0 {
		t.Fatalf("named %d resolvers beside an answer no resolver produced: %v",
			len(explanation.Candidates), explanation.Candidates)
	}
}

// A name the filter sends down to the resolver must still be explained normally, or the
// new branch would swallow the case the endpoint was built for.
func TestExplainStillExplainsNamesFakeIPSkips(t *testing.T) {
	installEnhancer(t, fakeIPEnhancerStub{enabled: true, skipped: map[string]bool{"cn.example": true}})
	r := explainResolver(t, nil, []dnsClient{&answeringClient{}})

	explanation := r.Explain(context.Background(), typedQuestion("cn.example", D.TypeA), false)
	if explanation.Source == ExplainSourceFakeIP {
		t.Fatal("a name fake-ip skips was reported as answered by fake-ip")
	}
	if len(explanation.Candidates) == 0 {
		t.Fatal("a name that does reach the resolver was explained with no candidates")
	}
}

// Only A and AAAA. TXT and MX fall through withFakeIP's switch to the resolver
// (dns/middleware.go:180), so they are explained the way they always were.
func TestExplainDoesNotClaimFakeIPForTypesItDoesNotAnswer(t *testing.T) {
	installEnhancer(t, fakeIPEnhancerStub{enabled: true})
	r := explainResolver(t, nil, []dnsClient{&answeringClient{}})

	for _, qType := range []uint16{D.TypeTXT, D.TypeMX} {
		explanation := r.Explain(context.Background(), typedQuestion("github.com", qType), false)
		if explanation.Source == ExplainSourceFakeIP {
			t.Fatalf("type %d was claimed by fake-ip, which never answers it", qType)
		}
	}
}

// With fake-ip off, nothing changes.
func TestExplainIsUnchangedWithoutFakeIP(t *testing.T) {
	installEnhancer(t, fakeIPEnhancerStub{enabled: false})
	r := explainResolver(t, nil, []dnsClient{&answeringClient{}})

	explanation := r.Explain(context.Background(), typedQuestion("github.com", D.TypeA), false)
	if explanation.Source == ExplainSourceFakeIP {
		t.Fatal("claimed fake-ip in a configuration that does not use it")
	}
}

func typedQuestion(name string, qType uint16) *D.Msg {
	m := new(D.Msg)
	m.SetQuestion(D.Fqdn(name), qType)
	return m
}

// The hosts branch shipped with no test at all, while the commit that added it claimed
// "each bound tested". Deleting the whole block passed every suite in the repository.
//
// withHosts runs FIRST in the chain (dns/middleware.go:237) and answers A/AAAA/CNAME from
// resolver.DefaultHosts without the resolver being reached, so a name in `hosts:` was
// being explained as `main` with a list of nameservers that never see it.
func TestExplainReportsHostsRatherThanResolversNobodyAsks(t *testing.T) {
	previousHosts := resolver.DefaultHosts
	tree := trie.New[resolver.HostValue]()
	value, err := resolver.NewHostValue([]string{"198.51.100.7"})
	if err != nil {
		t.Fatal(err)
	}
	if err := tree.Insert("pinned.example", value); err != nil {
		t.Fatal(err)
	}
	resolver.DefaultHosts = resolver.NewHosts(tree)
	t.Cleanup(func() { resolver.DefaultHosts = previousHosts })

	installEnhancer(t, fakeIPEnhancerStub{useHosts: true})
	r := explainResolver(t, nil, []dnsClient{&answeringClient{}})

	explanation := r.Explain(context.Background(), typedQuestion("pinned.example", D.TypeA), false)
	if explanation.Source != ExplainSourceHosts {
		t.Fatalf("a name answered from hosts was attributed to %q", explanation.Source)
	}
	if len(explanation.Candidates) != 0 {
		t.Fatalf("named %d resolvers beside an answer no resolver produced: %v",
			len(explanation.Candidates), explanation.Candidates)
	}

	// A name hosts does not hold must still reach the resolver, or the branch would
	// swallow everything the moment any hosts entry exists.
	other := r.Explain(context.Background(), typedQuestion("elsewhere.example", D.TypeA), false)
	if other.Source == ExplainSourceHosts {
		t.Fatal("a name hosts does not hold was attributed to hosts")
	}
	if len(other.Candidates) == 0 {
		t.Fatal("a name that does reach the resolver was explained with no candidates")
	}
}

// SVCB and HTTPS are answered by withFakeIP too, with an authoritative empty message
// (dns/middleware.go:179-180). iOS asks HTTPS for almost every name it loads, so this is
// not an exotic case -- and probe=1 would have SENT an HTTPS query the tunnel never emits.
func TestExplainReportsFakeIPForTheTypesItAnswersEmpty(t *testing.T) {
	installEnhancer(t, fakeIPEnhancerStub{enabled: true, ipv6: true})
	r := explainResolver(t, nil, []dnsClient{&answeringClient{}})

	for _, qType := range []uint16{D.TypeHTTPS, D.TypeSVCB} {
		explanation := r.Explain(context.Background(), typedQuestion("apple.com", qType), false)
		if explanation.Source != ExplainSourceFakeIP {
			t.Fatalf("type %d is answered empty by withFakeIP but was attributed to %q",
				qType, explanation.Source)
		}
		if len(explanation.Candidates) != 0 {
			t.Fatalf("type %d named %d resolvers that receive nothing", qType, len(explanation.Candidates))
		}
	}
	// A name the filter skips reaches the resolver for these types like anything else.
	installEnhancer(t, fakeIPEnhancerStub{enabled: true, ipv6: true, skipped: map[string]bool{"skipped.example": true}})
	skipped := r.Explain(context.Background(), typedQuestion("skipped.example", D.TypeHTTPS), false)
	if skipped.Source == ExplainSourceFakeIP {
		t.Fatal("a skipped name was claimed by fake-ip for HTTPS")
	}
}

// mihomo defaults dns.ipv6 to false, and withResolver then answers AAAA empty before
// exchanging (dns/middleware.go:205). Every AAAA explanation on a default configuration
// was naming resolvers that are never asked.
func TestExplainReportsTheIPv6GateForAAAA(t *testing.T) {
	installEnhancer(t, fakeIPEnhancerStub{ipv6: false})
	r := explainResolver(t, nil, []dnsClient{&answeringClient{}})

	explanation := r.Explain(context.Background(), typedQuestion("example.com", D.TypeAAAA), false)
	if explanation.Source != ExplainSourceIPv6Disabled {
		t.Fatalf("AAAA with dns.ipv6 off was attributed to %q", explanation.Source)
	}
	if len(explanation.Candidates) != 0 {
		t.Fatalf("named %d resolvers for a question answered above them", len(explanation.Candidates))
	}

	// A is unaffected, and with ipv6 on so is AAAA.
	if a := r.Explain(context.Background(), typedQuestion("example.com", D.TypeA), false); a.Source == ExplainSourceIPv6Disabled {
		t.Fatal("an A question was refused by the ipv6 gate")
	}
	installEnhancer(t, fakeIPEnhancerStub{ipv6: true})
	if on := r.Explain(context.Background(), typedQuestion("example.com", D.TypeAAAA), false); on.Source == ExplainSourceIPv6Disabled {
		t.Fatal("AAAA was refused with ipv6 enabled")
	}
}

// A question answered above the resolver never consults the resolver's cache, so the
// response must not carry a cache expiry beside it.
//
// The peek used to run first and the source was overwritten afterwards, producing two
// true-looking fields that contradict each other: source fake-ip next to "expires at".
func TestExplainDoesNotReportACacheForAnswersAboveTheResolver(t *testing.T) {
	installEnhancer(t, fakeIPEnhancerStub{enabled: true, ipv6: true})
	r := explainResolver(t, nil, []dnsClient{&answeringClient{}})

	// Seed the resolver's cache for the very name we then ask about, so a peek would
	// definitely hit and the assertion cannot pass by the cache simply being empty.
	question := typedQuestion("cached.example", D.TypeA)
	answer := question.Copy()
	answer.Answer = []D.RR{&D.A{
		Hdr: D.RR_Header{Name: question.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 300},
		A:   []byte{203, 0, 113, 9},
	}}
	putMsgToCache(r.cache, question.Question[0], answer)

	explanation := r.Explain(context.Background(), question, false)
	if explanation.Source != ExplainSourceFakeIP {
		t.Fatalf("source = %q, want fake-ip", explanation.Source)
	}
	if explanation.CacheExpiresAt != nil {
		t.Fatalf("reported a cache expiry beside a source that never consults the cache: %v",
			explanation.CacheExpiresAt)
	}
}
