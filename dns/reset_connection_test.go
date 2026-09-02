package dns

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/component/resolver"
	"github.com/TokenPLS/Hako/component/trie"

	D "github.com/miekg/dns"
)

// Resolver.ResetConnection walked r.main, r.fallback and r.defaultResolver, and never
// r.policy -- so a nameserver-policy entry's clients kept their sockets across a path
// change. Reproduced before the fix: main=1 fallback=1 defaultResolver=1 policy=0.
//
// The cost is genuinely small and worth stating so nobody over-claims it: reset is a
// no-op for plain udp/tcp/system/rcode clients, exposure needs a policy-ONLY tls/https/
// quic server, and all three stateful transports self-heal on the first failed exchange.
// Steady state is one degraded query, not dead DNS. It is still a hole, and it is the
// kind that cannot be found by reading the happy path.
//
// sing-box cannot miss one by construction because it walks a transport registry. Our
// shape needs the policy structures to be enumerable, which is what Clients() adds.

type resetCountingClient struct {
	resets atomic.Int64
}

func (c *resetCountingClient) ExchangeContext(ctx context.Context, m *D.Msg) (*D.Msg, error) {
	return nil, context.Canceled
}

func (c *resetCountingClient) Address() string { return "counting" }

func (c *resetCountingClient) ResetConnection() { c.resets.Add(1) }

func TestResetConnectionReachesPolicyClients(t *testing.T) {
	mainClient := &resetCountingClient{}
	fallbackClient := &resetCountingClient{}
	triePolicyClient := &resetCountingClient{}
	matcherPolicyClient := &resetCountingClient{}
	defaultClient := &resetCountingClient{}

	domainTrie := trie.New[[]dnsClient]()
	if err := domainTrie.Insert("policy.example.com", []dnsClient{triePolicyClient}); err != nil {
		t.Fatal(err)
	}

	resolver := &Resolver{
		main:     []dnsClient{mainClient},
		fallback: []dnsClient{fallbackClient},
		policy: []dnsPolicy{
			domainTriePolicy{DomainTrie: domainTrie},
			domainMatcherPolicy{dnsClients: []dnsClient{matcherPolicyClient}},
		},
		defaultResolver: &Resolver{main: []dnsClient{defaultClient}},
	}

	resolver.ResetConnection()

	for name, client := range map[string]*resetCountingClient{
		"main":             mainClient,
		"fallback":         fallbackClient,
		"defaultResolver":  defaultClient,
		"policy (trie)":    triePolicyClient,
		"policy (matcher)": matcherPolicyClient,
	} {
		if got := client.resets.Load(); got != 1 {
			t.Errorf("%s client was reset %d times, want 1", name, got)
		}
	}
}

// TestResetConnectionOnNilAndEmptyIsSafe: ResetConnection is called from the path monitor
// on every applied update, including before any resolver exists, so it must tolerate a nil
// receiver and empty policy structures rather than panicking on a network change.
func TestResetConnectionOnNilAndEmptyIsSafe(t *testing.T) {
	var nilResolver *Resolver
	nilResolver.ResetConnection()

	emptyTrie := trie.New[[]dnsClient]()
	(&Resolver{
		policy: []dnsPolicy{
			domainTriePolicy{DomainTrie: emptyTrie},
			domainMatcherPolicy{},
		},
	}).ResetConnection()
}

// TestClearCacheReachesPolicyClientsToo: the same walk backs cache clearing, and missing
// policy there has the worse failure mode -- a stale positive answer misroutes traffic,
// where a stale connection merely costs one query.
func TestClearCacheDoesNotPanicWithPolicies(t *testing.T) {
	domainTrie := trie.New[[]dnsClient]()
	if err := domainTrie.Insert("policy.example.com", []dnsClient{&resetCountingClient{}}); err != nil {
		t.Fatal(err)
	}
	(&Resolver{
		policy: []dnsPolicy{domainTriePolicy{DomainTrie: domainTrie}},
	}).ClearCache()
}

// A nameserver-policy entry written as "8.8.8.8#disable-ipv6=true" (or #disable-ipv4,
// #disable-qtype-N) is wrapped by upstream's wrapClientWithDisableTypes -- a struct VALUE
// holding a map, stored in the dnsClient interface. Deduplicating such clients with a
// map[dnsClient]struct{} is a runtime panic ("hash of unhashable type
// dns.clientWithDisableTypes"), and ApplyConfig ends by calling ResetConnection, so the
// tunnel died on applying a legal configuration. Reproduced before the fix.
func TestResetConnectionSurvivesADisableTypesPolicyClient(t *testing.T) {
	raw := &resetCountingClient{}
	wrapped := clientWithDisableTypes{dnsClient: raw, disableTypes: map[uint16]struct{}{D.TypeAAAA: {}}}

	domainTrie := trie.New[[]dnsClient]()
	if err := domainTrie.Insert("policy.example.com", []dnsClient{wrapped}); err != nil {
		t.Fatal(err)
	}
	if err := domainTrie.Insert("+.wild.example.com", []dnsClient{wrapped}); err != nil {
		t.Fatal(err)
	}

	resolver := &Resolver{policy: []dnsPolicy{domainTriePolicy{DomainTrie: domainTrie}}}
	resolver.ResetConnection() // must not panic

	if got := raw.resets.Load(); got != 1 {
		t.Fatalf("raw transport behind the disable-types wrapper was reset %d times, want exactly 1", got)
	}
}

// v1.19.30's NewResolver shares one raw transport between name servers that differ only
// in wrapper-only params (transportEqual + rewrapClient), so the same *dnsOverHTTPS can
// sit behind a main client, a fallback client and a policy client, each under a
// different wrapper. Deduplicating by wrapper identity would reset that transport once
// per wrapper -- and a duplicate landing after a query has already rebuilt the transport
// closes the new one. Identity is the raw transport, reached by unwrapping.
func TestResetConnectionResetsASharedRawTransportOnce(t *testing.T) {
	raw := &resetCountingClient{}
	asMain := clientWithEdns0Subnet{dnsClient: raw}
	asPolicy := clientWithDisableTypes{dnsClient: raw, disableTypes: map[uint16]struct{}{D.TypeA: {}}}

	domainTrie := trie.New[[]dnsClient]()
	if err := domainTrie.Insert("policy.example.com", []dnsClient{asPolicy}); err != nil {
		t.Fatal(err)
	}

	resolver := &Resolver{
		main:     []dnsClient{asMain},
		fallback: []dnsClient{raw},
		policy: []dnsPolicy{
			domainTriePolicy{DomainTrie: domainTrie},
			domainMatcherPolicy{dnsClients: []dnsClient{asPolicy}},
		},
	}
	resolver.ResetConnection()

	if got := raw.resets.Load(); got != 1 {
		t.Fatalf("shared raw transport was reset %d times across main/fallback/policy wrappers, want exactly 1", got)
	}
}

// NewResolver builds main, proxy and direct resolvers from ONE nameServerCache, so a raw
// transport can be shared across all three -- and Resolvers.ResetConnection walks all
// three. Deduplicating inside each Resolver is not enough: the identity set has to span
// the whole aggregate, or a shared transport is reset once per resolver that holds it.
func TestAggregateResetConnectionResetsATransportSharedAcrossResolversOnce(t *testing.T) {
	raw := &resetCountingClient{}
	rs := Resolvers{
		Resolver:       &Resolver{main: []dnsClient{clientWithEdns0Subnet{dnsClient: raw}}},
		ProxyResolver:  &Resolver{main: []dnsClient{raw}},
		DirectResolver: &Resolver{main: []dnsClient{clientWithDisableTypes{dnsClient: raw, disableTypes: map[uint16]struct{}{D.TypeAAAA: {}}}}},
	}
	rs.ResetConnection()

	if got := raw.resets.Load(); got != 1 {
		t.Fatalf("raw transport shared across main/proxy/direct resolvers was reset %d times, want exactly 1", got)
	}
}

func TestResolversContainsResolverNamesItsMembersOnly(t *testing.T) {
	main, proxy, direct, stranger := &Resolver{}, &Resolver{}, &Resolver{}, &Resolver{}
	rs := Resolvers{Resolver: main, ProxyResolver: proxy, DirectResolver: direct}
	for name, r := range map[string]*Resolver{"main": main, "proxy": proxy, "direct": direct} {
		if !rs.ContainsResolver(r) {
			t.Errorf("aggregate does not report its %s member as contained", name)
		}
	}
	if rs.ContainsResolver(stranger) {
		t.Error("aggregate reports a resolver it does not hold as contained")
	}
	if (Resolvers{}).ContainsResolver(main) {
		t.Error("an empty aggregate reports a member")
	}
}

// The production entry is component/resolver.ResetConnection, reached from the path monitor
// and from the end of ApplyConfig. It walks DefaultResolver, ProxyServerHostResolver and
// DirectHostResolver -- registered by updateDNS as the dns.Resolvers aggregate and that same
// aggregate's own members -- each in its own goroutine. Before the aggregate could report its
// members, a raw transport shared across the three was reset three times concurrently.
func TestProductionResetConnectionResetsASharedTransportOnce(t *testing.T) {
	raw := &resetCountingClient{}
	rs := Resolvers{
		Resolver:       &Resolver{main: []dnsClient{clientWithEdns0Subnet{dnsClient: raw}}},
		ProxyResolver:  &Resolver{main: []dnsClient{raw}},
		DirectResolver: &Resolver{main: []dnsClient{clientWithDisableTypes{dnsClient: raw, disableTypes: map[uint16]struct{}{D.TypeAAAA: {}}}}},
	}

	priorDefault, priorProxy, priorDirect := resolver.DefaultResolver, resolver.ProxyServerHostResolver, resolver.DirectHostResolver
	t.Cleanup(func() {
		resolver.DefaultResolver, resolver.ProxyServerHostResolver, resolver.DirectHostResolver = priorDefault, priorProxy, priorDirect
	})
	// Exactly what hub/executor's updateDNS assigns.
	resolver.DefaultResolver = rs
	resolver.ProxyServerHostResolver = rs.ProxyResolver
	resolver.DirectHostResolver = rs.DirectResolver

	resolver.ResetConnection()

	deadline := time.Now().Add(2 * time.Second)
	for raw.resets.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond) // a duplicate reset from a sibling goroutine would already be in flight
	if got := raw.resets.Load(); got != 1 {
		t.Fatalf("through the production entry, a raw transport shared across main/proxy/direct was reset %d times, want exactly 1", got)
	}
}
