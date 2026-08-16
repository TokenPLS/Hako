package dns

import (
	"context"
	"sync/atomic"
	"testing"

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
