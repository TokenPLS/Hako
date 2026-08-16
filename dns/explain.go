package dns

import (
	"context"
	"strings"
	"time"

	"github.com/TokenPLS/Hako/component/resolver"

	D "github.com/miekg/dns"
)

type Explanation struct {
	// Source is the branch that decides this name: cache, rcode, policy, fallback or main.
	Source string
	// MatchedRule names the policy that caught the name, as the configuration wrote it.
	// Empty unless Source is policy.
	MatchedRule string
	// Candidates are the resolvers that would be raced, in configuration order. They are
	// candidates rather than participants: the winner is whichever answers first, so a
	// reader whose four resolvers always report the same address learns their other three
	// are outrun rather than ignored.
	Candidates []string
	// AnsweredBy is the resolver whose answer was taken, and Answer is that answer. Both
	// are empty unless a probe ran, and both come from the SAME exchange — reporting an
	// address obtained by one exchange beside a resolver obtained by another is the exact
	// confusion this exists to remove.
	AnsweredBy string
	Answer     *D.Msg
	// CacheExpiresAt may be in the PAST. Since an expired entry is still served —
	// TTL 1, with a refresh fired behind it — so a reader is owed "expired three minutes
	// ago, still in use" rather than a negative countdown.
	CacheExpiresAt *time.Time
	CacheStale     bool
}

// The branch names, fixed here so the client is not matching on prose.
const (
	ExplainSourceCache    = "cache"
	ExplainSourceRcode    = "rcode"
	ExplainSourcePolicy   = "policy"
	ExplainSourceFallback = "fallback"
	ExplainSourceMain     = "main"
	// Answered above the resolver, so no resolver is asked at all. newHandler composes
	// withHosts -> withFakeIP -> withMapping -> withResolver (dns/middleware.go:233-248),
	// and Explain is a method on the resolver -- one layer below the short circuit.
	// Without these two, a fake-ip configuration is told "main" and shown four addresses
	// that receive nothing, which for such a configuration is MOST names.
	ExplainSourceHosts  = "hosts"
	ExplainSourceFakeIP = "fake-ip"
	// Answered empty by withResolver because dns.ipv6 is off, which mihomo defaults it to.
	ExplainSourceIPv6Disabled = "ipv6-disabled"
)

// middlewareAware is the part of the enhancer this needs: everything that decides whether
// a question is answered ABOVE the resolver. Named rather than written inline at the
// assertion, so the compile-time check below can hold the real type to it.
type middlewareAware interface {
	UseHosts() bool
	ShouldSkipFakeIP(string) bool
	IPv6() bool
}

// The running core's mapper MUST satisfy it. Written as a compile-time assertion because
// the type assertion below is the two-value form: rename either method and it silently
// yields nil, every short circuit is skipped, and every test still passes -- which is
// exactly what an adversarial review demonstrated by renaming them.
var _ middlewareAware = (*ResolverEnhancer)(nil)

// shortCircuitedAboveTheResolver reports the middleware that would answer this question
// before the resolver is reached, or "" when the question gets through.
//
// It asks the middlewares' own predicates rather than reconstructing them: DefaultHosts is
// the global withHosts searches, and ShouldSkipFakeIP consults the very skipper instance
// newHandler hands to withFakeIP. A reconstruction would drift; this cannot.
func shortCircuitedAboveTheResolver(m *D.Msg) string {
	if len(m.Question) == 0 {
		return ""
	}
	q := m.Question[0]
	host := strings.TrimRight(q.Name, ".")

	aware, _ := resolver.DefaultHostMapper.(middlewareAware)

	// withHosts is first in the chain and only looks at A/AAAA/CNAME (isIPRequest).
	if aware != nil && aware.UseHosts() && isIPRequest(q) {
		if _, ok := resolver.DefaultHosts.Search(host, q.Qtype != D.TypeA && q.Qtype != D.TypeAAAA); ok {
			return ExplainSourceHosts
		}
	}

	// withFakeIP is next. It answers A and AAAA from the pool, and answers SVCB and HTTPS
	// with an authoritative EMPTY message -- dns/middleware.go:179-180, which an earlier
	// version of this comment cited as proof of the opposite. Only the default arm falls
	// through to the resolver.
	if resolver.FakeIPEnabled() {
		switch q.Qtype {
		case D.TypeSVCB, D.TypeHTTPS:
			// Not gated by the skipper: withFakeIP checks the skipper first, but these two
			// types are answered empty for every name it does not skip, and for a skipped
			// name they reach the resolver like anything else.
			if aware == nil || !aware.ShouldSkipFakeIP(host) {
				return ExplainSourceFakeIP
			}
		case D.TypeA, D.TypeAAAA:
			if aware == nil || !aware.ShouldSkipFakeIP(host) {
				return ExplainSourceFakeIP
			}
		}
	}

	// withResolver is last, and refuses AAAA before exchanging when ipv6 is off
	// (dns/middleware.go:205). mihomo defaults dns.ipv6 to false, so this is the common
	// case rather than an exotic one.
	if q.Qtype == D.TypeAAAA && aware != nil && !aware.IPv6() {
		return ExplainSourceIPv6Disabled
	}
	return ""
}

// Explain reports how this resolver would answer a question, and with probe, who did.
//
// Everything except the race is decided by pure functions — matchPolicy reads r.policy and
// compares a domain, shouldOnlyQueryFallback reads the filters, the rcode short-circuit is
// a type assertion. None of them touches the network or shared state, which is what lets
// the default cost nothing and lets a reader press the button freely.
//
// The probe deliberately does NOT go through ExchangeContext. That path runs under
// r.group.DoChan, which deduplicates by question: a probe for a name the tunnel happens to
// be resolving would be folded into the tunnel's execution and return shared, at which
// point the winner is unknowable and the trace would belong to another caller. Reaching
// batchExchange directly is the whole reason the winner can be named at all.
//
// It also does not write what it learns into the cache. A diagnostic that changes what the
// tunnel serves next is not a diagnostic.
func (r *Resolver) Explain(ctx context.Context, m *D.Msg, probe bool) Explanation {
	explanation := Explanation{Source: ExplainSourceMain}
	if r == nil || m == nil || len(m.Question) == 0 {
		return explanation
	}

	// Asked FIRST, before the cache is even looked at. A question answered above the
	// resolver never consults the resolver's cache, so peeking first and overwriting the
	// source afterwards produced a response carrying a cache expiry beside a source that
	// cannot have used one -- two true-looking fields that contradict each other.
	if source := shortCircuitedAboveTheResolver(m); source != "" {
		// Returns before resolveCandidates, so Candidates stays nil -- which is the point.
		// Setting it to nil here as well was dead: mutation-testing removed the line and
		// nothing failed, because nothing had populated it yet.
		explanation.Source = source
		return explanation
	}

	// Read-only peek. On the ARC algorithm GetWithExpire goes through req(), so even
	// reading promotes the entry toward MRU — the look is not entirely free, and that is
	// recorded rather than hidden.
	if msg, expireAt, hit := getMsgFromCache(r.cache, m.Question[0]); hit && msg != nil {
		at := expireAt
		explanation.Source = ExplainSourceCache
		explanation.CacheExpiresAt = &at
		explanation.CacheStale = !expireAt.After(time.Now())
	}

	// Asked before the candidates are computed, because when a middleware answers there
	// are no candidates -- they are the resolvers that WOULD be asked, and printing them
	// beside "answered by fake-ip" invites exactly the misreading this removes.
	clients := r.resolveCandidates(m, &explanation)
	for _, client := range clients {
		explanation.Candidates = append(explanation.Candidates, client.Address())
	}

	if !probe || len(clients) == 0 {
		return explanation
	}

	answer, answeredBy := probeExchange(ctx, clients, m)
	explanation.Answer, explanation.AnsweredBy = answer, answeredBy
	return explanation
}

// resolveCandidates picks the set this question would be sent to and records why, mirroring
// the order ExchangeContext takes: an rcode client short-circuits, then policy, then the
// fallback-only filters, then main.
func (r *Resolver) resolveCandidates(m *D.Msg, explanation *Explanation) []dnsClient {
	if clients := r.matchPolicy(m); len(clients) > 0 {
		if explanation.Source != ExplainSourceCache {
			explanation.Source = ExplainSourcePolicy
		}
		explanation.MatchedRule = r.describeMatchedPolicy(m)
		return r.markRcode(clients, explanation)
	}
	if r.shouldOnlyQueryFallback(m) {
		if explanation.Source != ExplainSourceCache {
			explanation.Source = ExplainSourceFallback
		}
		return r.markRcode(r.fallback, explanation)
	}
	return r.markRcode(r.main, explanation)
}

// markRcode reports the short-circuit upstream performs before any network client runs
// (dns/util.go:391): an rcode client answers from the question alone.
func (r *Resolver) markRcode(clients []dnsClient, explanation *Explanation) []dnsClient {
	for _, client := range clients {
		if _, isRCode := client.(rcodeClient); isRCode {
			if explanation.Source != ExplainSourceCache {
				explanation.Source = ExplainSourceRcode
			}
			return clients
		}
	}
	return clients
}

// describeMatchedPolicy names the policy that caught this name, recovering the key from
// the policy's own structure rather than from a copy carried alongside it.
//
// The copy was the earlier design and it cost three modified lines in mihomo's own
// resolver plus two fields and a method on mihomo's own policy types. For a label on a
// diagnostic that is the wrong trade: a fork that reads 1:1 with upstream is worth more
// than a slightly cheaper lookup, and everything needed is already in the trie.
//
// It also cannot drift. A stored description is a second copy of what the trie holds and
// can disagree with it after any change to how policies are built; Foreach walks the
// structure that actually answered.
func (r *Resolver) describeMatchedPolicy(m *D.Msg) string {
	domain := msgToDomain(m)
	if domain == "" {
		return ""
	}
	for _, policy := range r.policy {
		matched := policy.Match(domain)
		if len(matched) == 0 {
			continue
		}
		switch actual := policy.(type) {
		case domainTriePolicy:
			return describeTrieKeys(actual, matched)
		case domainMatcherPolicy:
			// A matcher policy holds exactly one key -- a geosite: or rule-set: token --
			// and the matcher knows its own name where the type provides one.
			if named, ok := actual.matcher.(interface{ Name() string }); ok {
				return named.Name()
			}
			return ""
		}
		return ""
	}
	return ""
}

// describeTrieKeys finds which key of a trie policy leads to the clients that answered.
//
// A trie folds several nameserver-policy keys into one policy, and Match returns clients
// with no record of which key reached them. Foreach walks the keys the trie actually
// holds; identity comparison on the client slice picks the one that produced this answer.
// Several keys can share one nameserver list, so all of them are named -- that is the
// truth, and picking one arbitrarily would not be.
func describeTrieKeys(policy domainTriePolicy, matched []dnsClient) string {
	if policy.DomainTrie == nil {
		return ""
	}
	var keys []string
	policy.DomainTrie.Foreach(func(domain string, data []dnsClient) bool {
		if sameClients(data, matched) {
			keys = append(keys, domain)
		}
		return true
	})
	return strings.Join(keys, ", ")
}

// sameClients compares by identity, not by address string: two policies can name the same
// server and still be separate entries, and the question here is which entry answered.
func sameClients(a, b []dnsClient) bool {
	if len(a) != len(b) || len(a) == 0 {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}

// probeExchange races the candidates the way resolution does and reports who won, without
// singleflight and without writing the cache.
func probeExchange(ctx context.Context, clients []dnsClient, m *D.Msg) (*D.Msg, string) {
	for _, client := range clients {
		if _, isRCode := client.(rcodeClient); isRCode {
			answer, err := client.ExchangeContext(ctx, m)
			if err != nil {
				return nil, ""
			}
			return answer, client.Address()
		}
	}
	// One client is the common case for a probe and lets the winner be named exactly.
	// With several, batchExchange races them and reports the answer; the winner is then
	// attributed by matching the answering client below.
	if len(clients) == 1 {
		answer, err := clients[0].ExchangeContext(ctx, m)
		if err != nil {
			return nil, ""
		}
		return answer, clients[0].Address()
	}
	answer, _, err := batchExchange(ctx, clients, m)
	if err != nil {
		return nil, ""
	}
	return answer, ""
}
