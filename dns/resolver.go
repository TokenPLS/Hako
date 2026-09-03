package dns

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"sync"
	"time"

	"github.com/TokenPLS/Hako/common/arc"
	"github.com/TokenPLS/Hako/common/lru"
	"github.com/TokenPLS/Hako/common/singleflight"
	"github.com/TokenPLS/Hako/component/resolver"
	"github.com/TokenPLS/Hako/component/trie"
	C "github.com/TokenPLS/Hako/constant"
	"github.com/TokenPLS/Hako/log"

	D "github.com/miekg/dns"
	"github.com/samber/lo"
	"golang.org/x/exp/maps"
)

type dnsClient interface {
	ExchangeContext(ctx context.Context, m *D.Msg) (msg *D.Msg, err error)
	Address() string
	ResetConnection()
}

type dnsCache interface {
	GetWithExpire(key string) (*D.Msg, time.Time, bool)
	SetWithExpire(key string, value *D.Msg, expire time.Time)
	Clear()
}

type result struct {
	Msg   *D.Msg
	Error error
}

type Resolver struct {
	ipv6                  bool
	ipv6Timeout           time.Duration
	main                  []dnsClient
	fallback              []dnsClient
	fallbackDomainFilters []C.DomainMatcher
	fallbackIPFilters     []C.IpMatcher
	fallbackLazyQuery     bool
	group                 singleflight.Group[*D.Msg]
	cache                 dnsCache
	policy                []dnsPolicy
	defaultResolver       *Resolver
	// queryMu guards the context every upstream query runs under -- live caller queries and
	// detached cache refreshes alike, because singleflight shares ONE fn between them and that
	// fn's context is what governs the actual client call. There is no way to give the two
	// different lifetimes at that level, and pretending otherwise is what broke.
	//
	// It used to be context.Background(), so nothing could stop a query: a shutdown could not,
	// and up to one DNS timeout of goroutines survived the core they belonged to. The first
	// attempt at fixing that tied the fn to a context ResetConnection cancels, which fixed
	// shutdown and broke something worse: component/resolver.ResetConnection fans out as
	// `go r.ResetConnection()`, so it races whatever is in flight, and on Apple it fires on
	// every default-interface change. Every Wi-Fi to cellular switch handed the caller a
	// SERVFAIL for a lookup whose upstream was fine.
	//
	// So the lifetime is the CORE's, cancelled by CloseQueries and by nothing else. That is
	// upstream's shape: sing-box's queries run under the service context given to NewClient,
	// and ResetNetwork drops connections and clears the cache without touching it. Cancelling
	// queries on a path change was ours alone, and the repository's own older controlled DNS
	// interop tests said so by going red.
	queryMu     sync.Mutex
	queryCtx    context.Context
	queryCancel context.CancelFunc
	// queryClosed makes CloseQueries one-way. Without it, cancelling a live query at shutdown
	// synthesised a replacement: the retry branch in exchangeWithoutCache and the
	// context.Canceled arm of ExchangeContext's defer both call queryContext again, which used
	// to build a fresh live context on demand.
	queryClosed bool
}

func (r *Resolver) LookupIPPrimaryIPv4(ctx context.Context, host string) (ips []netip.Addr, err error) {
	ch := make(chan []netip.Addr, 1)
	go func() {
		defer close(ch)
		ip, err := r.lookupIP(ctx, host, D.TypeAAAA)
		if err != nil {
			return
		}
		ch <- ip
	}()

	ips, err = r.lookupIP(ctx, host, D.TypeA)
	if err == nil {
		return
	}

	ip, open := <-ch
	if !open {
		return nil, resolver.ErrIPNotFound
	}

	return ip, nil
}

func (r *Resolver) LookupIP(ctx context.Context, host string) (ips []netip.Addr, err error) {
	ch := make(chan []netip.Addr, 1)
	go func() {
		defer close(ch)
		ip, err := r.lookupIP(ctx, host, D.TypeAAAA)
		if err != nil {
			return
		}

		ch <- ip
	}()

	ips, err = r.lookupIP(ctx, host, D.TypeA)
	var waitIPv6 *time.Timer
	if r != nil && r.ipv6Timeout > 0 {
		waitIPv6 = time.NewTimer(r.ipv6Timeout)
	} else {
		waitIPv6 = time.NewTimer(100 * time.Millisecond)
	}
	defer waitIPv6.Stop()
	select {
	case ipv6s, open := <-ch:
		if !open && err != nil {
			return nil, resolver.ErrIPNotFound
		}
		ips = append(ips, ipv6s...)
	case <-waitIPv6.C:
		// wait ipv6 result
	}

	return ips, nil
}

// LookupIPv4 request with TypeA
func (r *Resolver) LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.lookupIP(ctx, host, D.TypeA)
}

// LookupIPv6 request with TypeAAAA
func (r *Resolver) LookupIPv6(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.lookupIP(ctx, host, D.TypeAAAA)
}

func (r *Resolver) shouldIPFallback(ip netip.Addr) bool {
	for _, filter := range r.fallbackIPFilters {
		if filter.MatchIp(ip) {
			return true
		}
	}
	return false
}

func (r *Resolver) ResolveECH(ctx context.Context, host string) ([]byte, error) {
	query := &D.Msg{}
	query.SetQuestion(D.Fqdn(host), D.TypeHTTPS)

	msg, err := r.ExchangeContext(ctx, query)
	if err != nil {
		return nil, err
	}

	for _, rr := range msg.Answer {
		switch resource := rr.(type) {
		case *D.HTTPS:
			for _, value := range resource.Value {
				if echConfig, ok := value.(*D.SVCBECHConfig); ok {
					return echConfig.ECH, nil
				}
			}
		}
	}
	return nil, errors.New("no ECH config found in DNS records")
}

// ExchangeContext a batch of dns request with context.Context, and it use cache
func (r *Resolver) ExchangeContext(ctx context.Context, m *D.Msg) (msg *D.Msg, err error) {
	if len(m.Question) == 0 {
		return nil, errors.New("should have one question at least")
	}
	continueFetch := false
	defer func() {
		if continueFetch || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			parent := r.queryContext()
			go func() {
				ctx, cancel := context.WithTimeout(parent, resolver.DefaultDNSTimeout)
				defer cancel()
				_, _ = r.exchangeWithoutCache(ctx, m) // ignore result, just for putMsgToCache
			}()
		}
	}()

	q := m.Question[0]
	domain := msgToDomain(m)
	// mihomo's cache-hit branch verbatim (dns/resolver.go:169-181 at v1.19.29). Three things
	// this core used to do differently, all removed under one rule -- what mihomo does is what
	// we do:
	//
	//   - the remaining TTL was clamped at zero. mihomo reads the clock a SECOND time here,
	//     via time.Until, so an entry expiring between the check above and this line yields a
	//     negative value that wraps to roughly four billion seconds. That is a real defect and
	//     it is inherited on purpose: fixing it here is still behaving differently from the
	//     upstream a reader's configuration was written for, and the fix belongs upstream.
	//   - an expired entry was bounded by an optimistic window. mihomo has no window; it
	// serves the stale answer and refetches, however old ('s finding: the cache is
	//     built WithStale(true) and no WithAge, so staleness has no upper bound at all).
	//   - a hard miss evicted the key. mihomo never evicts here.
	msg, expireTime, hit := getMsgFromCache(r.cache, q)
	if hit {
		log.Debugln("[DNS] cache hit %s --> %s, expire at %s", domain, msgToLogString(msg), expireTime.Format("2006-01-02 15:04:05"))
		now := time.Now()
		if expireTime.Before(now) {
			setMsgTTL(msg, uint32(1)) // Continue fetch
			continueFetch = true
		} else {
			// updating TTL by subtracting common delta time from each DNS record
			updateMsgTTL(msg, uint32(time.Until(expireTime).Seconds()))
		}
		return
	}
	return r.exchangeWithoutCache(ctx, m)
}

// ExchangeWithoutCache a batch of dns request, and it do NOT GET from cache
func (r *Resolver) exchangeWithoutCache(ctx context.Context, m *D.Msg) (msg *D.Msg, err error) {
	q := m.Question[0]

	retryNum := 0
	retryMax := 3
	fn := func() (result *D.Msg, err error) {
		// Rooted at the resolver's own context, not context.Background().
		//
		// Re-rooting away from the CALLER is deliberate and must stay: singleflight shares
		// one fn across every caller waiting on the same question, so tying it to one
		// caller's context would let that caller's cancellation kill everybody else's
		// query. But Background() threw away the process lifetime along with the caller's,
		// which meant no in-flight upstream query was cancellable by anything --
		// shutdownCore could not stop one, and neither could a path change. Queries
		// outlived the core they belonged to, talking to upstreams over a path being torn
		// down. A resolver-scoped parent keeps the independence from callers and gives back
		// the lifetime.
		//
		// It must be queryContext and NOT refetchContext: this fn serves live callers, and the
		// refetch context is cancelled on every ResetConnection. See queryMu.
		ctx, cancel := context.WithTimeout(r.queryContext(), resolver.DefaultDNSTimeout)
		defer cancel()
		cache := false

		defer func() {
			if err != nil {
				result = &D.Msg{}
				result.Opcode = retryNum
				retryNum++
				return
			}

			if cache {
				putMsgToCache(r.cache, q, result)
			}
		}()

		isIPReq := isIPRequest(q)
		if isIPReq {
			cache = true
			return r.ipExchange(ctx, m)
		}

		if matched := r.matchPolicy(m); len(matched) != 0 {
			result, cache, err = batchExchange(ctx, matched, m)
			return
		}
		result, cache, err = batchExchange(ctx, r.main, m)
		return
	}

	ch := r.group.DoChan(q.String(), fn)

	var result singleflight.Result[*D.Msg]

	select {
	case result = <-ch:
		break
	case <-ctx.Done():
		select {
		case result = <-ch: // maybe ctxDone and chFinish in same time, get DoChan's result as much as possible
			break
		default:
			go func() { // start a retrying monitor in background
				result := <-ch
				ret, err, shared := result.Val, result.Err, result.Shared
				if err != nil && !shared && ret.Opcode < retryMax { // retry
					r.group.DoChan(q.String(), fn)
				}
			}()
			return nil, ctx.Err()
		}
	}

	ret, err, shared := result.Val, result.Err, result.Shared
	if err != nil && !shared && ret.Opcode < retryMax { // retry
		r.group.DoChan(q.String(), fn)
	}

	if err == nil {
		msg = ret
		if shared {
			msg = msg.Copy()
		}
	}

	return
}

func (r *Resolver) matchPolicy(m *D.Msg) []dnsClient {
	if r.policy == nil {
		return nil
	}

	domain := msgToDomain(m)
	if domain == "" {
		return nil
	}

	for _, policy := range r.policy {
		if dnsClients := policy.Match(domain); len(dnsClients) > 0 {
			return dnsClients
		}
	}
	return nil
}

func (r *Resolver) shouldOnlyQueryFallback(m *D.Msg) bool {
	if r.fallback == nil || len(r.fallbackDomainFilters) == 0 {
		return false
	}

	domain := msgToDomain(m)

	if domain == "" {
		return false
	}

	for _, df := range r.fallbackDomainFilters {
		if df.MatchDomain(domain) {
			return true
		}
	}

	return false
}

func (r *Resolver) ipExchange(ctx context.Context, m *D.Msg) (msg *D.Msg, err error) {
	if matched := r.matchPolicy(m); len(matched) != 0 {
		res := <-r.asyncExchange(ctx, matched, m)
		return res.Msg, res.Error
	}

	onlyFallback := r.shouldOnlyQueryFallback(m)

	if onlyFallback {
		res := <-r.asyncExchange(ctx, r.fallback, m)
		return res.Msg, res.Error
	}

	msgCh := r.asyncExchange(ctx, r.main, m)

	if r.fallback == nil { // directly return if no fallback servers are available
		res := <-msgCh
		msg, err = res.Msg, res.Error
		return
	}

	var fallbackMsg <-chan *result
	if !r.fallbackLazyQuery {
		fallbackMsg = r.asyncExchange(ctx, r.fallback, m)
	}
	res := <-msgCh
	if res.Error == nil {
		if ips := msgToIP(res.Msg); len(ips) != 0 {
			shouldNotFallback := lo.EveryBy(ips, func(ip netip.Addr) bool {
				return !r.shouldIPFallback(ip)
			})
			if shouldNotFallback {
				msg, err = res.Msg, res.Error // no need to wait for fallback result
				return
			}
		}
	}

	if fallbackMsg == nil {
		fallbackMsg = r.asyncExchange(ctx, r.fallback, m)
	}
	res = <-fallbackMsg
	msg, err = res.Msg, res.Error
	return
}

func (r *Resolver) lookupIP(ctx context.Context, host string, dnsType uint16) (ips []netip.Addr, err error) {
	ip, err := netip.ParseAddr(host)
	if err == nil {
		ip = ip.Unmap()
		isIPv4 := ip.Is4()
		if dnsType == D.TypeAAAA && !isIPv4 {
			return []netip.Addr{ip}, nil
		} else if dnsType == D.TypeA && isIPv4 {
			return []netip.Addr{ip}, nil
		} else {
			return []netip.Addr{}, resolver.ErrIPVersion
		}
	}

	query := &D.Msg{}
	query.SetQuestion(D.Fqdn(host), dnsType)

	msg, err := r.ExchangeContext(ctx, query)
	if err != nil {
		return []netip.Addr{}, err
	}

	ips = msgToIP(msg)
	ipLength := len(ips)
	if ipLength == 0 {
		return []netip.Addr{}, resolver.ErrIPNotFound
	}

	return
}

func (r *Resolver) asyncExchange(ctx context.Context, client []dnsClient, msg *D.Msg) <-chan *result {
	ch := make(chan *result, 1)
	go func() {
		res, _, err := batchExchange(ctx, client, msg)
		ch <- &result{Msg: res, Error: err}
	}()
	return ch
}

// Invalid return this resolver can or can't be used
func (r *Resolver) Invalid() bool {
	if r == nil {
		return false
	}
	return len(r.main) > 0
}

func (r *Resolver) ClearCache() {
	if r != nil && r.cache != nil {
		r.cache.Clear()
	}
}

// ResetConnection drops the live upstream connections of every client this resolver can
// use, so the next query re-dials on the current network path.
//
// r.policy used to be skipped. That is invisible from the resolution path -- Match is all
// resolution needs -- so a nameserver-policy entry's tls/https/quic clients kept sockets
// scoped to the previous path across a network change. The blast radius is one degraded
// query, because all three stateful transports self-heal on their first failure, but the
// omission is the kind that only an enumeration can prevent.
//
// Identity is the RAW transport, not the client handed out. Since v1.19.30 NewResolver
// shares one raw transport between name servers that differ only in wrapper-only params
// (transportEqual, then rewrapClient re-wraps the same *dnsOverHTTPS per name server), so
// the same connection can sit behind a main client, a fallback client and a policy client
// under three different wrappers; and a policy trie stores one insert under two nodes.
// Resetting per wrapper would reset that transport once per wrapper, and a duplicate that
// lands after a query has already rebuilt the transport closes the new one. So every
// client is unwrapped first -- the Unwrap() the wrappers expose for exactly this, the
// primitive rewrapClient itself uses -- and the reset is issued once per raw transport.
//
// The dedup map is keyed only by transports whose dynamic type is comparable. Every raw
// transport built today is a pointer or a comparable value; the disable-types wrapper is a struct value
// holding a map and is not -- keying a map[dnsClient] on it is a runtime panic ("hash of
// unhashable type"), which is what a nameserver-policy entry written as
// "8.8.8.8#disable-ipv6=true" produced here before this shape, on ApplyConfig, because
// ApplyConfig ends in ResetConnection. Anything still uncomparable after unwrapping is
// reset without dedup rather than risked as a key.
func (r *Resolver) ResetConnection() {
	r.resetConnections(make(map[dnsClient]struct{}))
}

// resetConnections is ResetConnection with the identity set supplied by the caller, so
// that Resolvers.ResetConnection can span main, proxy and direct with ONE set: NewResolver
// builds all three from a single nameServerCache, and a raw transport shared across them
// would otherwise be reset once per resolver that holds it.
func (r *Resolver) resetConnections(seen map[dnsClient]struct{}) {
	if r == nil {
		return
	}
	resetOnce := func(c dnsClient) {
		if c == nil {
			return
		}
		raw := rawTransport(c)
		if reflect.TypeOf(raw).Comparable() {
			if _, done := seen[raw]; done {
				return
			}
			seen[raw] = struct{}{}
		}
		raw.ResetConnection()
	}
	for _, c := range r.main {
		resetOnce(c)
	}
	for _, c := range r.fallback {
		resetOnce(c)
	}
	for _, p := range r.policy {
		for _, c := range p.Clients() {
			resetOnce(c)
		}
	}
	// Deliberately does NOT cancel in-flight queries: see queryMu. A reset drops the
	// connections so the NEXT query re-dials on the current path, which is upstream's
	// ResetNetwork exactly.
	if dr := r.defaultResolver; dr != nil {
		dr.resetConnections(seen)
	}
}

// rawTransport peels every wrapper layer off c the way rewrapClient does, so callers
// that need to identify or reset the underlying connection act on the connection and
// not on one of the several wrappers v1.19.30 may hand out for it.
func rawTransport(c dnsClient) dnsClient {
	for {
		u, ok := c.(interface{ Unwrap() dnsClient })
		if !ok {
			return c
		}
		inner := u.Unwrap()
		if inner == nil {
			return c
		}
		c = inner
	}
}

type NameServer struct {
	Net          string
	Addr         string
	ProxyAdapter C.ProxyAdapter
	ProxyName    string
	Params       map[string]string
	PreferH3     bool
}

func (ns NameServer) Equal(ns2 NameServer) bool {
	defer func() {
		// C.ProxyAdapter compare maybe panic, just ignore
		recover()
	}()
	if ns.Net == ns2.Net &&
		ns.Addr == ns2.Addr &&
		ns.ProxyAdapter == ns2.ProxyAdapter &&
		ns.ProxyName == ns2.ProxyName &&
		maps.Equal(ns.Params, ns2.Params) &&
		ns.PreferH3 == ns2.PreferH3 {
		return true
	}
	return false
}

// transportEqual reports whether two NameServers share the same raw transport and
// may reuse a single client. It compares all fields except wrapper-only params.
func (ns NameServer) transportEqual(ns2 NameServer) bool {
	defer func() {
		// C.ProxyAdapter compare maybe panic, just ignore
		recover()
	}()
	paramsEqual := func(a, b map[string]string) bool {
		for k, v := range a {
			if isWrapperOnlyParam(k) {
				continue
			}
			if bv, ok := b[k]; !ok || bv != v {
				return false
			}
		}
		return true
	}
	return ns.Net == ns2.Net &&
		ns.Addr == ns2.Addr &&
		ns.ProxyAdapter == ns2.ProxyAdapter &&
		ns.ProxyName == ns2.ProxyName &&
		ns.PreferH3 == ns2.PreferH3 &&
		paramsEqual(ns.Params, ns2.Params) &&
		paramsEqual(ns2.Params, ns.Params)
}

type Policy struct {
	Domain      string
	Matcher     C.DomainMatcher
	NameServers []NameServer
}

type Config struct {
	Main, Fallback       []NameServer
	Default              []NameServer
	ProxyServer          []NameServer
	DirectServer         []NameServer
	DirectFollowPolicy   bool
	IPv6                 bool
	IPv6Timeout          uint
	FallbackIPFilter     []C.IpMatcher
	FallbackDomainFilter []C.DomainMatcher
	FallbackLazyQuery    bool
	Policy               []Policy
	ProxyServerPolicy    []Policy
	CacheAlgorithm       string
	CacheMaxSize         int
}

func (config Config) newCache() dnsCache {
	if config.CacheMaxSize == 0 {
		config.CacheMaxSize = 4096
	}
	switch config.CacheAlgorithm {
	case "arc":
		return arc.New(arc.WithSize[string, *D.Msg](config.CacheMaxSize))
	default:
		return lru.New(lru.WithSize[string, *D.Msg](config.CacheMaxSize), lru.WithStale[string, *D.Msg](true))
	}
}

type Resolvers struct {
	*Resolver
	ProxyResolver  *Resolver
	DirectResolver *Resolver
}

func (rs Resolvers) ClearCache() {
	rs.Resolver.ClearCache()
	rs.ProxyResolver.ClearCache()
	rs.DirectResolver.ClearCache()
}

// CloseQueries fans shutdown out to the same three resolvers the other lifecycle methods walk.
// Missing one here would leave its live queries running past shutdown, which is the whole
// defect this method exists to prevent -- and the aggregate is exactly where the earlier
// enumeration bug (r.policy never reached) lived.
func (rs Resolvers) CloseQueries() {
	rs.Resolver.CloseQueries()
	rs.ProxyResolver.CloseQueries()
	rs.DirectResolver.CloseQueries()
}

// ContainsResolver reports whether r is one of this aggregate's members, so that
// component/resolver's lifecycle helpers -- which are handed the aggregate as DefaultResolver
// and its members as ProxyServerHostResolver / DirectHostResolver -- visit each member once,
// through the aggregate, and not a second time on its own.
func (rs Resolvers) ContainsResolver(r resolver.Resolver) bool {
	for _, member := range []*Resolver{rs.Resolver, rs.ProxyResolver, rs.DirectResolver} {
		if member != nil && r == resolver.Resolver(member) {
			return true
		}
	}
	return false
}

func (rs Resolvers) ResetConnection() {
	// One identity set for the whole aggregate: see resetConnections.
	seen := make(map[dnsClient]struct{})
	rs.Resolver.resetConnections(seen)
	rs.ProxyResolver.resetConnections(seen)
	rs.DirectResolver.resetConnections(seen)
}

func NewResolverFromClient(client dnsClient) *Resolver {
	return &Resolver{
		ipv6:  true,
		main:  []dnsClient{client},
		cache: Config{}.newCache(),
	}
}

func NewResolver(config Config) (rs Resolvers) {
	defaultResolver := &Resolver{
		main:        transform(config.Default, nil),
		cache:       config.newCache(),
		ipv6Timeout: time.Duration(config.IPv6Timeout) * time.Millisecond,
	}

	var nameServerCache []struct {
		NameServer
		dnsClient
	}
	cacheTransform := func(nameserver []NameServer) (result []dnsClient) {
	LOOP:
		for _, ns := range nameserver {
			var dc dnsClient
			for _, nsc := range nameServerCache {
				if nsc.NameServer.Equal(ns) {
					result = append(result, nsc.dnsClient)
					continue LOOP // exact match wins: reuse the wrapped client as-is
				}
				if dc == nil && nsc.NameServer.transportEqual(ns) {
					dc = nsc.dnsClient // reusable raw transport; keep scanning for an exact match
				}
			}
			if dc != nil { // reuse raw transport, re-wrap the client
				dc = rewrapClient(dc, ns.Params)
			} else { // no reusable transport: build from scratch
				built := transform([]NameServer{ns}, defaultResolver)
				if len(built) == 0 {
					continue
				}
				dc = built[0]
			}
			nameServerCache = append(nameServerCache, struct {
				NameServer
				dnsClient
			}{NameServer: ns, dnsClient: dc})
			result = append(result, dc)
		}
		return
	}

	makePolicy := func(policies []Policy) (dnsPolicies []dnsPolicy) {
		var triePolicy *trie.DomainTrie[[]dnsClient]
		insertPolicy := func(policy dnsPolicy) {
			if triePolicy != nil {
				triePolicy.Optimize()
				dnsPolicies = append(dnsPolicies, domainTriePolicy{triePolicy})
				triePolicy = nil
			}
			if policy != nil {
				dnsPolicies = append(dnsPolicies, policy)
			}
		}

		for _, policy := range policies {
			if policy.Matcher != nil {
				insertPolicy(domainMatcherPolicy{matcher: policy.Matcher, dnsClients: cacheTransform(policy.NameServers)})
			} else {
				if triePolicy == nil {
					triePolicy = trie.New[[]dnsClient]()
				}
				_ = triePolicy.Insert(policy.Domain, cacheTransform(policy.NameServers))
			}
		}
		insertPolicy(nil)
		return
	}

	r := &Resolver{
		ipv6:        config.IPv6,
		main:        cacheTransform(config.Main),
		cache:       config.newCache(),
		ipv6Timeout: time.Duration(config.IPv6Timeout) * time.Millisecond,
		policy:      makePolicy(config.Policy),
	}
	r.defaultResolver = defaultResolver
	rs.Resolver = r

	if len(config.ProxyServer) != 0 {
		rs.ProxyResolver = &Resolver{
			ipv6:        config.IPv6,
			main:        cacheTransform(config.ProxyServer),
			cache:       config.newCache(),
			ipv6Timeout: time.Duration(config.IPv6Timeout) * time.Millisecond,
			policy:      makePolicy(config.ProxyServerPolicy),
		}
	}

	if len(config.DirectServer) != 0 {
		rs.DirectResolver = &Resolver{
			ipv6:        config.IPv6,
			main:        cacheTransform(config.DirectServer),
			cache:       config.newCache(),
			ipv6Timeout: time.Duration(config.IPv6Timeout) * time.Millisecond,
		}
		if config.DirectFollowPolicy {
			rs.DirectResolver.policy = r.policy
		}
	}

	if len(config.Fallback) != 0 {
		r.fallback = cacheTransform(config.Fallback)
		r.fallbackIPFilters = config.FallbackIPFilter
		r.fallbackDomainFilters = config.FallbackDomainFilter
		r.fallbackLazyQuery = config.FallbackLazyQuery
	}

	return
}

var ParseNameServer func(servers []string) ([]NameServer, error) // define in config/config.go

// queryContext returns the parent context live caller queries run under, creating it on first
// use. ResetConnection deliberately does NOT cancel it -- see queryMu for why -- so the only
// thing that ends a live query early is the caller's own context or CloseQueries.
//
// After CloseQueries this returns an ALREADY-CANCELLED context rather than a fresh one, and that
// is the whole point of queryClosed. Lazily renewing here let shutdown resurrect the very
// goroutines it had just cancelled: exchangeWithoutCache retries on error (`r.group.DoChan` at
// the retry branch) and ExchangeContext's defer re-fires on context.Canceled, so cancelling a
// live query synthesised a fresh one under a brand-new live context -- restoring the
// outlives-the-core defect from the other direction. Upstream has no equivalent revival: closing
// the box closes the DNS router and its transports, and nothing rebuilds a service context on
// demand.
func (r *Resolver) queryContext() context.Context {
	r.queryMu.Lock()
	defer r.queryMu.Unlock()
	if r.queryClosed {
		return r.queryCtx
	}
	if r.queryCtx == nil || r.queryCtx.Err() != nil {
		r.queryCtx, r.queryCancel = context.WithCancel(context.Background())
	}
	return r.queryCtx
}

// CloseQueries cancels in-flight live queries as well as detached refreshes. This is the
// shutdown signal, and it is the ONLY caller allowed to end a live query: a Network Extension
// can restart in the same process, so up to one DNS timeout of goroutines must not survive the
// core they belong to. A path change is not a shutdown and must not call this.
// It is one-way on purpose. A core that has been shut down must not start serving again: the
// process can host the NEXT core, and that one gets its own Resolver. Leaving the door open is
// what let a cancelled query be retried straight back into existence.
func (r *Resolver) CloseQueries() {
	if r == nil {
		return
	}
	r.queryMu.Lock()
	cancel := r.queryCancel
	r.queryClosed = true
	if r.queryCtx == nil {
		// Nothing ever queried, so there is no context to cancel -- but queryContext must still
		// have a dead one to hand out from here on, because it returns r.queryCtx directly once
		// closed and a nil context would panic in the caller's context.WithTimeout. Building it
		// under queryMu is safe: context.WithCancel touches nothing this lock guards.
		dead, cancelDead := context.WithCancel(context.Background())
		cancelDead()
		r.queryCtx = dead
	}
	r.queryCancel = nil
	r.queryMu.Unlock()
	if cancel != nil {
		cancel()
	}
	if dr := r.defaultResolver; dr != nil {
		dr.CloseQueries()
	}
}
