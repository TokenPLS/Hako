package router

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/TokenPLS/Hako/component/cidr"
	"github.com/TokenPLS/Hako/component/geodata/strmatcher"
	"github.com/TokenPLS/Hako/component/trie"
)

var matcherTypeMap = map[Domain_Type]strmatcher.Type{
	Domain_Plain:  strmatcher.Substr,
	Domain_Regex:  strmatcher.Regex,
	Domain_Domain: strmatcher.Domain,
	Domain_Full:   strmatcher.Full,
}

func domainToMatcher(domain *Domain) (strmatcher.Matcher, error) {
	matcherType, f := matcherTypeMap[domain.Type]
	if !f {
		return nil, fmt.Errorf("unsupported domain type %v", domain.Type)
	}

	matcher, err := matcherType.New(domain.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to create domain matcher, base error: %s", err.Error())
	}

	return matcher, nil
}

type DomainMatcher interface {
	ApplyDomain(string) bool
	Count() int
}

type succinctDomainMatcher struct {
	set           *trie.DomainSet
	otherMatchers []strmatcher.Matcher
	count         int
}

func (m *succinctDomainMatcher) ApplyDomain(domain string) bool {
	isMatched := m.set.Has(domain)
	if !isMatched {
		for _, matcher := range m.otherMatchers {
			isMatched = matcher.Match(domain)
			if isMatched {
				break
			}
		}
	}
	return isMatched
}

func (m *succinctDomainMatcher) Count() int {
	return m.count
}

func NewSuccinctMatcherGroup(domains []*Domain) (DomainMatcher, error) {
	t := trie.New[struct{}]()
	m := &succinctDomainMatcher{
		count: len(domains),
	}
	for _, d := range domains {
		switch d.Type {
		case Domain_Plain, Domain_Regex:
			matcher, err := matcherTypeMap[d.Type].New(d.Value)
			if err != nil {
				return nil, err
			}
			m.otherMatchers = append(m.otherMatchers, matcher)

		case Domain_Domain:
			err := t.Insert("+."+d.Value, struct{}{})
			if err != nil {
				return nil, err
			}

		case Domain_Full:
			err := t.Insert(d.Value, struct{}{})
			if err != nil {
				return nil, err
			}
		}
	}
	m.set = t.NewDomainSet()
	return m, nil
}

type v2rayDomainMatcher struct {
	matchers strmatcher.IndexMatcher
	count    int
}

func NewMphMatcherGroup(domains []*Domain) (DomainMatcher, error) {
	g := strmatcher.NewMphMatcherGroup()
	for _, d := range domains {
		matcherType, f := matcherTypeMap[d.Type]
		if !f {
			return nil, fmt.Errorf("unsupported domain type %v", d.Type)
		}
		_, err := g.AddPattern(d.Value, matcherType)
		if err != nil {
			return nil, err
		}
	}
	g.Build()
	return &v2rayDomainMatcher{
		matchers: g,
		count:    len(domains),
	}, nil
}

func (m *v2rayDomainMatcher) ApplyDomain(domain string) bool {
	return len(m.matchers.Match(strings.ToLower(domain))) > 0
}

func (m *v2rayDomainMatcher) Count() int {
	return m.count
}

type notDomainMatcher struct {
	DomainMatcher
}

func (m notDomainMatcher) ApplyDomain(domain string) bool {
	return !m.DomainMatcher.ApplyDomain(domain)
}

func NewNotDomainMatcherGroup(matcher DomainMatcher) DomainMatcher {
	return notDomainMatcher{matcher}
}

type IPMatcher interface {
	Match(ip netip.Addr) bool
	Count() int
}

type geoIPMatcher struct {
	cidrSet *cidr.IpCidrSet
	count   int
}

// Match returns true if the given ip is included by the GeoIP.
func (m *geoIPMatcher) Match(ip netip.Addr) bool {
	return m.cidrSet.IsContain(ip)
}

func (m *geoIPMatcher) Count() int {
	return m.count
}

func NewGeoIPMatcher(cidrList []*CIDR) (IPMatcher, error) {
	m := &geoIPMatcher{
		cidrSet: cidr.NewIpCidrSet(),
		count:   len(cidrList),
	}
	for _, cidr := range cidrList {
		addr, ok := netip.AddrFromSlice(cidr.Ip)
		if !ok {
			return nil, fmt.Errorf("error when loading GeoIP: invalid IP: %s", cidr.Ip)
		}
		err := m.cidrSet.AddIpCidr(netip.PrefixFrom(addr, int(cidr.Prefix)))
		if err != nil {
			return nil, fmt.Errorf("error when loading GeoIP: %w", err)
		}
	}
	err := m.cidrSet.Merge()
	if err != nil {
		return nil, err
	}

	return m, nil
}

// NewGeoIPMatcherFromCidrSet wraps a set that is already built.
//
// NewGeoIPMatcher above takes decoded source records and constructs the set from them,
// which is the expensive half: on the shipped GeoIP.dat that path peaks at 130 MiB for one
// country code. A compiled artifact restores the finished set directly, and this is the
// seam that lets it become a matcher without the decode ever happening.
//
// count comes from the artifact rather than the set because it is the number of source
// records the set was built from, which Merge has already collapsed and the set can no
// longer report.
func NewGeoIPMatcherFromCidrSet(set *cidr.IpCidrSet, count int) (IPMatcher, error) {
	if set == nil {
		return nil, fmt.Errorf("nil cidr set")
	}
	return &geoIPMatcher{cidrSet: set, count: count}, nil
}

type notIPMatcher struct {
	IPMatcher
}

func (m notIPMatcher) Match(ip netip.Addr) bool {
	return !m.IPMatcher.Match(ip)
}

func NewNotIpMatcherGroup(matcher IPMatcher) IPMatcher {
	return notIPMatcher{matcher}
}

// ResidualDomain is a category entry a compact domain set cannot hold.
//
// A succinct set answers suffix and exact questions. A category may also carry
// keyword and regex entries — geosite:private has one regex among 131 entries —
// and dropping them to make the set writable would quietly change what the
// category matches. They are small enough to carry alongside verbatim.
type ResidualDomain struct {
	Type  Domain_Type
	Value string
}

// NewSuccinctMatcherFromParts assembles a matcher from an already-built set and
// the entries that did not fit in it.
//
// The other constructor takes source domains and builds the set, which costs an
// order of magnitude more memory than the set itself; this one exists so a
// compiled artifact can be used without paying that again.
func NewSuccinctMatcherFromParts(
	set *trie.DomainSet, count int, residual []ResidualDomain,
) (DomainMatcher, error) {
	matcher := &succinctDomainMatcher{set: set, count: count}
	for _, entry := range residual {
		matcherType, known := matcherTypeMap[entry.Type]
		if !known {
			return nil, fmt.Errorf("unsupported domain type %v", entry.Type)
		}
		built, err := matcherType.New(entry.Value)
		if err != nil {
			return nil, err
		}
		matcher.otherMatchers = append(matcher.otherMatchers, built)
	}
	return matcher, nil
}

// CompileDomains splits a category into the part a compact set can hold and the
// part it cannot, without building a matcher.
//
// Compiling is deliberately not "load the matcher and take its set": that route
// goes through the loader's cache, and a process whose preflight ran as the
// tunnel would — which is exactly what the App does — has an empty matcher
// cached for every category it declined to decode. Compiling from that cache
// produced an artifact holding nothing and reported success.
func CompileDomains(domains []*Domain) (*trie.DomainSet, int, []ResidualDomain, error) {
	tree := trie.New[struct{}]()
	var residual []ResidualDomain
	for _, domain := range domains {
		switch domain.Type {
		case Domain_Plain, Domain_Regex:
			residual = append(residual, ResidualDomain{Type: domain.Type, Value: domain.Value})
		case Domain_Domain:
			if err := tree.Insert("+."+domain.Value, struct{}{}); err != nil {
				return nil, 0, nil, err
			}
		case Domain_Full:
			if err := tree.Insert(domain.Value, struct{}{}); err != nil {
				return nil, 0, nil, err
			}
		}
	}
	return tree.NewDomainSet(), len(domains), residual, nil
}

// A resource this runtime could not build, kept distinct from a resource that is genuinely
// empty.
//
// The distinction is not cosmetic. A degraded matcher that merely returns false gets
// wrapped by NewNotIpMatcherGroup / NewNotDomainMatcherGroup when the configuration wrote
// a leading '!', and !false is true for EVERYTHING -- so `GEOIP,!CN,PROXY` with cn
// unavailable stops being "cn does not match" and becomes "every address matches", killing
// every rule below it and sending domestic traffic through the proxy. Same shape for
// dns.fallback-filter.geoip, where the filter computes !Match and would judge every answer
// polluted.
//
// Callers ask Unavailable() before negating, so an unavailable resource stays inert in
// both spellings.
type unavailableIPMatcher struct{}

func (unavailableIPMatcher) Match(netip.Addr) bool { return false }
func (unavailableIPMatcher) Count() int            { return 0 }

func NewUnavailableIPMatcher() IPMatcher { return unavailableIPMatcher{} }

type unavailableDomainMatcher struct{}

func (unavailableDomainMatcher) ApplyDomain(string) bool { return false }
func (unavailableDomainMatcher) Count() int              { return 0 }

func NewUnavailableDomainMatcher() DomainMatcher { return unavailableDomainMatcher{} }

// Unavailable reports whether a matcher stands for a resource that could not be built, so
// a caller knows not to negate it.
func Unavailable(matcher any) bool {
	switch matcher.(type) {
	case unavailableIPMatcher, unavailableDomainMatcher:
		return true
	}
	return false
}
