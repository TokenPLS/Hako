package dns

import (
	"github.com/TokenPLS/Hako/component/trie"
	C "github.com/TokenPLS/Hako/constant"
)

type dnsPolicy interface {
	Match(domain string) []dnsClient
	// Clients returns every client this policy can hand out, so lifecycle operations
	// can reach them. Without it Resolver.ResetConnection and ClearCache walked only
	// main/fallback/default and silently skipped every policy client -- a hole that
	// cannot be seen from the resolution path, because Match is all resolution needs.
	Clients() []dnsClient
}

type domainTriePolicy struct {
	*trie.DomainTrie[[]dnsClient]
}

func (p domainTriePolicy) Clients() []dnsClient {
	if p.DomainTrie == nil {
		return nil
	}
	// Deduplicated by identity. One insert can occupy two nodes -- "+.example.com" stores
	// its data under both the exact base and the dot-wildcard child, which the trie's own
	// Foreach test records -- and one nameserver is commonly shared across several policy
	// entries. Without this a single client is reset more than once, and a duplicate that
	// lands after a query has already rebuilt a DoH or DoQ transport would close the new
	// one.
	seen := make(map[dnsClient]struct{})
	var clients []dnsClient
	p.DomainTrie.Foreach(func(domain string, data []dnsClient) bool {
		for _, client := range data {
			if _, duplicate := seen[client]; duplicate {
				continue
			}
			seen[client] = struct{}{}
			clients = append(clients, client)
		}
		return true
	})
	return clients
}

func (p domainTriePolicy) Match(domain string) []dnsClient {
	record := p.DomainTrie.Search(domain)
	if record != nil {
		return record.Data()
	}
	return nil
}

type domainMatcherPolicy struct {
	matcher    C.DomainMatcher
	dnsClients []dnsClient
}

func (p domainMatcherPolicy) Clients() []dnsClient {
	return p.dnsClients
}

func (p domainMatcherPolicy) Match(domain string) []dnsClient {
	if p.matcher.MatchDomain(domain) {
		return p.dnsClients
	}
	return nil
}
