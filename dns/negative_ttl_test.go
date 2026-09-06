package dns

import (
	"testing"
	"time"

	D "github.com/miekg/dns"
)

// Negative answers are cached exactly the way mihomo caches them: minimalTTL over
// Answer+Ns+Extra, with no branch for negativity at all.
//
// This file used to assert RFC 2308 section 5 instead -- a negative answer's lifetime is
// min(SOA MINIMUM, the SOA's header TTL) -- and that reading is the conformant one. Measured
// against live responses, amazon.com's NXDOMAIN via 1.1.1.1 carries a 7200 second header TTL
// where the RFC gives 60, so mihomo caches "this name does not exist" for two hours after a
// zone says one minute. Removing the fix reintroduces that, knowingly.
//
// It was removed anyway. Being more correct than mihomo is still being different from
// mihomo, and the promise this core makes is that a mihomo configuration behaves the way its
// author expects -- which is however mihomo behaves, bugs included. The same helper exists in
// sing-box (dns/client.go extractNegativeTTL), so "written from the RFC" also described a
// shape only the other project has. The fix belongs upstream, where every mihomo user gets it.
//
// These tests now pin the parity. If one of them fails, this core has drifted away from
// mihomo again -- check dns/util.go putMsgToCache against v1.19.29 before changing the test.

func negativeReply(t *testing.T, rcode int, soaHeaderTTL, soaMinimum uint32) *D.Msg {
	t.Helper()
	question := new(D.Msg)
	question.SetQuestion("absent.example.com.", D.TypeA)
	reply := new(D.Msg)
	reply.SetReply(question)
	reply.Rcode = rcode
	reply.Ns = []D.RR{&D.SOA{
		Hdr: D.RR_Header{
			Name: "example.com.", Rrtype: D.TypeSOA, Class: D.ClassINET, Ttl: soaHeaderTTL,
		},
		Ns: "ns.example.com.", Mbox: "root.example.com.", Minttl: soaMinimum,
	}}
	return reply
}

func cachedLifetime(t *testing.T, reply *D.Msg) (time.Duration, bool) {
	t.Helper()
	cache := Config{}.newCache()
	question := reply.Question[0]
	before := time.Now()
	putMsgToCache(cache, question, reply)
	_, expireAt, hit := getMsgFromCache(cache, question)
	if !hit {
		return 0, false
	}
	// Rounded UP: the expiry is computed from a clock read inside putMsgToCache, always a
	// hair after `before`, so the raw difference is a few hundred nanoseconds short of the
	// TTL and Round() lands it one second low.
	return expireAt.Sub(before).Truncate(time.Second) + time.Second, true
}

// The case the deviation existed for: an SOA MINIMUM well below its header TTL. mihomo takes
// the header TTL and never looks at MINIMUM, so this core does the same.
func TestNXDomainTakesTheSOAHeaderTTLLikeMihomo(t *testing.T) {
	lifetime, hit := cachedLifetime(t, negativeReply(t, D.RcodeNameError, 7200, 60))
	if !hit {
		t.Fatal("an NXDOMAIN carrying an SOA was not cached at all")
	}
	if lifetime != 7200*time.Second {
		t.Fatalf("cached for %v, want 7200s. mihomo's putMsgToCache takes minimalTTL over "+
			"Answer+Ns+Extra, which for a negative answer is the SOA's header TTL; bounding "+
			"it by SOA MINIMUM is RFC 2308 and is not what upstream does", lifetime)
	}
}

// NODATA -- NOERROR with no record of the requested type -- takes the same path, because
// mihomo has no negativity branch to take.
func TestNoDataTakesTheSameUnbranchedPath(t *testing.T) {
	lifetime, hit := cachedLifetime(t, negativeReply(t, D.RcodeSuccess, 1800, 30))
	if !hit {
		t.Fatal("a NODATA answer was not cached")
	}
	if lifetime != 1800*time.Second {
		t.Fatalf("cached for %v, want 1800s", lifetime)
	}
}

// A negative answer with no SOA is cached on whatever records it does carry. The removed
// version refused to cache it at all (RFC 2308: no SOA, no bound to count down); mihomo has
// no such rule, so the NSEC's own TTL decides.
func TestNegativeAnswerWithoutSOAIsStillCached(t *testing.T) {
	question := new(D.Msg)
	question.SetQuestion("absent.example.com.", D.TypeA)
	reply := new(D.Msg)
	reply.SetReply(question)
	reply.Rcode = D.RcodeNameError
	reply.Ns = []D.RR{&D.NSEC{
		Hdr: D.RR_Header{
			Name: "absent.example.com.", Rrtype: D.TypeNSEC, Class: D.ClassINET, Ttl: 300,
		},
		NextDomain: "next.example.com.",
	}}

	lifetime, hit := cachedLifetime(t, reply)
	if !hit {
		t.Fatal("mihomo caches this on the NSEC's TTL; refusing to cache it is the RFC's rule, not upstream's")
	}
	if lifetime != 300*time.Second {
		t.Fatalf("cached for %v, want 300s (the NSEC's own TTL)", lifetime)
	}
}

// A CNAME chain with no record of the requested type is negative in RFC 2308's sense, and
// mihomo caches it on the CNAME's TTL regardless. Pinned because this was the subtlest case
// the removed code handled: it is the one where "negative" is not visible from an empty
// answer section.
func TestCNAMEOnlyAnswerIsCachedOnTheCNAMETTL(t *testing.T) {
	question := new(D.Msg)
	question.SetQuestion("alias.example.com.", D.TypeA)
	reply := new(D.Msg)
	reply.SetReply(question)
	reply.Answer = []D.RR{&D.CNAME{
		Hdr: D.RR_Header{
			Name: "alias.example.com.", Rrtype: D.TypeCNAME, Class: D.ClassINET, Ttl: 3600,
		},
		Target: "target.example.com.",
	}}
	reply.Ns = []D.RR{&D.SOA{
		Hdr: D.RR_Header{
			Name: "example.com.", Rrtype: D.TypeSOA, Class: D.ClassINET, Ttl: 3600,
		},
		Ns: "ns.example.com.", Mbox: "root.example.com.", Minttl: 60,
	}}

	lifetime, hit := cachedLifetime(t, reply)
	if !hit {
		t.Fatal("a CNAME-only answer was not cached")
	}
	if lifetime != 3600*time.Second {
		t.Fatalf("cached for %v, want 3600s: mihomo sees records with a 3600 TTL and caches "+
			"for that; the SOA MINIMUM of 60 is the RFC's bound, not upstream's", lifetime)
	}
}

// Unchanged, and upstream's own: a zero minimal TTL means do not cache.
func TestZeroTTLIsStillNotCached(t *testing.T) {
	if _, hit := cachedLifetime(t, negativeReply(t, D.RcodeNameError, 0, 0)); hit {
		t.Fatal("an answer whose minimal TTL is zero was cached")
	}
}

// Also unchanged and also upstream's: SERVFAIL keeps its own five-second bound.
func TestServerFailureKeepsUpstreamsOwnBound(t *testing.T) {
	lifetime, hit := cachedLifetime(t, negativeReply(t, D.RcodeServerFailure, 7200, 60))
	if !hit {
		t.Fatal("a SERVFAIL was not cached")
	}
	want := time.Duration(serverFailureCacheTTL) * time.Second
	if lifetime != want {
		t.Fatalf("cached for %v, want %v (upstream's serverFailureCacheTTL)", lifetime, want)
	}
}
