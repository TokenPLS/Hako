package dns

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	D "github.com/miekg/dns"
)

// A cache hit past its expiry is served with its TTL rewritten to 1 and a detached
// goroutine is fired to refresh it. That goroutine was rooted at context.Background(), so
// nothing could cancel it: shutdownCore could not, and neither could a path change. Up to
// one DNS timeout of goroutines therefore survived the core they belonged to, querying
// upstreams over a network path that was being torn down.
//
// The fix roots them at a context the CORE owns, cancelled by CloseQueries -- shutdown --
// and by nothing else.
//
// The first version of this fix cancelled on ResetConnection instead, reasoning that a path
// change discards the state a refresh is querying over. That was wrong twice over. singleflight
// shares one fn between refreshes and live caller queries, so the fn's context governs both:
// tying it to a reset meant every default-interface change cancelled in-flight USER lookups and
// returned SERVFAIL for a query whose upstream was fine. And upstream does not do it either --
// sing-box's ResetNetwork drops connections and clears the cache without touching the client
// context. See and dns.Resolver's queryMu.
//
// Not fixed here: the unbounded stale window. Closed separately, and the reason
// given here for deferring it turned out to be wrong -- there was no "hard miss makes DNS
// block where it used to answer instantly" trade-off to weigh, because upstream's optimistic
// mode is a BOUNDED window (dns/client.go:418, default 3*24h) rather than a hard miss. See
// optimisticStaleWindow in dns/util.go.

type refetchCountingClient struct {
	started  atomic.Int64
	finished atomic.Int64
	cancels  atomic.Int64
	block    chan struct{}
}

func (c *refetchCountingClient) ExchangeContext(ctx context.Context, m *D.Msg) (*D.Msg, error) {
	c.started.Add(1)
	defer c.finished.Add(1)
	select {
	case <-c.block:
		return nil, context.Canceled
	case <-ctx.Done():
		c.cancels.Add(1)
		return nil, ctx.Err()
	}
}

func (c *refetchCountingClient) Address() string { return "refetch-counting" }

func (c *refetchCountingClient) ResetConnection() {}

func TestShutdownCancelsInFlightRefetches(t *testing.T) {
	client := &refetchCountingClient{block: make(chan struct{})}
	resolver := &Resolver{
		main:  []dnsClient{client},
		cache: Config{}.newCache(),
		// Optimistic serving is opt-in and off by default since, so a test whose premise is
		// "a stale hit is served and fires a refresh" must arm it. At the default the seeded entry
		// is a hard miss and there is no refresh to cancel -- the test would pass vacuously or, as
		// it did, fail on the upstream it was never meant to reach.
	}

	question := new(D.Msg)
	question.SetQuestion("stale.example.com.", D.TypeA)

	// Seed an entry that is already past its expiry, which is what makes the exchange
	// serve it and fire a detached refresh.
	answer := new(D.Msg)
	answer.SetReply(question)
	answer.Answer = []D.RR{&D.A{
		Hdr: D.RR_Header{Name: "stale.example.com.", Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 1},
	}}
	resolver.cache.SetWithExpire(question.Question[0].String(), answer, time.Now().Add(-time.Minute))

	if _, err := resolver.ExchangeContext(context.Background(), question); err != nil {
		t.Fatalf("a stale hit must still be served: %v", err)
	}

	// Wait for the detached refresh to be in flight.
	deadline := time.Now().Add(2 * time.Second)
	for client.started.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if client.started.Load() == 0 {
		t.Fatal("a stale hit must fire a refresh; without one this test proves nothing")
	}

	resolver.CloseQueries()

	deadline = time.Now().Add(2 * time.Second)
	for client.cancels.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if client.cancels.Load() == 0 {
		t.Fatal("shutdown did not cancel the in-flight refresh; it would outlive the core it " +
			"belongs to, and this process can host the next one")
	}
}

// TestRefetchesWorkAgainAfterAReset: a RESET must not be a one-way door. It drops connections and
// normal service continues, so refreshes have to keep working afterwards.
//
// The comment here used to claim it covered "shut down and serve again", which it never did -- it
// only calls ResetConnection, and after that does not touch the query context at all. It
// also would have been claiming the wrong invariant: CloseQueries IS one-way by design ('s
// queryClosed), because a core that has been shut down must not serve again; the next core gets
// its own Resolver. TestShutdownDoesNotResurrectTheQueryItCancelled is what covers that side.
func TestRefetchesWorkAgainAfterAReset(t *testing.T) {
	client := &refetchCountingClient{block: make(chan struct{})}
	close(client.block) // return immediately rather than blocking
	resolver := &Resolver{
		main:  []dnsClient{client},
		cache: Config{}.newCache(),
		// Optimistic serving is opt-in and off by default since, so a test whose premise is
		// "a stale hit is served and fires a refresh" must arm it. At the default the seeded entry
		// is a hard miss and there is no refresh to cancel -- the test would pass vacuously or, as
		// it did, fail on the upstream it was never meant to reach.
	}
	resolver.ResetConnection()

	question := new(D.Msg)
	question.SetQuestion("after-reset.example.com.", D.TypeA)
	answer := new(D.Msg)
	answer.SetReply(question)
	answer.Answer = []D.RR{&D.A{
		Hdr: D.RR_Header{Name: "after-reset.example.com.", Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 1},
	}}
	resolver.cache.SetWithExpire(question.Question[0].String(), answer, time.Now().Add(-time.Minute))

	if _, err := resolver.ExchangeContext(context.Background(), question); err != nil {
		t.Fatalf("serving a stale hit after a reset: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for client.started.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if client.started.Load() == 0 {
		t.Fatal("no refresh fired after a reset; the refetch context must be renewed, not " +
			"left cancelled forever")
	}
}

// TestOneCallerCancellingDoesNotKillSharedQuery pins the reason singleflight re-roots away
// from the caller in the first place, so that reason survives this change. Many callers can
// wait on one question; if the shared query ran on the first caller's context, that caller
// walking away would fail everyone else. Rooting at the resolver keeps them independent.
func TestOneCallerCancellingDoesNotKillSharedQuery(t *testing.T) {
	client := &refetchCountingClient{block: make(chan struct{})}
	resolver := &Resolver{main: []dnsClient{client}, cache: Config{}.newCache()}

	question := new(D.Msg)
	question.SetQuestion("shared.example.com.", D.TypeA)

	// A caller that gives up almost immediately.
	impatient, cancelImpatient := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = resolver.ExchangeContext(impatient, question)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for client.started.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if client.started.Load() == 0 {
		t.Fatal("the upstream query never started")
	}

	cancelImpatient()
	<-done

	// The shared query must still be running: only the caller left.
	time.Sleep(100 * time.Millisecond)
	if client.cancels.Load() != 0 {
		t.Fatal("one caller cancelling aborted the shared upstream query; every other caller " +
			"waiting on the same question would have failed with it")
	}

	// A reset must NOT stop it: that is the regression this file now guards against, and
	// live_query_lifecycle_test.go states it directly.
	resolver.ResetConnection()
	time.Sleep(100 * time.Millisecond)
	if client.cancels.Load() != 0 {
		t.Fatal("ResetConnection aborted the shared upstream query; on Apple that fires on " +
			"every default-interface change")
	}

	// Shutdown still can, which is the property the context exists for.
	resolver.CloseQueries()
	deadline = time.Now().Add(2 * time.Second)
	for client.cancels.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if client.cancels.Load() == 0 {
		t.Fatal("the core could not stop its own query at shutdown")
	}
}
