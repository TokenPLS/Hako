package dns

import (
	"context"
	"testing"
	"time"

	D "github.com/miekg/dns"
)

// A reset must not cancel a live caller's query.
//
// Giving queries a cancellable lifetime instead of context.Background() was right. Making
// ResetConnection the thing that cancels it was not, and that is what shipped. singleflight
// shares one fn between detached refreshes and live caller queries, so the fn's context governs
// both -- there is no level at which a reset could reach only the refreshes.
//
// component/resolver/resolver.go:268 is what makes it bite rather than being theoretical:
//
//	func ResetConnection() { eachConfiguredResolver(func(r Resolver) { go r.ResetConnection() }) }
//
// The reset runs in its own goroutine, so it races whatever queries are in flight -- and on
// Apple a reset fires on every default-interface change, i.e. on every Wi-Fi to cellular
// switch. The observable result was SERVFAIL handed back to the app for a query that had a
// perfectly good upstream: `dial udp 127.0.0.1:59027: operation was canceled` with the
// caller's own context still healthy.
//
// It was caught by TestControlledDNSOutbound{UDP,TCP}Interop in bind/hako, which went red at
// bbc7b4c13 and stayed red -- the gate that runs those tests had not been run on main since.
//
// Upstream does not do this. sing-box's live queries run under the service context passed to
// NewClient (dns/client.go), and ResetNetwork closes connections and clears the cache without
// touching it. Cancelling live queries on a path change is ours, and it was never a decision.
func TestResetConnectionDoesNotCancelALiveQuery(t *testing.T) {
	client := &refetchCountingClient{block: make(chan struct{})}
	resolver := &Resolver{
		main:  []dnsClient{client},
		cache: Config{}.newCache(),
	}

	question := new(D.Msg)
	question.SetQuestion("live.example.com.", D.TypeA)

	// No cache entry, so this is a live query rather than a stale hit with a refresh behind it.
	done := make(chan error, 1)
	go func() {
		_, err := resolver.ExchangeContext(context.Background(), question)
		done <- err
	}()

	deadline := time.Now().Add(2 * time.Second)
	for client.started.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if client.started.Load() == 0 {
		t.Fatal("the live query never reached the client; this test would prove nothing")
	}

	resolver.ResetConnection()

	// Give the cancellation the same window the refetch test gives it, then require that it
	// did NOT happen. A reset is allowed to drop connections and cached answers; it is not
	// allowed to fail a query the caller is still waiting on.
	time.Sleep(300 * time.Millisecond)
	if got := client.cancels.Load(); got != 0 {
		t.Fatalf("ResetConnection cancelled %d live query/queries; the caller gets SERVFAIL for "+
			"a lookup whose upstream was fine, and on Apple this fires on every "+
			"default-interface change", got)
	}

	close(client.block)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the live query never returned after the client was unblocked")
	}
}

// TestShutdownStillCancelsRefetches guards the other direction: making a reset harmless must not
// quietly undo the fix that gave queries a cancellable lifetime at all. Restated here, next to
// the assertion it trades against, so a change that re-collapses them fails both files.
func TestShutdownStillCancelsRefetches(t *testing.T) {
	client := &refetchCountingClient{block: make(chan struct{})}
	resolver := &Resolver{
		main:  []dnsClient{client},
		cache: Config{}.newCache(),
		// Nothing to arm: mihomo serves a stale hit unconditionally and fires the refresh
		// so the expired entry seeded below is served and a refresh fires.
	}

	question := new(D.Msg)
	question.SetQuestion("stale-after-split.example.com.", D.TypeA)
	answer := new(D.Msg)
	answer.SetReply(question)
	answer.Answer = []D.RR{&D.A{Hdr: D.RR_Header{
		Name: "stale-after-split.example.com.", Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 1,
	}}}
	// Expired, so it is served stale and fires a refresh -- mihomo has no window and no
	// hard-miss path for an expired entry.
	resolver.cache.SetWithExpire(question.Question[0].String(), answer, time.Now().Add(-time.Minute))

	if _, err := resolver.ExchangeContext(context.Background(), question); err != nil {
		t.Fatalf("a stale hit expired and served stale (mihomo has no window) must still be served: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for client.started.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if client.started.Load() == 0 {
		t.Fatal("a stale hit must fire a refresh")
	}

	resolver.CloseQueries()

	deadline = time.Now().Add(2 * time.Second)
	for client.cancels.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if client.cancels.Load() == 0 {
		t.Fatal("shutdown stopped cancelling detached refreshes; those must not outlive the " +
			"core they belong to")
	}
}

// TestShutdownDoesNotResurrectTheQueryItCancelled is the assertion the first version of these
// tests was missing, and an adversarial review is what surfaced the gap: they only checked that a
// cancel was OBSERVED, never that nothing started afterwards. A query that was cancelled and then
// immediately re-launched satisfies "at least one cancel" while leaving the goroutine running.
//
// Two paths re-enter the query machinery on exactly the error a shutdown produces:
//
//   - exchangeWithoutCache's retry branch calls r.group.DoChan(q.String(), fn) when the result
//     carried an error;
//   - ExchangeContext's defer re-fires on errors.Is(err, context.Canceled).
//
// Both call queryContext(), which used to build a FRESH live context whenever the old one was
// cancelled -- so shutdown cancelled a query and then handed its replacement a healthy context.
// That is the outlives-the-core defect the query lifetime exists to prevent, reintroduced from
// the other side. queryClosed is what makes CloseQueries one-way.
func TestShutdownDoesNotResurrectTheQueryItCancelled(t *testing.T) {
	client := &refetchCountingClient{block: make(chan struct{})}
	resolver := &Resolver{main: []dnsClient{client}, cache: Config{}.newCache()}

	question := new(D.Msg)
	question.SetQuestion("resurrect.example.com.", D.TypeA)
	go func() { _, _ = resolver.ExchangeContext(context.Background(), question) }()

	deadline := time.Now().Add(2 * time.Second)
	for client.started.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	started := client.started.Load()
	if started == 0 {
		t.Fatal("the live query never reached the client")
	}

	resolver.CloseQueries()

	deadline = time.Now().Add(2 * time.Second)
	for client.cancels.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if client.cancels.Load() == 0 {
		t.Fatal("shutdown did not cancel the in-flight query")
	}

	// The retry and the defer both get their chance inside this window.
	//
	// What must hold is not "nothing enters the client again" -- the retry does re-enter, and the
	// counting client increments on entry before it looks at its context, so a bare
	// started-is-unchanged assertion fails on a query that returned instantly. What must hold is
	// that nothing is still RUNNING: with a dead parent context every re-entry observes
	// ctx.Done() at once and returns, so started and finished converge. A resurrected query is
	// precisely one that does NOT finish -- it runs on for up to DefaultDNSTimeout, which is the
	// goroutine-outlives-the-core defect.
	time.Sleep(400 * time.Millisecond)
	entered, done := client.started.Load(), client.finished.Load()
	if entered != done {
		t.Fatalf("%d of %d queries are still running after shutdown; a cancelled query was "+
			"retried under a freshly built live context and outlives the core that owned it",
			entered-done, entered)
	}
	if entered > started+3 {
		t.Fatalf("client entered %d times after shutdown (was %d); even instant returns should "+
			"be bounded by the retry limit, so this is a loop", entered-started, started)
	}

	// And queryContext must keep handing out a dead context rather than reviving on the next call.
	if err := resolver.queryContext().Err(); err == nil {
		t.Fatal("queryContext returned a live context after CloseQueries; the next query would " +
			"run under a core that has been shut down")
	}
}
