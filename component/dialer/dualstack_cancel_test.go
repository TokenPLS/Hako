package dialer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

// Both legs of the dual-stack race used the caller's context, so a leg that lost -- or
// one that never finished at all -- held its dial open until the caller's own deadline,
// five seconds by default. On a phone that is a socket and a radio wake kept alive for
// nothing.
//
// The fallback ticker is a separate matter and is NOT dead code in general, contrary to
// how the finding was phrased. With prefer unset both legs get isPrimary=true, so
// fallback is never assigned and the ticker can never fire -- allocated and stopped for
// nothing on every dual-stack dial. With prefer explicitly 4 or 6 one leg is
// non-primary, fallback is assigned, and the ticker is live. So it is created only when
// it can fire, rather than deleted.
//
// Every leg's context is cancelled before returning, the winner's included. The first
// version spared the winner out of caution about a custom opt.netDialer still using its
// context; adversarial review showed that leaks a child context per successful dial, and
// cancelling it is safe by the contract net.Dialer documents. See
// TestDualStackDoesNotAccumulateChildContexts at the bottom of this file.

func TestDualStackCancelsTheLosingLegAtTheWin(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	var loserCancelled atomic.Bool
	loserDone := make(chan struct{})

	dialFn := func(ctx context.Context, network string, ips []netip.Addr, port string, opt option) (net.Conn, error) {
		if ips[0].Is6() {
			// The stalled leg: never completes on its own, so the only thing that can
			// release it is a cancel from the race.
			<-ctx.Done()
			loserCancelled.Store(true)
			close(loserDone)
			return nil, ctx.Err()
		}
		return net.Dial("tcp4", net.JoinHostPort("127.0.0.1", port))
	}

	// A caller deadline far longer than the test: if the leg were only released by the
	// caller's context, this test would time out rather than pass.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	conn, err := dualStackDialContext(ctx, dialFn,
		"tcp", []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")}, port, option{})
	if err != nil {
		t.Fatalf("the reachable leg must win: %v", err)
	}
	if conn == nil {
		t.Fatal("no connection returned")
	}

	// The winner must still be usable: cancelling the race must not have taken it out.
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("the winning connection is not usable after the race returned: %v", err)
	}
	_ = conn.Close()

	select {
	case <-loserDone:
	case <-time.After(2 * time.Second):
		t.Fatal("the losing leg was still dialling 2s after the win; it should be cancelled at " +
			"the win, not at the caller's deadline")
	}
	if !loserCancelled.Load() {
		t.Fatal("the losing leg ended without being cancelled")
	}
}

// TestDualStackStillReturnsTheFallbackWhenPreferIsSet guards the half that is not free:
// with prefer set, a non-primary success is held as fallback and returned if the primary
// fails. Cancelling losers must not break that.
func TestDualStackStillReturnsTheFallbackWhenPreferIsSet(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	failure := errors.New("primary refused")
	dialFn := func(ctx context.Context, network string, ips []netip.Addr, port string, opt option) (net.Conn, error) {
		if ips[0].Is6() {
			return nil, failure // prefer 6 makes this the primary
		}
		return net.Dial("tcp4", net.JoinHostPort("127.0.0.1", port))
	}

	conn, err := dualStackDialContext(context.Background(), dialFn,
		"tcp", []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")}, port,
		option{prefer: 6})
	if err != nil {
		t.Fatalf("a failed primary must fall back to the non-primary success: %v", err)
	}
	if conn == nil {
		t.Fatal("no connection returned")
	}
	_ = conn.Close()
}

// TestDualStackReturnsBothFailures: cancelling losers must not swallow the error report
// when neither leg succeeds.
func TestDualStackReturnsBothFailures(t *testing.T) {
	primary := errors.New("v6 refused")
	secondary := errors.New("v4 refused")
	dialFn := func(ctx context.Context, network string, ips []netip.Addr, port string, opt option) (net.Conn, error) {
		if ips[0].Is6() {
			return nil, primary
		}
		return nil, secondary
	}

	_, err := dualStackDialContext(context.Background(), dialFn,
		"tcp", []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")}, "443", option{})
	if err == nil {
		t.Fatal("both legs failed; an error must be returned")
	}
	if !errors.Is(err, primary) || !errors.Is(err, secondary) {
		t.Fatalf("both failures must be reported, got %v", err)
	}
}

// TestDualStackDoesNotAccumulateChildContexts: the winner's cancel must be called too.
//
// Found by adversarial review of the first version, which skipped the winner's cancel to
// avoid any chance of breaking its connection. Go retains a cancellable child in its
// parent's children set until the child's cancel or the parent's runs, so one uncancelled
// child per successful dial accumulates for as long as the parent lives. Reproduced
// independently: five dials left five children on the parent.
//
// Bounded in the tunnel path, where the parent is a per-dial WithTimeout that the caller
// cancels -- but unbounded for any caller passing a long-lived context, and the fix costs
// nothing.
//
// Cancelling the winner is safe, and the codebase already proves it: tunnel.go creates the
// dial context with WithTimeout plus defer cancel and then uses the returned connection
// long afterwards. A connection surviving cancellation of the context it was dialled on is
// already load-bearing here, which is also exactly what net.Dialer documents.
func TestDualStackDoesNotAccumulateChildContexts(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	dialFn := func(ctx context.Context, network string, ips []netip.Addr, port string, opt option) (net.Conn, error) {
		if ips[0].Is6() {
			return nil, errors.New("v6 unreachable")
		}
		return net.Dial("tcp4", net.JoinHostPort("127.0.0.1", port))
	}

	// A long-lived parent, which is the shape where the accumulation is unbounded.
	parent, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()

	for i := 0; i < 20; i++ {
		conn, err := dualStackDialContext(parent, dialFn,
			"tcp", []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")}, port, option{})
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		// The connection must still be usable after the race released its context.
		if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatalf("dial %d returned an unusable connection: %v", i, err)
		}
		_ = conn.Close()
	}

	if children := parentChildCount(parent); children != 0 {
		t.Fatalf("20 dials left %d child contexts on a long-lived parent, want 0; each "+
			"uncancelled winner is retained until the parent is cancelled", children)
	}
}

// parentChildCount reads the unexported children set of a cancelCtx. Reflection is the only
// way to observe this from outside context, and observing it is the point: the leak is
// invisible to go vet's lostcancel, which cannot follow a CancelFunc stored in a slice.
func parentChildCount(parent context.Context) int {
	value := reflect.ValueOf(parent)
	if value.Kind() == reflect.Ptr {
		value = value.Elem()
	}
	field := value.FieldByName("children")
	if !field.IsValid() {
		return -1
	}
	return field.Len()
}
