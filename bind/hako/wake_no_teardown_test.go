package hako

import (
	"testing"

	"github.com/TokenPLS/Hako/tunnel/statistic"
)

// Wake() used to call CloseAllConnections(), killing every app's live session through
// the tunnel on every NEProvider.wake().
//
// That line was never decided. decided exactly two things: Pause() =
// debug.FreeOSMemory(), and Wake() = resolver.ResetConnection() "to drop DNS and
// underlying connections that may have died while asleep". The connection teardown
// arrived later inside b5180e96a ("core: harden iOS config and lifecycle gates"), a
// commit with a one-line message that does not mention it, and the code comment then
// cited for it. So restoring the decided behaviour is the fix, not a reversal of
// a decision.
//
// It is also where upstream landed independently: sing-box added an iOS-only 60s
// debounce around wake (e6885e996) and then removed the reset from sleep and wake on
// every platform (a031aaf2c).
//
// The genuine case -- the old sockets really being dead -- is already handled, and
// handled better, by bind/hako/monitor.go:79, which closes tracked connections only on
// an interface identity or address-family change. A sleep/wake pair is not evidence
// that anything died; a changed physical path is.

// TestWakeKeepsLiveConnections pins the restored contract. A momentary sleep/wake pair
// -- which iOS delivers routinely -- must not destroy work.
func TestWakeKeepsLiveConnections(t *testing.T) {
	service := &BoxService{running: true}

	tracker := &fakeTracker{}
	statistic.DefaultManager.Join(tracker)
	t.Cleanup(func() { statistic.DefaultManager.Leave(tracker) })

	before := service.wakeCount.Load()
	service.Wake()

	if tracker.closed {
		t.Fatal("Wake() closed a live connection; a sleep/wake pair is not evidence that the " +
			"connection died, and every app's session pays a TCP connect and a full TLS " +
			"handshake to recover -- one trustd round trip each on iOS")
	}
	if got := service.wakeCount.Load(); got != before+1 {
		t.Fatalf("wakeCount = %d, want %d", got, before+1)
	}
}

// TestPauseKeepsLiveConnections: Pause() has always been footprint-only, and must stay
// that way. Asserted so that a future change cannot quietly make sleep destructive
// either.
func TestPauseKeepsLiveConnections(t *testing.T) {
	service := &BoxService{running: true}

	tracker := &fakeTracker{}
	statistic.DefaultManager.Join(tracker)
	t.Cleanup(func() { statistic.DefaultManager.Leave(tracker) })

	before := service.pauseCount.Load()
	service.Pause()

	if tracker.closed {
		t.Fatal("Pause() closed a live connection; the useful action while asleep is shrinking " +
			"the footprint against jetsam, not discarding work")
	}
	if got := service.pauseCount.Load(); got != before+1 {
		t.Fatalf("pauseCount = %d, want %d", got, before+1)
	}
}

// TestCloseAllConnectionsStillWorks: the function itself is not the problem and remains
// the Clash /connections DELETE handler and the mode-switch path, where discarding flows
// is exactly what the caller asked for. Only its unconditional use on wake was wrong.
func TestCloseAllConnectionsStillWorks(t *testing.T) {
	tracker := &fakeTracker{}
	statistic.DefaultManager.Join(tracker)
	t.Cleanup(func() { statistic.DefaultManager.Leave(tracker) })

	CloseAllConnections()

	if !tracker.closed {
		t.Fatal("CloseAllConnections must still close tracked connections for its real callers")
	}
}
