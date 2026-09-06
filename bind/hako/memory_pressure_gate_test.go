package hako

import (
	"testing"

	"github.com/TokenPLS/Hako/tunnel/statistic"
)

// A memory-pressure NOTIFICATION must never close a tracked connection.
//
// The scope of that claim is the point. Upstream sheds too, just not from here -- see the
// correction below.
//
// A critical pressure event is device-wide: it is raised by whatever the machine is doing,
// most often another application, and XNU re-notifies roughly every 25 seconds for as long as
// the episode lasts. handleMemoryPressure answered every one by closing every tracked
// connection, killing every app's live session through the tunnel at once. At a typical
// Extension footprint of ~18 MiB against a ~50 MiB budget that shed almost nothing, and each
// app-side recovery then paid a fresh TCP connect and a full TLS handshake -- on Apple
// platforms every handshake is an XPC round trip to trustd, so the teardown was a volume
// multiplier on a separate defect.
//
// That was first narrowed to fire only when this task's own footprint was near its configured
// budget, then removed entirely.
//
// CORRECTION to what this comment used to claim. sing-box's darwin pressure callback logs,
// writes a throttled OOM draft, and notifies a timer -- it does not shed, and that is what
// these tests pin. But sing-box DOES shed from a different trigger: its adaptive timer polls
// memory itself, runs a three-state hysteresis machine, and on crossing into the triggered
// state calls NetworkManager.ResetNetwork, whose first statement is connectionManager.CloseAll
// (route/network.go). So "sing-box never closes connections" was wrong; it never closes them
// in response to the OS notification.
//
// These tests therefore assert something narrower and still true: the NOTIFICATION path does
// not shed. The threshold machine that would shed on measured evidence does not exist here
// yet -- in MACOS-UPSTREAM-PARITY-TODO.md.
//
// These tests assert the ABSENCE of an action, which is worth nothing unless the probe would
// actually observe that action. So the probe is registered with the real
// statistic.DefaultManager -- the same registry the removed teardown walked -- and
// TestTheProbeWouldSeeATeardown closes it through that registry to prove the observation
// works.

// pressureProbe is a statistic.Tracker that records whether it was closed. Only Close and ID
// are reached by the registry walk; the embedded interface supplies the rest and would panic
// if anything else were called, which is the desired outcome for an unexpected call.
type pressureProbe struct {
	statistic.Tracker
	id     string
	closed int
}

func (p *pressureProbe) Close() error {
	p.closed++
	return nil
}

func (p *pressureProbe) ID() string { return p.id }

func newPressureProbe(t *testing.T, id string) *pressureProbe {
	t.Helper()
	probe := &pressureProbe{id: id}
	statistic.DefaultManager.Join(probe)
	t.Cleanup(func() { statistic.DefaultManager.Leave(probe) })
	return probe
}

func TestMemoryPressureNeverClosesConnections(t *testing.T) {
	// This gate pins the NOTIFICATION path alone. Shedding is the threshold
	// machine's job and its default now; park the machine on an idle mode so
	// the pokes below cannot reach a live one armed by an earlier test.
	startPressureThresholdMonitor(0, pressureThresholdShedEnabled.Load())
	cases := []struct {
		name      string
		footprint int64
		softLimit int64
		why       string
	}{
		{
			name:      "far below any budget",
			footprint: 18 << 20,
			softLimit: 50 << 20,
			why:       "the measured steady state of the iOS Extension",
		},
		{
			name:      "at the budget, which the narrowed gate shed on",
			footprint: 49 << 20,
			softLimit: 50 << 20,
			why:       "the narrowed gate fired here; sing-box still does not",
		},
		{
			name:      "over the budget",
			footprint: 60 << 20,
			softLimit: 50 << 20,
			why:       "exceeding it is jetsam's business, not ours to pre-empt by killing sessions",
		},
		{
			name:      "no budget configured, as the macOS profiles run",
			footprint: 2 << 30,
			softLimit: 0,
			why:       "sing-box reaches for its NE regime only under C.IsIos, so macOS has none",
		},
		{
			name:      "footprint unavailable",
			footprint: -1,
			softLimit: 50 << 20,
			why:       "acting without a measurement is what was removed, not a fallback for it",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			probe := newPressureProbe(t, "pressure-"+testCase.name)

			before := memoryPressureEventCount.Load()
			// Repeated notifications, because XNU re-notifies for the duration of the episode.
			for i := 0; i < 4; i++ {
				handleMemoryPressureWith(testCase.footprint, testCase.softLimit)
			}

			if probe.closed != 0 {
				t.Fatalf("pressure closed the connection %d time(s) at footprint=%d softLimit=%d — %s",
					probe.closed, testCase.footprint, testCase.softLimit, testCase.why)
			}
			if got := memoryPressureEventCount.Load() - before; got != 4 {
				t.Fatalf("pressure event count rose by %d, want 4; that counter is the only "+
					"remaining signal that the episode happened at all", got)
			}
		})
	}
}

// TestTheProbeWouldSeeATeardown keeps the tests above from going vacuous. If a future change
// made the probe unreachable from statistic.DefaultManager -- a different registry, a Join
// that silently drops it -- every no-teardown assertion would pass while proving nothing.
func TestTheProbeWouldSeeATeardown(t *testing.T) {
	probe := newPressureProbe(t, "pressure-observability")

	found := false
	statistic.DefaultManager.Range(func(tracker statistic.Tracker) bool {
		if tracker == statistic.Tracker(probe) {
			found = true
			_ = tracker.Close()
			return false
		}
		return true
	})

	if !found {
		t.Fatal("the probe is not reachable from statistic.DefaultManager.Range, which is the " +
			"registry the removed teardown walked; the no-teardown assertions would be vacuous")
	}
	if probe.closed != 1 {
		t.Fatalf("closing through the registry recorded %d closes, want 1", probe.closed)
	}
}

// TestPressureHandlingSurvivesAnEvidenceWriteFailure: releasing pages is the one thing
// pressure handling must always do, and it happens after the evidence write. A write that
// fails -- unwritable container, full disk, or simply no Setup yet -- must not skip it.
func TestPressureHandlingSurvivesAnEvidenceWriteFailure(t *testing.T) {
	if err := RecordMemoryPressureEvidence(); err == nil {
		t.Skip("evidence recording succeeds in this process, so there is no failure to arrange")
	}

	probe := newPressureProbe(t, "pressure-evidence-failure")
	before := memoryPressureEventCount.Load()
	handleMemoryPressureWith(18<<20, 50<<20)

	if got := memoryPressureEventCount.Load() - before; got != 1 {
		t.Fatalf("event count rose by %d, want 1: a failed evidence write must not abort "+
			"pressure handling", got)
	}
	if probe.closed != 0 {
		t.Fatalf("a failed evidence write led to %d connection close(s)", probe.closed)
	}
}
