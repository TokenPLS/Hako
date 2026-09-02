package hako

import (
	"strings"
	"testing"

	"github.com/TokenPLS/Hako/component/profile"
	"github.com/TokenPLS/Hako/component/profile/cachefile"
)

// A user switched nodes in a dashboard and the app's home screen kept naming the old one. Same
// shape as mode and allow-lan: the app holds "which node is selected" as its own state, and
// PUT /proxies/{name} gave that state a second writer it cannot see.
//
// The seam is cachefile.SetSelected, which both writers reach immediately after SelectAble.Set
// -- hub/route/proxies.go:98 for the dashboard, bind/hako/control.go:35 for the app.
//
// It fires before that function's persistence checks, and this test is the reason: those checks
// return early when store-selected is off, so an observer installed after them would go silent
// under a setting that has nothing to do with what is selected. That is an instrument that stops
// reporting under a condition nobody would think to check, which this batch has now met in four
// different disguises.
func TestSelectionChangesReachTheStreamEvenWithStoreSelectedOff(t *testing.T) {
	fired := make(chan string, 4)
	cachefile.SetSelectedObserver(func(group, selected string) { fired <- group + "=" + selected })
	t.Cleanup(func() { cachefile.SetSelectedObserver(nil) })

	// The condition has to be MADE true, not assumed. The first version of this test asserted
	// "no Setup, so both early returns apply" and was wrong on both counts -- measured,
	// StoreSelected defaults to true and Cache() hands back a database. So the mutation that
	// moves the observer below those returns passed, and the comment claiming this test protects
	// that position was the only thing wrong with the test.
	previous := profile.StoreSelected.Load()
	profile.StoreSelected.Store(false)
	t.Cleanup(func() { profile.StoreSelected.Store(previous) })

	cachefile.Cache().SetSelected("GLOBAL", "singapore")

	select {
	case got := <-fired:
		if got != "GLOBAL=singapore" {
			t.Fatalf("observer saw %q", got)
		}
	default:
		t.Fatal("a selection change did not reach the observer; with store-selected off the seam " +
			"would be silent exactly when nothing is written down to fall back on")
	}
}

// The payload carries manual groups only, and the omission is deliberate rather than an
// oversight: an automatic group's current node is computed when something asks, so there is no
// moment at which it changes and nothing to push.
func TestSelectionSnapshotDocumentsWhatItCannotCover(t *testing.T) {
	switches := currentRuntimeSwitches()
	if switches.Selected == nil {
		t.Fatal("Selected must be an empty map rather than nil: a consumer cannot tell a null " +
			"it did not expect from a core that has nothing selected")
	}
	// The field's own documentation is the contract here, so it has to say what it excludes.
	source := packageSourceFiles(t)["mode_stream_route.go"]
	for _, required := range []string{"Manual only", "Fallback.Now()"} {
		if !strings.Contains(source, required) {
			t.Errorf("the Selected field no longer documents %q; the exclusion is the part a "+
				"consumer would otherwise discover from a stale screen", required)
		}
	}
}
