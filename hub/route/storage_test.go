package route

import (
	"testing"

	"github.com/metacubex/chi"
	"github.com/metacubex/http"
)

// Embed mode does not narrow this router, and that is a decision rather than an oversight.
// The gate that used to be here rested on "embedded apps own persistence outside the native
// API" -- a design preference wearing the clothes of a constraint -- and on a two-process
// bbolt worry that was checked and does not hold: nothing in the containing app opens
// cache.db. Against this repository's own test for an invented constraint (stricter than
// upstream AND required by the platform), it was neither, so it went. storage.go carries the
// full reasoning.
//
// This test asserted the removed gate and stayed red on main from then until 2026-08-11,
// because the workflow that runs the root module's tests triggers on Alpha and tags, never on
// main. It is kept, pointed the other way, so the decision has something holding it down.
func TestEmbeddedStorageRouterKeepsEveryVerb(t *testing.T) {
	previous := embedMode
	SetEmbedMode(true)
	t.Cleanup(func() { SetEmbedMode(previous) })
	routes := storageRouter().(chi.Routes)
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		if !routes.Match(chi.NewRouteContext(), method, "/key") {
			t.Fatalf("embedded storage router lost %s; upstream serves all three and nothing "+
				"platform-specific argues against it here", method)
		}
	}
}

func TestStandaloneStorageRouterKeepsMutations(t *testing.T) {
	previous := embedMode
	SetEmbedMode(false)
	t.Cleanup(func() { SetEmbedMode(previous) })
	routes := storageRouter().(chi.Routes)
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		if !routes.Match(chi.NewRouteContext(), method, "/key") {
			t.Fatalf("standalone storage router lost %s", method)
		}
	}
}
