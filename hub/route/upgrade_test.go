package route

import (
	"testing"

	"github.com/metacubex/chi"
	"github.com/metacubex/http"
)

// Embed mode closes exactly one of these three, and each answer has its own reason -- which is
// why they are asserted separately rather than as a block.
//
// POST /          stays closed: it replaces the running binary, and code signing forbids that
//                 on Apple. A platform fact, so the gate is legitimate.
// POST /ui        stays open: the core already calls AutoDownloadUI on the start path,
//                 synchronously, measured adding six seconds to a first connection. Refusing
//                 the route asked for nothing this core was not doing unprompted on a worse
//                 schedule -- it refused the safer half.
// POST /geo       is gated on its own measurement, not on embed mode: 17 MB fetched and
//                 unpacked does not fit an iOS packet tunnel measured dying at 49.5 MiB, while
//                 a macOS app extension has no such ceiling.
//
// This test asserted all three closed and stayed red on main from the day upgrade.go changed
// until 2026-08-11, because the workflow that runs the root module's tests triggers on Alpha
// and tags, never on main.
func TestEmbeddedUpgradeRouterClosesOnlyTheBinaryReplacement(t *testing.T) {
	previous := embedMode
	SetEmbedMode(true)
	t.Cleanup(func() { SetEmbedMode(previous) })

	routes, ok := upgradeRouter().(chi.Routes)
	if !ok {
		t.Fatal("upgrade router does not expose route metadata")
	}
	if routes.Match(chi.NewRouteContext(), http.MethodPost, "/") {
		t.Fatal("embedded upgrade router exposes POST /; code signing forbids replacing the " +
			"binary on Apple, so this one is a platform fact and must stay closed")
	}
	if !routes.Match(chi.NewRouteContext(), http.MethodPost, "/ui") {
		t.Fatal("embedded upgrade router lost POST /ui; the core downloads the dashboard " +
			"unprompted on the start path, so refusing the route only removes the safer half")
	}
	if routes.Match(chi.NewRouteContext(), http.MethodPost, "/geo") != geoUpdaterAllowed {
		t.Fatalf("POST /geo presence must follow geoUpdaterAllowed (%v), not embed mode",
			geoUpdaterAllowed)
	}
}

func TestStandaloneUpgradeRouterKeepsUpstreamRoutes(t *testing.T) {
	previous := embedMode
	SetEmbedMode(false)
	t.Cleanup(func() { SetEmbedMode(previous) })

	routes := upgradeRouter().(chi.Routes)
	for _, path := range []string{"/", "/geo", "/ui"} {
		if !routes.Match(chi.NewRouteContext(), http.MethodPost, path) {
			t.Fatalf("standalone upgrade router lost POST %s", path)
		}
	}
}
