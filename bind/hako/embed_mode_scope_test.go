package hako

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// embedMode removes routes from the controller this binding serves, and the removals were
// written as three `if !embedMode` blocks whose comments give one reason each. The reasons are
// not interchangeable, and at least one block covered a route its reason does not describe:
//
//	configs.go:28   PUT /configs        bypasses the immutable revision pipeline   -- holds
//	                POST /configs/geo   downloads inside the extension             -- holds
//	                PATCH /configs      neither                                    -- did not hold
//
// A dashboard switching between rule/global/direct sends PATCH /configs, so the most ordinary
// action a Clash panel has was answered 405 by a condition written about two other routes. The
// consuming lane found it when a user tried to switch modes on a device.
//
// The shape is the night's most productive one: ONE CONDITION COVERING SEVERAL THINGS WITH
// DIFFERENT REASONS. It is the same as disposition=apple buying exemption from two gates at
// once, and the same as one family note describing tun.mtu and tun.stack in a single sentence.
//
// So this test enumerates the surface rather than trusting the blocks: every route that stays
// closed is listed with the reason it stays closed, and every route that is open is listed too.
// Adding a route to either list is then a deliberate act.
func TestEmbedModeClosesOnlyWhatItsReasonsCover(t *testing.T) {
	port := freeLoopbackPort(t)
	addr := "127.0.0.1:" + port
	path := shortClashSocketPath(t)
	cfg := controllerConfig(t, addr)

	if err := startControlPlane(cfg, path); err != nil {
		t.Fatalf("startControlPlane: %v", err)
	}
	t.Cleanup(func() { stopClashAPI(path) })

	client := &http.Client{Timeout: 3 * time.Second}
	call := func(method, route string) int {
		t.Helper()
		request, err := http.NewRequest(method, "http://"+addr+route, strings.NewReader("{}"))
		if err != nil {
			t.Fatalf("build %s %s: %v", method, route, err)
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := client.Do(request)
		if err != nil {
			t.Fatalf("%s %s: %v", method, route, err)
		}
		defer response.Body.Close()
		return response.StatusCode
	}

	// Positive control first: if the controller is not actually serving, every route below
	// would "fail closed" and this test would pass by measuring nothing.
	if status := call(http.MethodGet, "/configs"); status != http.StatusOK {
		t.Fatalf("GET /configs = %d; the controller is not serving, so nothing below is measured", status)
	}

	closed := map[string]string{
		"PUT /configs":      "replaces the running configuration, bypassing the immutable revision pipeline",
		"POST /configs/geo": "downloads geo data inside the extension",
		"POST /upgrade":     "replaces the binary, which Apple code signing forbids",
		"POST /upgrade/geo": "downloads and unpacks 17 MB of GeoIP inside an extension measured dying at 49.5 MiB",
		"POST /restart":     "re-executes os.Executable(), which inside an app extension is the host process",
	}
	for route, reason := range closed {
		method, target, _ := strings.Cut(route, " ")
		status := call(method, target)
		if status != http.StatusNotFound && status != http.StatusMethodNotAllowed {
			t.Errorf("%s is answered %d but is supposed to stay closed: %s", route, status, reason)
		}
	}

	// Open, and each for a reason of its own rather than by omission.
	open := map[string]string{
		"PATCH /configs":       "runtime switches -- mode, sniffing, log level. Writes no file and downloads nothing",
		"PATCH /rules/disable": "flips SetDisabled in memory on already-parsed rules; the configuration on disk is untouched",
		"PUT /storage/hako":    "the dashboard's own scratch key-value store; nothing in the containing app opens cache.db, so there is no second writer to protect it from",
	}
	for route, reason := range open {
		method, target, _ := strings.Cut(route, " ")
		status := call(method, target)
		// 404/405 is the only thing that means "not routed". An open route is free to fail on
		// its own terms -- /upgrade/ui really does try to download and will report 500 without a
		// dashboard to fetch -- and treating that as closed would make this test enforce success
		// rather than reachability.
		if status == http.StatusNotFound || status == http.StatusMethodNotAllowed {
			t.Errorf("%s is answered %d but nothing justifies closing it: %s", route, status, reason)
		}
	}

	// Routes whose handler has a real side effect are proved routed WITHOUT being invoked: a
	// method the path does not accept answers 405 when the path exists and 404 when it does not.
	// POST /upgrade/ui really downloads a dashboard, so calling it here made the suite reach the
	// network and time out -- a test that goes online to prove a route is registered is a test
	// that fails for reasons having nothing to do with the code.
	routedButNotInvoked := map[string]string{
		"GET /upgrade/ui": "the same u.downloadUI() the start path already calls unprompted via " +
			"AutoDownloadUI, only on demand instead of during startup",
	}
	for route, reason := range routedButNotInvoked {
		method, target, _ := strings.Cut(route, " ")
		if status := call(method, target); status != http.StatusMethodNotAllowed {
			t.Errorf("%s answered %d; 405 means the path is registered and 404 means it is not, "+
				"and this one has to be registered: %s", route, status, reason)
		}
	}
}
