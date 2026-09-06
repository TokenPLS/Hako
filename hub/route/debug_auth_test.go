package route

import (
	"testing"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
)

// /debug mounts pprof and PUT /debug/gc. Upstream mounts it beside the
// authenticated group rather than inside it, so a configured secret protected
// every route except this one. On a desktop that is a debug switch nobody
// reaches from outside; in this fork the switch is wired to the configuration
// itself -- the RESTful controller turns it on whenever log-level is debug
// (bind/hako/external_controller.go) -- and the controller's listen address is
// configuration too. A subscription that writes `log-level: debug` plus
// `external-controller: 0.0.0.0:9090` therefore publishes a heap profiler to
// the local network: pprof output carries proxy server addresses, subscription
// URLs and whatever credential material is resident.
//
// Threat model: the subscription author sets it up, anyone on the same network
// collects.

func debugRequest(t *testing.T, handler http.Handler, method, path, secret string) int {
	t.Helper()
	request := httptest.NewRequest(method, path, nil)
	if secret != "" {
		request.Header.Set("Authorization", "Bearer "+secret)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder.Code
}

func TestDebugRoutesRequireTheSecret(t *testing.T) {
	handler := router(true, "s3cr3t", "", Cors{})

	if code := debugRequest(t, handler, http.MethodGet, "/debug/pprof/", ""); code != http.StatusUnauthorized {
		t.Fatalf("GET /debug/pprof/ without the secret returned %d, want 401: a heap profile carries proxy addresses and credential material", code)
	}
	if code := debugRequest(t, handler, http.MethodPut, "/debug/gc", ""); code != http.StatusUnauthorized {
		t.Fatalf("PUT /debug/gc without the secret returned %d, want 401", code)
	}
	// With the secret it still works -- this is a debugging surface, not a
	// removed one.
	if code := debugRequest(t, handler, http.MethodPut, "/debug/gc", "s3cr3t"); code == http.StatusUnauthorized {
		t.Fatal("PUT /debug/gc with the correct secret was rejected; the surface must stay usable")
	}
}

// With no secret configured nothing on this controller is authenticated, which
// is upstream's own default and the reader's choice. The debug surface must
// still behave exactly as the rest of the API does in that mode -- no more
// exposed, no less.
func TestDebugRoutesFollowTheControllerWhenNoSecretIsSet(t *testing.T) {
	handler := router(true, "", "", Cors{})
	if code := debugRequest(t, handler, http.MethodPut, "/debug/gc", ""); code == http.StatusUnauthorized {
		t.Fatal("an unauthenticated controller must not demand a secret for /debug")
	}
}

func TestDebugRoutesAreAbsentWhenDebugIsOff(t *testing.T) {
	handler := router(false, "s3cr3t", "", Cors{})
	if code := debugRequest(t, handler, http.MethodPut, "/debug/gc", "s3cr3t"); code != http.StatusNotFound {
		t.Fatalf("PUT /debug/gc with debug off returned %d, want 404", code)
	}
}
