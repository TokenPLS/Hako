package route

import (
	"context"
	"encoding/json"
	stdhttp "net/http"
	stdtest "net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/TokenPLS/Hako/adapter"
	"github.com/TokenPLS/Hako/adapter/outbound"
)

// The target is a stdlib test server; the route is exercised through the
// forked http the router is built on.
func delayRequest(t *testing.T, target, expected string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/proxies/x/delay?timeout=2000&url="+target+"&expected="+expected, nil)
	req = req.WithContext(context.WithValue(req.Context(), CtxKeyProxy, adapter.NewProxy(outbound.NewDirect())))
	rec := httptest.NewRecorder()
	getProxyDelay(rec, req)
	return rec
}

// `expected` is still the request's (nil when absent) and an answer outside it
// is still a 503 that says what the status was -- read from the outcome now,
// so the proxy is not marked dead for every URL over one URL's expectation.
func TestDelayRouteReportsAnUnexpectedStatusWithoutAnError(t *testing.T) {
	server := stdtest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, _ *stdhttp.Request) {
		w.WriteHeader(stdhttp.StatusServiceUnavailable)
	}))
	defer server.Close()

	rec := delayRequest(t, server.URL, "200-299")
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "unexpected HTTP status 503") {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
}

func TestDelayRouteReportsASatisfiedAnswer(t *testing.T) {
	server := stdtest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, _ *stdhttp.Request) {
		w.WriteHeader(stdhttp.StatusNoContent)
	}))
	defer server.Close()

	rec := delayRequest(t, server.URL, "200-299")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "delay") {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	// Without `expected`, any answer satisfies: upstream's contract.
	rec = delayRequest(t, server.URL, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("without expected: status %d body %s", rec.Code, rec.Body.String())
	}
}

// A caller that hangs up must take its probe with it. The App abandons a dead
// node's delay request after its own patience runs out; the probe used to be
// built on context.Background() and kept dialing, handshaking and waiting for
// the full `timeout` parameter on its own -- one orphaned goroutine with a
// socket per abandoned probe, a whole sweep of them alive at once (measured on
// device at ~68KB each, and the difference between a 42 MiB resident sweep and
// a jetsam kill). The sibling group-delay handler derives from r.Context()
// upstream already; this pins the proxy-delay handler to the same shape.
func TestDelayRouteFollowsTheCallersCancellation(t *testing.T) {
	release := make(chan struct{})
	server := stdtest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, _ *stdhttp.Request) {
		<-release // a dead node: connects, then nothing, for longer than any caller waits
	}))
	// LIFO: release the stalled handlers BEFORE Close waits on them.
	defer server.Close()
	defer close(release)

	reqCtx, hangUp := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/proxies/x/delay?timeout=8000&url="+server.URL, nil)
	req = req.WithContext(context.WithValue(reqCtx, CtxKeyProxy, adapter.NewProxy(outbound.NewDirect())))
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	start := time.Now()
	go func() {
		defer close(done)
		getProxyDelay(rec, req)
	}()
	time.Sleep(100 * time.Millisecond)
	hangUp()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the caller hung up and the probe kept running toward its own 8s timeout; " +
			"that orphan is the sweep-time residency the device evidence priced at ~68KB each")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("handler returned only after %v; cancellation did not propagate", elapsed)
	}
}

// The client reads the failure from fields, not from the sentence. Before this
// the whole answer to "why did this node fail" was `{"message": "<English>"}`,
// and the client matched a dozen substrings against it -- so a
// reworded error moved the category with nothing going red, and every
// the reason was a socket bound to a physical interface.
func TestDelayRouteAnswersWithAClassifiedFailure(t *testing.T) {
	// A target nothing is listening on: the dial fails with a typed error.
	rec := delayRequest(t, "http://127.0.0.1:1/", "200-299")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Deferred bool `json:"deferred"`
		Failure  *struct {
			Kind    string `json:"kind"`
			Errno   string `json:"errno"`
			Message string `json:"message"`
		} `json:"failure"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not json: %v\n%s", err, rec.Body.String())
	}
	if body.Failure == nil {
		t.Fatalf("no classified failure in the answer: %s", rec.Body.String())
	}
	if body.Failure.Kind == "" || body.Failure.Kind == "unknown" {
		t.Errorf("kind = %q -- a refused dial has a type to read", body.Failure.Kind)
	}
	// the sentence travels beside the classification, never instead.
	if body.Failure.Message == "" {
		t.Error("the verbatim sentence was dropped")
	}
	// upstream's `message` stays where every existing reader looks for it.
	if body.Message == "" {
		t.Error("upstream's message field was dropped -- existing readers break")
	}
}

// An unexpected status is an outcome, not an error, so it classifies
// from the outcome and still carries the status it saw.
func TestDelayRouteClassifiesAnUnexpectedStatus(t *testing.T) {
	server := stdtest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, _ *stdhttp.Request) {
		w.WriteHeader(stdhttp.StatusForbidden)
	}))
	defer server.Close()

	rec := delayRequest(t, server.URL, "200-299")
	var body struct {
		HTTPStatus int `json:"httpStatus"`
		Failure    *struct {
			Kind string `json:"kind"`
		} `json:"failure"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not json: %v\n%s", err, rec.Body.String())
	}
	if body.Failure == nil || body.Failure.Kind != "status" {
		t.Fatalf("kind = %+v, want status\n%s", body.Failure, rec.Body.String())
	}
	if body.HTTPStatus != 403 {
		t.Errorf("httpStatus = %d, want 403", body.HTTPStatus)
	}
}
