package adapter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/adapter/outbound"
	"github.com/TokenPLS/Hako/common/utils"
)

func statusRanges(t *testing.T, spec string) utils.IntRanges[uint16] {
	t.Helper()
	ranges, err := utils.NewUnsignedRanges[uint16](spec)
	if err != nil {
		t.Fatal(err)
	}
	return ranges
}

// An answer outside the expected range is not an error and does not mark the
// proxy dead everywhere: upstream records it as "not alive for this URL" and
// nothing more, and the fork's earlier error here turned one URL's
// expectation into a global death. The caller that needs to know reads the
// outcome.
func TestAnUnexpectedStatusIsAnOutcomeNotAnError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	proxy := NewProxy(outbound.NewDirect())
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	outcome, err := proxy.URLTestOutcome(ctx, server.URL, statusRanges(t, "200-299"))
	if err != nil {
		t.Fatalf("an unexpected status must not be an error: %v", err)
	}
	if outcome.Satisfied || outcome.HTTPStatus != http.StatusServiceUnavailable || outcome.Delay == 0 {
		t.Fatalf("outcome = %+v, want unsatisfied 503 with a measured delay", outcome)
	}
	if !proxy.alive.Load() {
		t.Fatal("one URL's expectation marked the proxy dead for every URL")
	}
	if proxy.AliveForTestUrl(server.URL) {
		t.Fatal("the per-URL state must record the unexpected status as not alive")
	}
	// C.Proxy's URLTest keeps upstream's shape on the same measurement.
	delay, err := proxy.URLTest(ctx, server.URL, statusRanges(t, "200-299"))
	if err != nil || delay == 0 {
		t.Fatalf("URLTest = (%d, %v), want a delay and no error", delay, err)
	}
}

// A sub-millisecond answer is reported as 1, never as the zero that
// hub/route/proxies.go reads as failure. Driven by a frozen clock, not by
// hoping the loopback round trip stays under a millisecond.
func TestASubMillisecondAnswerIsNeverReportedAsZero(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	proxy := NewProxy(outbound.NewDirect())
	frozen := time.Unix(1_700_000_000, 0)
	proxy.now = func() time.Time { return frozen }
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	outcome, err := proxy.URLTestOutcome(ctx, server.URL, statusRanges(t, "200-299"))
	if err != nil {
		t.Fatalf("URLTestOutcome: %v", err)
	}
	if outcome.Delay != 1 || !outcome.Satisfied {
		t.Fatalf("outcome = %+v, want delay 1 and satisfied", outcome)
	}
}

// A transport failure is still an error, with its cause.
func TestATransportFailureIsStillAnError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	target := server.URL
	server.Close()

	proxy := NewProxy(outbound.NewDirect())
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	outcome, err := proxy.URLTestOutcome(ctx, target, statusRanges(t, "200-299"))
	if err == nil {
		t.Fatalf("a closed target must fail, got %+v", outcome)
	}
	if outcome.Satisfied || outcome.Delay != 0 {
		t.Fatalf("a failed test must not claim a delay or satisfaction: %+v", outcome)
	}
}
