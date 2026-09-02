package hako

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TokenPLS/Hako/adapter"
	"github.com/TokenPLS/Hako/adapter/outbound"
	"github.com/TokenPLS/Hako/common/utils"
	C "github.com/TokenPLS/Hako/constant"
	P "github.com/TokenPLS/Hako/constant/provider"
	"github.com/TokenPLS/Hako/tunnel"
)

// The gomobile entry point folds failure into -1. An answer outside 200-299
// is a failure for it -- that is the app's expectation, stated here now that
// the kernel no longer turns it into an error -- and a 2xx answer is its
// delay.
func TestURLTestEntryPointReadsTheOutcome(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer bad.Close()
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer good.Close()

	proxy := adapter.NewProxy(outbound.NewDirect())
	if got := urlTestDelay(proxy, bad.URL); got != -1 {
		t.Fatalf("a 403 answer must be -1, got %d", got)
	}
	if got := urlTestDelay(proxy, good.URL); got <= 0 {
		t.Fatalf("a 204 answer must be a positive delay, got %d", got)
	}
}

// A stub provider: the entry point only ever asks it for its name and its
// members, so the rest of the interface is here to satisfy the compiler and
// nothing else calls it.
type stubProxyProvider struct {
	name    string
	proxies []C.Proxy
}

func (p *stubProxyProvider) Name() string               { return p.name }
func (p *stubProxyProvider) VehicleType() P.VehicleType { return P.File }
func (p *stubProxyProvider) Type() P.ProviderType       { return P.Proxy }
func (p *stubProxyProvider) Initial() error             { return nil }
func (p *stubProxyProvider) Update() error              { return nil }
func (p *stubProxyProvider) Proxies() []C.Proxy         { return p.proxies }
func (p *stubProxyProvider) Count() int                 { return len(p.proxies) }
func (p *stubProxyProvider) Touch()                     {}
func (p *stubProxyProvider) HealthCheck()               {}
func (p *stubProxyProvider) Version() uint32            { return 1 }
func (p *stubProxyProvider) RegisterHealthCheckTask(string, utils.IntRanges[uint16], string, uint) {
}
func (p *stubProxyProvider) HealthCheckURL() string { return "" }

// A node that only exists inside a proxy provider can still be tested.
//
// `config.go:962` builds the global proxy table from the `proxies:` section
// plus the groups; a provider's members go to `providersMap` (:996) and never
// enter it. So the entry point's `tunnel.Proxies()[name]` misses every node a
// subscription brought -- which is most people's nodes -- and answered -1 for
// all of them. The HTTP control plane learned this already and falls back to
// the provider's health-check route; the television cannot use that plane
// so the fallback belongs here too.
func TestURLTestFindsANodeThatOnlyAProviderHas(t *testing.T) {
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer good.Close()

	member := adapter.NewProxy(outbound.NewDirect())
	restore := swapTunnelProxies(
		map[string]C.Proxy{},
		map[string]P.ProxyProvider{
			"subscription": &stubProxyProvider{name: "subscription", proxies: []C.Proxy{member}},
		},
	)
	defer restore()

	if got := URLTest(member.Name(), good.URL); got <= 0 {
		t.Fatalf("a provider's own node must be testable, got %d", got)
	}
	if got := URLTest("nobody", good.URL); got != -1 {
		t.Fatalf("a name nothing has is still -1, got %d", got)
	}
}

// The same name under two providers is a conflict, not a coin toss.
//
// The HTTP client paid for this lesson first: measuring an arbitrary one of
// them reports a latency for a node the reader did not mean, and there is no
// way for them to tell which. Refuse instead.
func TestURLTestRefusesANameTwoProvidersBothClaim(t *testing.T) {
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer good.Close()

	shared := adapter.NewProxy(outbound.NewDirect())
	restore := swapTunnelProxies(
		map[string]C.Proxy{},
		map[string]P.ProxyProvider{
			"first":  &stubProxyProvider{name: "first", proxies: []C.Proxy{shared}},
			"second": &stubProxyProvider{name: "second", proxies: []C.Proxy{shared}},
		},
	)
	defer restore()

	if got := URLTest(shared.Name(), good.URL); got != -1 {
		t.Fatalf("an ambiguous name must not be guessed at, got %d", got)
	}
}

// The global table still wins: a name in both places is the one the reader
// wrote in `proxies:`, which is what every other surface resolves it to.
func TestURLTestPrefersTheGlobalTableOverAProvider(t *testing.T) {
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer good.Close()

	direct := adapter.NewProxy(outbound.NewDirect())
	// Same name, two different proxies: the provider's copy rejects, so a
	// positive delay can only come from the global table's entry. With the
	// same object in both places this test passed either way -- it did, until
	// a poison run showed it could not tell the two orders apart.
	shadow := adapter.NewProxy(outbound.NewRejectWithOption(
		outbound.RejectOption{Name: direct.Name()},
	))
	restore := swapTunnelProxies(
		map[string]C.Proxy{direct.Name(): direct},
		map[string]P.ProxyProvider{
			"subscription": &stubProxyProvider{name: "subscription", proxies: []C.Proxy{shadow}},
		},
	)
	defer restore()

	if got := URLTest(direct.Name(), good.URL); got <= 0 {
		t.Fatalf("the global table's entry must answer, got %d", got)
	}
}

func swapTunnelProxies(
	proxies map[string]C.Proxy,
	providers map[string]P.ProxyProvider,
) func() {
	previousProxies := tunnel.Proxies()
	previousProviders := tunnel.Providers()
	tunnel.UpdateProxies(proxies, providers)
	return func() { tunnel.UpdateProxies(previousProxies, previousProviders) }
}
