package adapter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/TokenPLS/Hako/common/atomic"
	"github.com/TokenPLS/Hako/common/queue"
	"github.com/TokenPLS/Hako/common/utils"
	"github.com/TokenPLS/Hako/common/xsync"
	"github.com/TokenPLS/Hako/component/ca"
	C "github.com/TokenPLS/Hako/constant"
	"github.com/TokenPLS/Hako/log"

	"github.com/metacubex/http"
)

var UnifiedDelay = atomic.NewBool(false)

const (
	defaultHistoriesNum = 10
)

type internalProxyState struct {
	alive   atomic.Bool
	history *queue.Queue[C.DelayHistory]
}

type Proxy struct {
	C.ProxyAdapter
	alive   atomic.Bool
	history *queue.Queue[C.DelayHistory]
	extra   xsync.Map[string, *internalProxyState]
	// now is the clock URLTest measures with. An instance seam rather than a
	// package variable so a test can hand one proxy a frozen clock without
	// touching any other; production never sets it.
	now func() time.Time
}

// URLTestOutcome is what one URL test measured: the delay, whether the status
// satisfied the caller's expectation, and the status itself. C.Proxy.URLTest
// keeps upstream's shape (delay, error) -- a reply with an unexpected status is
// NOT an error there, because upstream records it only as "not alive for this
// URL" and marking the proxy dead everywhere for one URL's expectation was the
// global-death defect. The two callers in this tree that need to act on
// "answered, but not with the expected status" read it from here instead.
type URLTestOutcome struct {
	Delay      uint16
	Satisfied  bool
	HTTPStatus int
}

// URLTestOutcomeProvider is what *Proxy adds on top of C.Proxy. Callers
// type-assert and fall back to C.Proxy.URLTest when the assertion fails.
type URLTestOutcomeProvider interface {
	URLTestOutcome(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) (URLTestOutcome, error)
}

// Adapter implements C.Proxy
func (p *Proxy) Adapter() C.ProxyAdapter {
	return p.ProxyAdapter
}

// AliveForTestUrl implements C.Proxy
func (p *Proxy) AliveForTestUrl(url string) bool {
	if state, ok := p.extra.Load(url); ok {
		return state.alive.Load()
	}

	return p.alive.Load()
}

// DialContext implements C.ProxyAdapter
func (p *Proxy) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	conn, err := p.ProxyAdapter.DialContext(ctx, metadata)
	return conn, err
}

// ListenPacketContext implements C.ProxyAdapter
func (p *Proxy) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	pc, err := p.ProxyAdapter.ListenPacketContext(ctx, metadata)
	return pc, err
}

// DelayHistory implements C.Proxy
func (p *Proxy) DelayHistory() []C.DelayHistory {
	queueM := p.history.Copy()
	histories := []C.DelayHistory{}
	for _, item := range queueM {
		histories = append(histories, item)
	}
	return histories
}

// DelayHistoryForTestUrl implements C.Proxy
func (p *Proxy) DelayHistoryForTestUrl(url string) []C.DelayHistory {
	var queueM []C.DelayHistory

	if state, ok := p.extra.Load(url); ok {
		queueM = state.history.Copy()
	}
	histories := []C.DelayHistory{}
	for _, item := range queueM {
		histories = append(histories, item)
	}
	return histories
}

// ExtraDelayHistories return all delay histories for each test URL
// implements C.Proxy
func (p *Proxy) ExtraDelayHistories() map[string]C.ProxyState {
	histories := map[string]C.ProxyState{}

	p.extra.Range(func(k string, v *internalProxyState) bool {
		testUrl := k
		state := v

		queueM := state.history.Copy()
		var history []C.DelayHistory

		for _, item := range queueM {
			history = append(history, item)
		}

		histories[testUrl] = C.ProxyState{
			Alive:   state.alive.Load(),
			History: history,
		}
		return true
	})
	return histories
}

// LastDelayForTestUrl return last history record of the specified URL. if proxy is not alive, return the max value of uint16.
// implements C.Proxy
func (p *Proxy) LastDelayForTestUrl(url string) (delay uint16) {
	var maxDelay uint16 = 0xffff

	alive := false
	var history C.DelayHistory

	if state, ok := p.extra.Load(url); ok {
		alive = state.alive.Load()
		history = state.history.Last()
	}

	if !alive || history.Delay == 0 {
		return maxDelay
	}
	return history.Delay
}

// MarshalJSON implements C.ProxyAdapter
func (p *Proxy) MarshalJSON() ([]byte, error) {
	inner, err := p.ProxyAdapter.MarshalJSON()
	if err != nil {
		return inner, err
	}

	mapping := map[string]any{}
	_ = json.Unmarshal(inner, &mapping)
	mapping["history"] = p.DelayHistory()
	mapping["extra"] = p.ExtraDelayHistories()
	mapping["alive"] = p.alive.Load()
	mapping["name"] = p.Name()
	mapping["udp"] = p.SupportUDP()
	mapping["uot"] = p.SupportUOT()

	proxyInfo := p.ProxyInfo()
	mapping["xudp"] = proxyInfo.XUDP
	mapping["tfo"] = proxyInfo.TFO
	mapping["mptcp"] = proxyInfo.MPTCP
	mapping["smux"] = proxyInfo.SMUX
	mapping["interface"] = proxyInfo.Interface
	mapping["routing-mark"] = proxyInfo.RoutingMark
	mapping["provider-name"] = proxyInfo.ProviderName
	mapping["dialer-proxy"] = proxyInfo.DialerProxy

	return json.Marshal(mapping)
}

// URLTest get the delay for the specified URL
// implements C.Proxy
// URLTest implements C.Proxy: upstream's shape, upstream's semantics. The
// delay is the measurement; an unexpected status is not an error (see
// URLTestOutcome).
func (p *Proxy) URLTest(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) (t uint16, err error) {
	t, _, _, err = p.urlTest(ctx, url, expectedStatus)
	return t, err
}

// URLTestOutcome implements URLTestOutcomeProvider.
func (p *Proxy) URLTestOutcome(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) (URLTestOutcome, error) {
	t, satisfied, status, err := p.urlTest(ctx, url, expectedStatus)
	return URLTestOutcome{Delay: t, Satisfied: satisfied, HTTPStatus: status}, err
}

func (p *Proxy) clock() time.Time {
	if p.now != nil {
		return p.now()
	}
	return time.Now()
}

// urlTestAdmission, when set, runs before every URL test's dial. Hako's iOS
// Network Extension arms it with a memory pacing gate;
// nil — the default everywhere else — keeps urlTest exactly upstream. A
// non-nil error skips the test entirely: urlTest returns it before the
// history/alive bookkeeping registers, so a skipped probe leaves the node's
// last known state untouched (first v2 device round: 1077 probes rewritten
// into fake timeouts during storm windows).
var urlTestAdmission = atomic.NewTypedValue[func(ctx context.Context) error](nil)

// ErrURLTestDeferred is what an armed admission gate returns for a probe it
// chose to skip (background health checks under memory pressure). The probe
// records nothing; the next scheduled check retries.
var ErrURLTestDeferred = errors.New("url test deferred: memory admission")

// SetURLTestAdmission installs f on the URL-test choke point shared by API
// probes, group tests and provider health checks. Pass nil to disarm.
func SetURLTestAdmission(f func(ctx context.Context) error) {
	urlTestAdmission.Store(f)
}

// backgroundProbeKey marks a context whose URL tests are background work
// (scheduled health checks), free to be skipped under memory pressure.
type backgroundProbeKey struct{}

// WithBackgroundProbe marks ctx's URL tests as background work.
func WithBackgroundProbe(ctx context.Context) context.Context {
	return context.WithValue(ctx, backgroundProbeKey{}, true)
}

// IsBackgroundProbe reports whether ctx carries the background mark.
func IsBackgroundProbe(ctx context.Context) bool {
	v, _ := ctx.Value(backgroundProbeKey{}).(bool)
	return v
}

func (p *Proxy) urlTest(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) (t uint16, satisfied bool, status int, err error) {
	// The admission gate runs before the deferred bookkeeping registers: a
	// probe the gate defers returns here with the node's history and alive
	// state untouched.
	if admit := urlTestAdmission.Load(); admit != nil {
		if admitErr := admit(ctx); admitErr != nil {
			return 0, false, 0, admitErr
		}
	}
	defer func() {
		alive := err == nil
		record := C.DelayHistory{Time: time.Now()}
		if alive {
			record.Delay = t
		}

		p.alive.Store(alive)
		p.history.Put(record)
		if p.history.Len() > defaultHistoriesNum {
			p.history.Pop()
		}

		state, _ := p.extra.LoadOrStoreFn(url, func() *internalProxyState {
			return &internalProxyState{
				history: queue.New[C.DelayHistory](defaultHistoriesNum),
				alive:   atomic.NewBool(true),
			}
		})

		if !satisfied {
			record.Delay = 0
			alive = false
		}

		state.alive.Store(alive)
		state.history.Put(record)
		if state.history.Len() > defaultHistoriesNum {
			state.history.Pop()
		}

	}()

	unifiedDelay := UnifiedDelay.Load()

	addr, err := urlToMetadata(url)
	if err != nil {
		return
	}

	start := p.clock()
	instance, err := p.DialContext(ctx, &addr)
	if err != nil {
		return
	}
	defer func() {
		_ = instance.Close()
	}()

	req, err := http.NewRequest(http.MethodHead, url, nil)
	if err != nil {
		return
	}
	req = req.WithContext(ctx)

	tlsConfig, err := ca.GetTLSConfig(ca.Option{})
	if err != nil {
		return
	}

	transport := &http.Transport{
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return instance, nil
		},
		// from http.DefaultTransport
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       tlsConfig,
	}

	client := http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	defer client.CloseIdleConnections()

	resp, err := client.Do(req)

	if err != nil {
		// net/http hands back a *url.Error carrying the whole URL, and this
		// error is serialised to the API and into the log -- so a health-check
		// URL whose PATH is the account (`https://host/<token>`) would arrive
		// there intact. Name the target by address and keep the cause.
		err = fmt.Errorf("%s: %w", url, err)
		return
	}

	_ = resp.Body.Close()

	if unifiedDelay {
		second := p.clock()
		var ignoredErr error
		var secondResp *http.Response
		secondResp, ignoredErr = client.Do(req)
		if ignoredErr == nil {
			resp = secondResp
			_ = resp.Body.Close()
			start = second
		} else {
			if strings.HasPrefix(url, "http://") {
				// The URL is the user's, and the error net/http hands back is a
				// *url.Error that prints the whole of it again: name the target
				// by address and take the URL out of the cause.
				log.Errorln("%s failed to get the second response from %s: %v", p.Name(), url, ignoredErr)
				log.Warnln("It is recommended to use HTTPS for provider.health-check.url and group.url to ensure better reliability. Due to some proxy providers hijacking test addresses and not being compatible with repeated HEAD requests, using HTTP may result in failed tests.")
			}
		}
	}

	satisfied = resp != nil && (expectedStatus == nil || expectedStatus.Check(uint16(resp.StatusCode)))
	if resp != nil {
		status = resp.StatusCode
	}
	t = uint16(p.clock().Sub(start) / time.Millisecond)
	// A local or edge target can answer in under a millisecond, and
	// hub/route/proxies.go reads a zero delay as the failure sentinel
	// (`err != nil || delay == 0`), so upstream's truncation turned a real
	// fast answer into a failed test. Report the minimum representable delay
	// for a measurement that did happen. This repairs that upstream reading;
	// it is not in service of bind/hako's -1, which is produced from the
	// error, never from zero.
	if t == 0 {
		t = 1
	}
	return
}

func NewProxy(adapter C.ProxyAdapter) *Proxy {
	return &Proxy{
		ProxyAdapter: adapter,
		history:      queue.New[C.DelayHistory](defaultHistoriesNum),
		alive:        atomic.NewBool(true),
	}
}

func urlToMetadata(rawURL string) (addr C.Metadata, err error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return
	}

	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		default:
			err = fmt.Errorf("%s scheme not Support", rawURL)
			return
		}
	}

	err = addr.SetRemoteAddress(net.JoinHostPort(u.Hostname(), port))
	return
}
