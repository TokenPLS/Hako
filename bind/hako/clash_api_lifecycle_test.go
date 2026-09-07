package hako

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

type lifecycleRoundTripper func(*http.Request) (*http.Response, error)

func (f lifecycleRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func lifecycleResponse(r *http.Request) *http.Response {
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("{}")), Request: r}
}

type lifecycleHandler struct {
	onConnected    func()
	onDisconnected func()
	onConnections  func()
	connected      atomic.Int32
	disconnected   atomic.Int32
}

func (h *lifecycleHandler) Connected() {
	h.connected.Add(1)
	if h.onConnected != nil {
		h.onConnected()
	}
}
func (h *lifecycleHandler) Disconnected(string) {
	h.disconnected.Add(1)
	if h.onDisconnected != nil {
		h.onDisconnected()
	}
}
func (*lifecycleHandler) WriteTraffic(string) {}
func (*lifecycleHandler) WriteMemory(string)  {}
func (*lifecycleHandler) WriteLogs(string)    {}
func (*lifecycleHandler) WriteMode(string)    {}
func (h *lifecycleHandler) WriteConnections(string) {
	if h.onConnections != nil {
		h.onConnections()
	}
}

func lifecycleWait[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("lifecycle barrier timed out")
	}
	var zero T
	return zero
}

func lifecycleClient(t *testing.T, h *lifecycleHandler, commands ...int32) *ClashAPIClient {
	t.Helper()
	o := &ClashAPIClientOptions{}
	for _, command := range commands {
		o.AddCommand(command)
	}
	c, err := NewClashAPIClientWithOptions("/unused-lifecycle-fixture", h, o)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestClashLifecycleCloseOwnsPendingConnect(t *testing.T) {
	h := &lifecycleHandler{}
	c := lifecycleClient(t, h)
	entered := make(chan *http.Request, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseDial := func() { releaseOnce.Do(func() { close(release) }) }
	// A transport that delays returning even after cancellation proves Close
	// owns the establishing worker, not just the cancellation signal.
	c.httpClient.Transport = lifecycleRoundTripper(func(r *http.Request) (*http.Response, error) {
		entered <- r
		<-release
		return lifecycleResponse(r), nil
	})
	connecting := make(chan error, 1)
	go func() { connecting <- c.Connect() }()
	request := lifecycleWait(t, entered)
	closing := make(chan struct{})
	go func() { c.Close(); close(closing) }()
	select {
	case <-closing:
		t.Error("Close returned before the pending Connect worker ended")
	case <-request.Context().Done():
		if request.Context().Err() != context.Canceled {
			t.Errorf("pending dial ended through timeout, not Close: %v", request.Context().Err())
		}
	case <-time.After(5 * time.Second):
		t.Error("Close did not cancel pending dial")
	}
	releaseDial()
	err := lifecycleWait(t, connecting)
	lifecycleWait(t, closing)
	// Clean up a late session on the unfixed source as well.
	c.Close()
	if err == nil {
		t.Error("canceled Connect reported success")
	}
	if got := h.connected.Load(); got != 0 {
		t.Errorf("late Connected callbacks = %d, want 0", got)
	}
}

func TestClashLifecycleCloseWaitsForConnectedCallback(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	h := &lifecycleHandler{onConnected: func() { close(entered); <-release }}
	c := lifecycleClient(t, h)
	c.httpClient.Transport = lifecycleRoundTripper(func(r *http.Request) (*http.Response, error) { return lifecycleResponse(r), nil })
	connecting := make(chan error, 1)
	go func() { connecting <- c.Connect() }()
	lifecycleWait(t, entered)
	c.mu.Lock()
	session := c.session
	c.mu.Unlock()
	closing := make(chan struct{})
	go func() { c.Close(); close(closing) }()
	lifecycleWait(t, session.ctx.Done())
	select {
	case <-closing:
		t.Error("Close returned while Connected callback was still running")
	default:
	}
	// The session must remain owned while its callback/worker is draining,
	// including for a concurrent second Close.
	c.mu.Lock()
	owned := c.session == session
	c.mu.Unlock()
	if !owned {
		t.Error("closing session was detached before its callback drained")
	}
	close(release)
	lifecycleWait(t, connecting)
	lifecycleWait(t, closing)
	if h.disconnected.Load() != 1 {
		t.Errorf("Disconnected = %d, want 1", h.disconnected.Load())
	}
	// An explicit later Connect must still be supported.
	h.onConnected = nil
	if err := c.Connect(); err != nil {
		t.Fatalf("reuse after Close: %v", err)
	}
	c.Close()
}

func lifecycleServer(t *testing.T, c *ClashAPIClient, handler http.HandlerFunc) {
	t.Helper()
	server := httptest.NewServer(handler)
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	}}
	c.httpClient = &http.Client{Transport: transport}
	t.Cleanup(func() { c.Close(); transport.CloseIdleConnections(); server.Close() })
}

func TestClashLifecycleCloseCancelsMemoryFallback(t *testing.T) {
	h := &lifecycleHandler{}
	c := lifecycleClient(t, h, CommandStatus)
	snapshot := make(chan *http.Request, 1)
	snapshotEnded := make(chan error, 1)
	lifecycleServer(t, c, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hako/v1/memory" {
			snapshot <- r
			<-r.Context().Done()
			return
		}
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		if r.URL.Path == "/memory" {
			_ = conn.Write(r.Context(), websocket.MessageText, []byte("{\"inuse\":42}"))
		}
		_, _, _ = conn.Read(r.Context())
	})
	transport := c.httpClient.Transport
	c.httpClient.Transport = lifecycleRoundTripper(func(r *http.Request) (*http.Response, error) {
		response, err := transport.RoundTrip(r)
		if r.URL.Path == "/hako/v1/memory" {
			snapshotEnded <- r.Context().Err()
		}
		return response, err
	})
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	lifecycleWait(t, snapshot)
	c.Close()
	if err := lifecycleWait(t, snapshotEnded); err != context.Canceled {
		t.Errorf("footprint request ended with %v, want session cancellation", err)
	}
}

func TestClashLifecycleCloseCancelsPartialStreams(t *testing.T) {
	h := &lifecycleHandler{}
	c := lifecycleClient(t, h, CommandLog, CommandMode)
	entered := make(chan *http.Request, 1)
	firstClosed := make(chan struct{}, 1)
	lifecycleServer(t, c, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hako/v1/mode" {
			entered <- r
			<-r.Context().Done()
			return
		}
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		_, _, _ = conn.Read(r.Context())
		firstClosed <- struct{}{}
	})
	connecting := make(chan error, 1)
	go func() { connecting <- c.Connect() }()
	lifecycleWait(t, entered)
	if err := c.SetOnlyStatisticsProxy(true); err == nil {
		t.Error("scope change while connecting must report unavailable")
	}
	if err := c.Connect(); err == nil {
		t.Error("concurrent Connect adopted a second attempt")
	}
	c.Close()
	if err := lifecycleWait(t, connecting); err == nil {
		t.Error("partial canceled Connect succeeded")
	}
	lifecycleWait(t, firstClosed)
	if h.connected.Load() != 0 {
		t.Error("partial attempt emitted Connected")
	}
}

func TestClashLifecycleCloseOwnsResubscribeDial(t *testing.T) {
	h := &lifecycleHandler{}
	c := lifecycleClient(t, h, CommandStatus)
	serverClosed := make(chan string, 4)
	lifecycleServer(t, c, func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		_, _, _ = conn.Read(r.Context())
		serverClosed <- r.URL.Path
	})
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	entered := make(chan *http.Request, 1)
	release := make(chan struct{})
	transport := c.httpClient.Transport
	c.httpClient.Transport = lifecycleRoundTripper(func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("only-proxy") == "true" {
			entered <- r
			<-release
			return nil, r.Context().Err()
		}
		return transport.RoundTrip(r)
	})
	resubscribe := make(chan error, 1)
	go func() { resubscribe <- c.SetOnlyStatisticsProxy(true) }()
	request := lifecycleWait(t, entered)
	closing := make(chan struct{})
	go func() { c.Close(); close(closing) }()
	lifecycleWait(t, request.Context().Done())
	if request.Context().Err() != context.Canceled {
		t.Errorf("scope dial canceled by %v, not Close", request.Context().Err())
	}
	c.mu.Lock()
	owned := c.session != nil
	c.mu.Unlock()
	if !owned {
		t.Error("Close detached session with pending re-subscribe")
	}
	close(release)
	if err := lifecycleWait(t, resubscribe); err == nil {
		t.Error("canceled scope change succeeded")
	}
	lifecycleWait(t, closing)
	if c.onlyStatisticsProxy.Load() {
		t.Error("failed scope change committed new scope")
	}
	for range 2 {
		lifecycleWait(t, serverClosed)
	}
}

func TestClashLifecycleConcurrentCloseDrainsWriteCallback(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	h := &lifecycleHandler{onConnections: func() { close(entered); <-release }}
	c := lifecycleClient(t, h, CommandConnections)
	lifecycleServer(t, c, func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		_ = conn.Write(r.Context(), websocket.MessageText, []byte("{}"))
		_, _, _ = conn.Read(r.Context())
	})
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	lifecycleWait(t, entered)
	c.mu.Lock()
	session := c.session
	c.mu.Unlock()
	completed := make(chan struct{}, 8)
	for range 8 {
		go func() { c.Close(); completed <- struct{}{} }()
	}
	lifecycleWait(t, session.ctx.Done())
	c.mu.Lock()
	owned := c.session == session
	c.mu.Unlock()
	if !owned {
		t.Error("write callback outlived session ownership")
	}
	early := 0
	select {
	case <-completed:
		early = 1
		t.Error("Close returned before the write callback drained")
	default:
	}
	close(release)
	for range 8 - early {
		lifecycleWait(t, completed)
	}
	if h.disconnected.Load() != 1 {
		t.Errorf("Disconnected count %d, want 1", h.disconnected.Load())
	}
}

func TestClashLifecycleCallbacksCanRequestAsyncClose(t *testing.T) {
	for _, event := range []string{"connected", "connections", "disconnected"} {
		t.Run(event, func(t *testing.T) {
			h := &lifecycleHandler{}
			c := lifecycleClient(t, h, CommandConnections)
			asyncClose := make(chan struct{})
			var once sync.Once
			closeFromOwner := func() { once.Do(func() { go func() { c.Close(); close(asyncClose) }() }) }
			switch event {
			case "connected":
				h.onConnected = closeFromOwner
			case "connections":
				h.onConnections = closeFromOwner
			case "disconnected":
				h.onDisconnected = closeFromOwner
			}
			lifecycleServer(t, c, func(w http.ResponseWriter, r *http.Request) {
				conn, err := websocket.Accept(w, r, nil)
				if err != nil {
					return
				}
				defer conn.CloseNow()
				_ = conn.Write(r.Context(), websocket.MessageText, []byte("{}"))
				_, _, _ = conn.Read(r.Context())
			})
			_ = c.Connect()
			if event == "disconnected" {
				c.Close()
			}
			lifecycleWait(t, asyncClose)
			c.Close()
		})
	}
}

func TestClashLifecycleConcurrentConnectCloseAndScope(t *testing.T) {
	h := &lifecycleHandler{}
	c := lifecycleClient(t, h, CommandStatus)
	lifecycleServer(t, c, func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		_, _, _ = conn.Read(r.Context())
	})
	for round := range 20 {
		var workers sync.WaitGroup
		workers.Add(4)
		go func() { defer workers.Done(); _ = c.Connect() }()
		go func() { defer workers.Done(); _ = c.Connect() }()
		go func() { defer workers.Done(); c.Close() }()
		go func() { defer workers.Done(); _ = c.SetOnlyStatisticsProxy(round%2 == 0) }()
		workers.Wait()
		c.Close()
		c.mu.Lock()
		idle := c.session == nil
		c.mu.Unlock()
		if !idle {
			t.Fatal("completed Close left an owned attempt")
		}
	}
	if err := c.Connect(); err != nil {
		t.Fatalf("reuse after concurrent operations: %v", err)
	}
	c.Close()
}

type lifecycleHeldCloseConn struct {
	net.Conn
	entered chan struct{}
	release <-chan struct{}
	once    sync.Once
}

func (c *lifecycleHeldCloseConn) Close() error {
	c.once.Do(func() { close(c.entered) })
	<-c.release
	return c.Conn.Close()
}

func TestClashLifecycleCloseWaitsForPartialSocketClose(t *testing.T) {
	h := &lifecycleHandler{}
	c := lifecycleClient(t, h, CommandLog, CommandMode)
	secondDial := make(chan struct{}, 1)
	lifecycleServer(t, c, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hako/v1/mode" {
			secondDial <- struct{}{}
			<-r.Context().Done()
			return
		}
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		_, _, _ = conn.Read(r.Context())
	})
	held := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseClose := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseClose()
	transport := c.httpClient.Transport.(*http.Transport)
	dial := transport.DialContext
	var dials atomic.Int32
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := dial(ctx, network, address)
		if err == nil && dials.Add(1) == 1 {
			return &lifecycleHeldCloseConn{Conn: conn, entered: held, release: release}, nil
		}
		return conn, err
	}
	connecting := make(chan error, 1)
	go func() { connecting <- c.Connect() }()
	lifecycleWait(t, secondDial)
	firstClose := make(chan struct{})
	go func() { c.Close(); close(firstClose) }()
	lifecycleWait(t, held)
	secondClose := make(chan struct{})
	go func() { c.Close(); close(secondClose) }()
	select {
	case <-secondClose:
		t.Error("second Close escaped while an adopted socket was still closing")
	case <-time.After(100 * time.Millisecond):
		// A controlled blocking Close, not a performance threshold: no close
		// operation can finish until the test releases its owned socket.
	}
	releaseClose()
	lifecycleWait(t, firstClose)
	lifecycleWait(t, secondClose)
	if err := lifecycleWait(t, connecting); err == nil {
		t.Error("partial canceled attempt succeeded")
	}
}
