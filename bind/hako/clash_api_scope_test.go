package hako

import (
	"context"

	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// fakeClashAPI is a Clash API stand-in on a Unix socket: it accepts the stream
// paths the client dials and publishes a frame on each one at a steady tick.
//
// The real core answers all four paths and answers them correctly, which is
// what TestClashAPIClientStreamsAndREST is for. What it cannot do is refuse one
// dial on demand, and "a failed re-subscribe leaves the previous stream
// working" is exactly the promise that only shows up when a dial fails. So the
// stand-in owns the failure, and every assertion here is about the client's
// own behaviour rather than about traffic accounting.
type fakeClashAPI struct {
	mu sync.Mutex
	// refuse holds path prefixes the server answers with 503 instead of an
	// upgrade. Set while connected to make one re-subscribe fail.
	refuse []string
	// dialed counts accepted upgrades per path, so a test can prove a stream
	// was NOT re-dialled.
	dialed   map[string]int
	server   *http.Server
	listener net.Listener
}

func startFakeClashAPI(t *testing.T, socketPath string) *fakeClashAPI {
	t.Helper()
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	api := &fakeClashAPI{dialed: make(map[string]int), listener: listener}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		target := request.URL.RequestURI()
		if request.Header.Get("Upgrade") == "" {
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write([]byte("{}"))
			return
		}
		if api.refusing(target) {
			writer.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		connection, err := websocket.Accept(writer, request, nil)
		if err != nil {
			return
		}
		api.recordDial(target)
		// Not request.Context(): once Accept hijacks the connection this
		// handler returns immediately, which would cancel it and end the
		// stream before it published anything. The write error when the
		// client goes away is what ends it.
		go api.publish(connection)
	})
	api.server = &http.Server{Handler: mux}
	go func() { _ = api.server.Serve(listener) }()
	t.Cleanup(func() {
		_ = api.server.Close()
		_ = listener.Close()
	})
	return api
}

// publish keeps the stream alive and delivering. The payload is the same shape
// the real /traffic sends, because the client rejects anything that is not
// valid JSON text.
func (a *fakeClashAPI) publish(connection *websocket.Conn) {
	defer connection.CloseNow()
	for {
		writeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		err := connection.Write(writeCtx, websocket.MessageText,
			[]byte(`{"up":0,"down":0,"upTotal":0,"downTotal":0}`))
		cancel()
		if err != nil {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func (a *fakeClashAPI) refusing(target string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, prefix := range a.refuse {
		if strings.HasPrefix(target, prefix) {
			return true
		}
	}
	return false
}

func (a *fakeClashAPI) recordDial(target string) {
	a.mu.Lock()
	a.dialed[target]++
	a.mu.Unlock()
}

func (a *fakeClashAPI) refuseAll(prefixes ...string) {
	a.mu.Lock()
	a.refuse = append(a.refuse, prefixes...)
	a.mu.Unlock()
}

func (a *fakeClashAPI) dialCount(target string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.dialed[target]
}

// streamConnections maps each live stream's path to the connection object
// carrying it. Identity across a scope change is the proof that a stream was
// left alone rather than re-dialled into an equivalent-looking one.
func (c *ClashAPIClient) streamConnections() map[string]*websocket.Conn {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]*websocket.Conn)
	if c.session == nil {
		return out
	}
	for _, stream := range c.session.streams {
		out[stream.path] = stream.conn
	}
	return out
}

// scopeHandler drops rather than blocks. The recording handler used elsewhere
// buffers two messages and blocks on the third, which is fine against the real
// core publishing once a second and fatal against a fixture publishing
// continuously: a blocked write wedges that stream's read loop, and Close()
// waits on exactly those goroutines. The hang looks like a deadlock in the
// code under test and is not one.
type scopeHandler struct {
	once         sync.Once
	connected    chan struct{}
	disconnected chan string
	traffic      chan string
}

func newScopeHandler() *scopeHandler {
	return &scopeHandler{
		connected:    make(chan struct{}),
		disconnected: make(chan string, 1),
		traffic:      make(chan string, 16),
	}
}

func (h *scopeHandler) Connected() { h.once.Do(func() { close(h.connected) }) }
func (h *scopeHandler) Disconnected(message string) {
	select {
	case h.disconnected <- message:
	default:
	}
}
func (h *scopeHandler) WriteTraffic(message string) {
	select {
	case h.traffic <- message:
	default:
	}
}
func (h *scopeHandler) WriteMemory(string)      {}
func (h *scopeHandler) WriteLogs(string)        {}
func (h *scopeHandler) WriteConnections(string) {}
func (h *scopeHandler) WriteMode(string)        {}

func connectedScopeClient(t *testing.T, onlyProxy bool) (*ClashAPIClient, *fakeClashAPI, *scopeHandler) {
	t.Helper()
	path := shortClashSocketPath(t)
	api := startFakeClashAPI(t, path)
	options := &ClashAPIClientOptions{OnlyStatisticsProxy: onlyProxy}
	options.AddCommand(CommandStatus)
	options.AddCommand(CommandLog)
	options.AddCommand(CommandConnections)
	handler := newScopeHandler()
	client, err := NewClashAPIClientWithOptions(path, handler, options)
	if err != nil {
		t.Fatalf("NewClashAPIClientWithOptions: %v", err)
	}
	t.Cleanup(client.Close)
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	return client, api, handler
}

// drainTraffic empties whatever the fixture published before now, so the next
// frame observed is one that arrived after the action under test.
func drainTraffic(handler *scopeHandler) {
	for {
		select {
		case <-handler.traffic:
		default:
			return
		}
	}
}

func awaitTraffic(t *testing.T, handler *scopeHandler, why string) {
	t.Helper()
	select {
	case <-handler.traffic:
	case <-time.After(3 * time.Second):
		t.Fatalf("no traffic frame arrived %s", why)
	}
}

// Changing which bytes the number counts is an observation. It must not cost
// a connection duration that live on the other streams, and tearing those down
// to add one query parameter is what made the tap cost a 690ms frame.
func TestSetOnlyStatisticsProxyChangesScopeOnALiveConnection(t *testing.T) {
	client, _, handler := connectedScopeClient(t, false)
	awaitTraffic(t, handler, "before the scope change")

	if before := client.streamConnections(); before["/traffic"] == nil {
		t.Fatalf("expected a plain /traffic stream, got %v", pathsOf(before))
	}
	if err := client.SetOnlyStatisticsProxy(true); err != nil {
		t.Fatalf("SetOnlyStatisticsProxy: %v", err)
	}

	after := client.streamConnections()
	if after["/traffic?only-proxy=true"] == nil {
		t.Fatalf("traffic stream did not move to the proxy-only path: %v", pathsOf(after))
	}
	if after["/traffic"] != nil {
		t.Fatalf("the old traffic stream is still subscribed: %v", pathsOf(after))
	}
	// A path is not a promise. Everything published before the swap is
	// discarded, so the frame waited for below can only have come from the
	// stream that replaced it.
	drainTraffic(handler)
	awaitTraffic(t, handler, "after the scope change")

	select {
	case message := <-handler.disconnected:
		t.Fatalf("the control session was torn down: %q", message)
	default:
	}
}

// The whole point, and the part a signature alone does not prove: the streams
// that have nothing to do with the traffic scope must be the same connections
// afterwards, not equivalent-looking new ones.
func TestSetOnlyStatisticsProxyLeavesTheOtherStreamsUntouched(t *testing.T) {
	client, api, handler := connectedScopeClient(t, false)
	awaitTraffic(t, handler, "before the scope change")
	before := client.streamConnections()

	if err := client.SetOnlyStatisticsProxy(true); err != nil {
		t.Fatalf("SetOnlyStatisticsProxy: %v", err)
	}
	after := client.streamConnections()

	for _, path := range []string{"/memory", "/logs?level=info", "/connections?interval=1000"} {
		if before[path] == nil {
			t.Fatalf("%s was not subscribed to begin with: %v", path, pathsOf(before))
		}
		if before[path] != after[path] {
			t.Fatalf("%s was re-dialled across a traffic-scope change", path)
		}
		if count := api.dialCount(path); count != 1 {
			t.Fatalf("%s was dialled %d times, want 1", path, count)
		}
	}
}

// The client calls this on every activation, so the value it already has must
// cost nothing at all — not a re-dial that happens to end up at the same path.
func TestSetOnlyStatisticsProxyIsIdempotent(t *testing.T) {
	client, api, handler := connectedScopeClient(t, true)
	awaitTraffic(t, handler, "before the no-op")
	before := client.streamConnections()

	if err := client.SetOnlyStatisticsProxy(true); err != nil {
		t.Fatalf("SetOnlyStatisticsProxy: %v", err)
	}

	after := client.streamConnections()
	if before["/traffic?only-proxy=true"] != after["/traffic?only-proxy=true"] {
		t.Fatal("setting the current value re-dialled the traffic stream")
	}
	if count := api.dialCount("/traffic?only-proxy=true"); count != 1 {
		t.Fatalf("traffic was dialled %d times, want 1", count)
	}
}

// seeing all-traffic numbers. A re-subscribe that cannot be made must report
// that and leave what was working alone — including the session itself.
func TestSetOnlyStatisticsProxyKeepsTheOldStreamWhenTheNewOneFails(t *testing.T) {
	client, api, handler := connectedScopeClient(t, false)
	awaitTraffic(t, handler, "before the failed change")
	before := client.streamConnections()

	api.refuseAll("/traffic?only-proxy=true")
	err := client.SetOnlyStatisticsProxy(true)
	if err == nil {
		t.Fatal("a refused re-subscribe reported success")
	}

	after := client.streamConnections()
	if before["/traffic"] != after["/traffic"] {
		t.Fatalf("the working traffic stream was dropped for a dial that failed: %v", pathsOf(after))
	}
	// Still delivering, and the session still up.
	drainTraffic(handler)
	awaitTraffic(t, handler, "after the failed change")
	select {
	case message := <-handler.disconnected:
		t.Fatalf("a failed re-subscribe tore down the session: %q", message)
	default:
	}

	// And the client did not quietly adopt a scope it failed to apply: asking
	// again must try again, not report the no-op of a value it never reached.
	if err := client.SetOnlyStatisticsProxy(true); err == nil {
		t.Fatal("the failed scope was recorded as if it had been applied")
	}
}

func pathsOf(streams map[string]*websocket.Conn) []string {
	out := make([]string, 0, len(streams))
	for path := range streams {
		out = append(out, path)
	}
	return out
}
