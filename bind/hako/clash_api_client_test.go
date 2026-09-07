package hako

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/TokenPLS/Hako/listener"
	"github.com/TokenPLS/Hako/log"
	"github.com/TokenPLS/Hako/tunnel"
)

type recordingClashAPIHandler struct {
	connected    chan struct{}
	disconnected chan string
	traffic      chan string
	memory       chan string
	logs         chan string
	connections  chan string
	modes        chan string
	once         sync.Once
}

func newRecordingClashAPIHandler() *recordingClashAPIHandler {
	return &recordingClashAPIHandler{
		connected:    make(chan struct{}),
		disconnected: make(chan string, 1),
		traffic:      make(chan string, 2),
		memory:       make(chan string, 2),
		logs:         make(chan string, 2),
		connections:  make(chan string, 2),
		modes:        make(chan string, 4),
	}
}

func (h *recordingClashAPIHandler) Connected() { h.once.Do(func() { close(h.connected) }) }
func (h *recordingClashAPIHandler) Disconnected(message string) {
	select {
	case h.disconnected <- message:
	default:
	}
}
func (h *recordingClashAPIHandler) WriteTraffic(message string) { h.traffic <- message }
func (h *recordingClashAPIHandler) WriteMemory(message string)  { h.memory <- message }
func (h *recordingClashAPIHandler) WriteLogs(message string)    { h.logs <- message }
func (h *recordingClashAPIHandler) WriteMode(message string) {
	select {
	case h.modes <- message:
	default:
	}
}

func (h *recordingClashAPIHandler) WriteConnections(message string) {
	h.connections <- message
}

func TestClashAPIClientStreamsAndREST(t *testing.T) {
	// Own a rejecting endpoint instead of assuming a developer's port 1080
	// is unused. Every accepted connection closes before a SOCKS handshake.
	rejecting, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			connection, err := rejecting.Accept()
			if err != nil {
				return
			}
			_ = connection.Close()
		}
	}()
	t.Cleanup(func() { _ = rejecting.Close(); <-stopped })
	configuration := strings.Replace(helloYAML, "port: 1080",
		"port: "+strconv.Itoa(rejecting.Addr().(*net.TCPAddr).Port), 1)

	options := testOptions(t)
	if err := Setup(options); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	service, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	t.Cleanup(func() { _ = service.Close() })
	if err := service.Start(configuration); err != nil {
		t.Fatalf("Start: %v", err)
	}
	path := shortClashSocketPath(t)
	if err := startControlPlane(nil, path); err != nil {
		t.Fatalf("startClashAPI: %v", err)
	}
	t.Cleanup(func() { stopClashAPI(path) })
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat Clash API socket: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("Clash API socket mode = %04o, want 0600", got)
	}

	handler := newRecordingClashAPIHandler()
	client, err := NewClashAPIClient(path, handler)
	if err != nil {
		t.Fatalf("NewClashAPIClient: %v", err)
	}
	t.Cleanup(client.Close)
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	select {
	case <-handler.connected:
	case <-time.After(time.Second):
		t.Fatal("connected callback missing")
	}

	select {
	case payload := <-handler.traffic:
		var traffic map[string]int64
		if err := json.Unmarshal([]byte(payload), &traffic); err != nil {
			t.Fatalf("traffic JSON: %v", err)
		}
		for _, key := range []string{"up", "down", "upTotal", "downTotal"} {
			if _, ok := traffic[key]; !ok {
				t.Fatalf("traffic missing %q: %s", key, payload)
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("traffic stream did not publish")
	}

	select {
	case payload := <-handler.memory:
		if !json.Valid([]byte(payload)) {
			t.Fatalf("memory stream invalid JSON: %q", payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("memory stream did not publish")
	}

	log.Infoln("clash-api-log-probe")
	select {
	case payload := <-handler.logs:
		if !strings.Contains(payload, "clash-api-log-probe") {
			t.Fatalf("unexpected log payload: %s", payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("log stream did not publish")
	}

	configs, err := client.GetConfigs()
	if err != nil || !json.Valid([]byte(configs)) {
		t.Fatalf("GetConfigs = %q, %v", configs, err)
	}
	trafficSnapshot, err := client.GetTraffic()
	if err != nil || !json.Valid([]byte(trafficSnapshot)) {
		t.Fatalf("GetTraffic = %q, %v", trafficSnapshot, err)
	}
	memorySnapshot, err := client.GetMemory()
	if err != nil || !json.Valid([]byte(memorySnapshot)) {
		t.Fatalf("GetMemory = %q, %v", memorySnapshot, err)
	}
	rules, err := client.GetRules()
	if err != nil || !strings.Contains(rules, `"rules"`) {
		t.Fatalf("GetRules = %q, %v", rules, err)
	}
	if err := client.FlushDNSCache(); err != nil {
		t.Fatalf("FlushDNSCache: %v", err)
	}
	if err := client.FlushFakeIPCache(); err != nil {
		t.Fatalf("FlushFakeIPCache: %v", err)
	}
	proxies, err := client.GetProxies()
	if err != nil || !strings.Contains(proxies, `"probe"`) {
		t.Fatalf("GetProxies = %q, %v", proxies, err)
	}
	if _, err := client.URLTest("probe", "http://127.0.0.1:1/"); err == nil {
		t.Fatal("unreachable fixture unexpectedly passed URLTest")
	} else {
		// The error names the endpoint it failed on, proxy name included
		// . It used to be rewritten to
		// `/proxies/<redacted>`, which left a reader with a failure that could
		// not be told from the same failure on any other node.
		if !strings.Contains(err.Error(), "probe") {
			t.Fatalf("URLTest error does not name the proxy it failed on: %v", err)
		}
		if strings.Contains(err.Error(), "An error occurred in the delay test") {
			t.Fatalf("URLTest discarded the underlying dial error: %v", err)
		}
	}
	groups, err := client.GetGroups()
	if err != nil || !json.Valid([]byte(groups)) {
		t.Fatalf("GetGroups = %q, %v", groups, err)
	}
	version, err := client.GetVersion()
	if err != nil || !strings.Contains(version, `"version"`) {
		t.Fatalf("GetVersion = %q, %v", version, err)
	}
	if err := client.SetMode("global"); err != nil {
		t.Fatalf("SetMode: %v", err)
	}
	if service.Mode() != "global" {
		t.Fatalf("mode = %q, want global", service.Mode())
	}
	// PATCH /configs is open now, and this assertion used to say the opposite. The embed gate
	// closed it alongside PUT and POST /geo, whose reasons -- bypassing the revision pipeline,
	// downloading inside the extension -- are not true of PATCH. Switching modes from a
	// dashboard is the most ordinary action a Clash panel has, and it answered 405 on a device.
	if _, err := client.request(http.MethodPatch, "/configs", map[string]string{"mode": "direct"}); err != nil {
		t.Fatalf("PATCH /configs is a runtime switch and must be available: %v", err)
	}
	if service.Mode() != "direct" {
		t.Fatalf("PATCH /configs did not take effect; mode = %q", service.Mode())
	}
	// What stays closed is the one the reason actually covers: replacing the whole configuration
	// would walk past the immutable revision pipeline the containing app owns.
	if _, err := client.request(http.MethodPut, "/configs", map[string]string{"path": "/dev/null"}); err == nil {
		t.Fatal("PUT /configs remained available; it bypasses the revision pipeline")
	}

	client.Close()
	select {
	case message := <-handler.disconnected:
		if message != "" {
			t.Fatalf("clean close reported error %q", message)
		}
	case <-time.After(time.Second):
		t.Fatal("disconnected callback missing")
	}
	// The upstream /memory handler only observes a peer close on its next 1 Hz
	// write. Let it leave before opening another status stream; otherwise two
	// handlers call mihomo's known non-synchronized Memory() sampler at once.
	time.Sleep(1100 * time.Millisecond)

	statusOptions := &ClashAPIClientOptions{}
	statusOptions.AddCommand(CommandStatus)
	statusHandler := newRecordingClashAPIHandler()
	statusClient, err := NewClashAPIClientWithOptions(path, statusHandler, statusOptions)
	if err != nil {
		t.Fatal(err)
	}
	if err := statusClient.Connect(); err != nil {
		t.Fatal(err)
	}
	defer statusClient.Close()
	select {
	case <-statusHandler.traffic:
	case <-time.After(2 * time.Second):
		t.Fatal("status-only client did not receive traffic")
	}
	log.Infoln("status-only-must-not-subscribe-logs")
	select {
	case payload := <-statusHandler.logs:
		t.Fatalf("status-only client received log %q", payload)
	case <-time.After(150 * time.Millisecond):
	}
	statusClient.Close()

	connectionsOptions := &ClashAPIClientOptions{StatusInterval: 100}
	connectionsOptions.AddCommand(CommandConnections)
	connectionsHandler := newRecordingClashAPIHandler()
	connectionsClient, err := NewClashAPIClientWithOptions(path, connectionsHandler, connectionsOptions)
	if err != nil {
		t.Fatal(err)
	}
	if err := connectionsClient.Connect(); err != nil {
		t.Fatal(err)
	}
	select {
	case payload := <-connectionsHandler.connections:
		if !json.Valid([]byte(payload)) || !strings.Contains(payload, `"connections"`) {
			t.Fatalf("invalid connections stream payload %q", payload)
		}
	case <-time.After(time.Second):
		t.Fatal("connections stream did not publish initial snapshot")
	}
	connections, err := connectionsClient.GetConnections()
	if err != nil || !json.Valid([]byte(connections)) {
		t.Fatalf("GetConnections = %q, %v", connections, err)
	}
	if err := connectionsClient.CloseConnection("missing/id"); err != nil {
		t.Fatalf("CloseConnection: %v", err)
	}
	if err := connectionsClient.CloseConnections(); err != nil {
		t.Fatalf("CloseConnections: %v", err)
	}
	connectionsClient.Close()

	restHandler := newRecordingClashAPIHandler()
	restClient, err := NewClashAPIClientWithOptions(path, restHandler, &ClashAPIClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := restClient.Connect(); err != nil {
		t.Fatalf("REST-only Connect probe: %v", err)
	}
	restClient.Close()
}

func TestClashAPIClientRejectsInvalidInputs(t *testing.T) {
	if _, err := NewClashAPIClient("", newRecordingClashAPIHandler()); err == nil {
		t.Fatal("empty socket path accepted")
	}
	if _, err := NewClashAPIClient("/tmp/clash.sock", nil); err == nil {
		t.Fatal("nil handler accepted")
	}
	client, err := NewClashAPIClient("/tmp/does-not-exist.sock", newRecordingClashAPIHandler())
	if err != nil {
		t.Fatal(err)
	}
	if err := client.SetMode("mystery"); err == nil {
		t.Fatal("unknown mode accepted")
	}
	if err := client.SelectProxy("", "node"); err == nil {
		t.Fatal("empty group accepted")
	}
	if err := client.UnfixProxy(""); err == nil {
		t.Fatal("empty unfix group accepted")
	}
	if _, err := client.QueryDNS("", "A"); err == nil {
		t.Fatal("empty DNS query name accepted")
	}
	if _, err := client.QueryDNS("example.com", "INVALID"); err == nil {
		t.Fatal("invalid DNS query type accepted")
	}
	badOptions := &ClashAPIClientOptions{LogLevel: "verbose"}
	badOptions.AddCommand(CommandLog)
	badClient, err := NewClashAPIClientWithOptions("/tmp/does-not-exist.sock", newRecordingClashAPIHandler(), badOptions)
	if err != nil {
		t.Fatal(err)
	}
	if err := badClient.Connect(); err == nil || !strings.Contains(err.Error(), "log level") {
		t.Fatalf("invalid log level Connect = %v", err)
	}
	unknownOptions := &ClashAPIClientOptions{}
	unknownOptions.AddCommand(99)
	unknownClient, err := NewClashAPIClientWithOptions("/tmp/does-not-exist.sock", newRecordingClashAPIHandler(), unknownOptions)
	if err != nil {
		t.Fatal(err)
	}
	if err := unknownClient.Connect(); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("unknown command Connect = %v", err)
	}
	badInterval := &ClashAPIClientOptions{StatusInterval: 1}
	badInterval.AddCommand(CommandConnections)
	intervalClient, err := NewClashAPIClientWithOptions("/tmp/does-not-exist.sock", newRecordingClashAPIHandler(), badInterval)
	if err != nil {
		t.Fatal(err)
	}
	if err := intervalClient.Connect(); err == nil || !strings.Contains(err.Error(), "interval") {
		t.Fatalf("invalid interval Connect = %v", err)
	}
}

func TestClashAPIClientRequestsProxyOnlyTrafficWithoutChangingOtherStreams(t *testing.T) {
	options := &ClashAPIClientOptions{OnlyStatisticsProxy: true}
	options.AddCommand(CommandStatus)
	options.AddCommand(CommandLog)
	options.AddCommand(CommandConnections)
	client, err := NewClashAPIClientWithOptions(
		"/tmp/does-not-exist.sock",
		newRecordingClashAPIHandler(),
		options,
	)
	if err != nil {
		t.Fatal(err)
	}

	specs, err := client.streamSpecs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	wantPaths := []string{
		"/traffic?only-proxy=true",
		"/memory",
		"/logs?level=info",
		"/connections?interval=1000",
	}
	if len(specs) != len(wantPaths) {
		t.Fatalf("stream count = %d, want %d", len(specs), len(wantPaths))
	}
	for index, want := range wantPaths {
		if got := specs[index].path; got != want {
			t.Fatalf("stream %d path = %q, want %q", index, got, want)
		}
	}

	options.OnlyStatisticsProxy = false
	defaultSpecs, err := client.streamSpecs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := defaultSpecs[0].path; got != "/traffic?only-proxy=true" {
		t.Fatalf("client options were not copied: traffic path = %q", got)
	}
}

// A subscription node lives under its provider, not in the global proxies
// table, and upstream measures it at /providers/proxies/{provider}/{name}/
// healthcheck. The client asked /proxies for every name, so every probe of a
// reader whose nodes all come from a subscription could measure nothing.
//
// A real core with a file provider and an include-all group, so the routing is
// upstream's, not a stub's. The node itself points at a dead port on purpose:
// the assertion is about WHICH failure comes back. A 404 means the name was
// never found; anything else means the probe reached the node and the node
// did not answer, which is the truth for a fixture.
func TestURLTestReachesProviderNodesThroughTheirProvider(t *testing.T) {
	options := testOptions(t)
	if err := Setup(options); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	providersDir := filepath.Join(options.WorkingPath, "providers")
	if err := os.MkdirAll(providersDir, 0o755); err != nil {
		t.Fatal(err)
	}
	const providerBody = `proxies:
  - name: 订阅节点甲
    type: socks5
    server: 127.0.0.1
    port: 1
  - name: 订阅节点乙
    type: socks5
    server: 127.0.0.1
    port: 1
`
	if err := os.WriteFile(
		filepath.Join(providersDir, "sub.yaml"), []byte(providerBody), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	// A second subscription that carries a node of the SAME name, plus one of
	// its own. Same-named nodes across subscriptions are ordinary — two
	// report a number that may belong to a different server.
	const secondBody = `proxies:
  - name: 订阅节点甲
    type: socks5
    server: 127.0.0.1
    port: 1
  - name: 独占节点
    type: socks5
    server: 127.0.0.1
    port: 1
`
	if err := os.WriteFile(
		filepath.Join(providersDir, "sub2.yaml"), []byte(secondBody), 0o600,
	); err != nil {
		t.Fatal(err)
	}

	service, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	t.Cleanup(func() { _ = service.Close() })
	configuration := `
mode: rule
log-level: info
dns:
  enable: true
  enhanced-mode: fake-ip
  nameserver:
    - 8.8.8.8
proxy-providers:
  订阅乙:
    type: file
    path: ` + filepath.Join(providersDir, "sub2.yaml") + `
    health-check:
      enable: false
      url: https://www.gstatic.com/generate_204
      interval: 0
  订阅:
    type: file
    path: ` + filepath.Join(providersDir, "sub.yaml") + `
    health-check:
      enable: false
      url: https://www.gstatic.com/generate_204
      interval: 0
proxy-groups:
  - name: 全部
    type: select
    include-all: true
rules:
  - MATCH,全部
`
	if err := service.Start(configuration); err != nil {
		t.Fatalf("Start: %v", err)
	}
	path := shortClashSocketPath(t)
	if err := startControlPlane(nil, path); err != nil {
		t.Fatalf("startClashAPI: %v", err)
	}
	t.Cleanup(func() { stopClashAPI(path) })

	client, err := NewClashAPIClient(path, newRecordingClashAPIHandler())
	if err != nil {
		t.Fatalf("NewClashAPIClient: %v", err)
	}
	t.Cleanup(client.Close)

	// providers of the include-all group carry both — the group's shell must
	// not win by map order, and a genuine collision must refuse rather than
	// guess.
	providerName, found := client.providerOf("订阅节点乙")
	if !found || providerName != "订阅" {
		t.Fatalf("providerOf = (%q, %v), want (订阅, true)", providerName, found)
	}
	if second, ok := client.providerOf("独占节点"); !ok || second != "订阅乙" {
		t.Fatalf("providerOf = (%q, %v), want (订阅乙, true)", second, ok)
	}
	if colliding, ok := client.providerOf("订阅节点甲"); ok {
		t.Fatalf("a name carried by two subscriptions was attributed to %q", colliding)
	}
	if _, stale := client.providerOf("从来没有过的名字"); stale {
		t.Fatal("an unknown node was attributed to a provider")
	}

	// The probe itself: wrong answers 404, right answers anything else.
	_, probeErr := client.URLTest("订阅节点乙", "")
	if probeErr == nil {
		t.Fatal("a node on a dead port measured successfully")
	}
	if isClashAPINotFound(probeErr) {
		t.Fatalf("the probe never reached the node: %v", probeErr)
	}

	// A name that exists nowhere still says so.
	_, missingErr := client.URLTest("从来没有过的名字", "")
	if !isClashAPINotFound(missingErr) {
		t.Fatalf("a missing name did not report not-found: %v", missingErr)
	}

	// A provider update changes exactly the fact the index caches, so the
	// index must be forgotten on update rather than left to its TTL: within
	// that minute a freshly added node keeps 404ing and a removed one would
	// measure a ghost.
	const updatedBody = `proxies:
  - name: 订阅节点甲
    type: socks5
    server: 127.0.0.1
    port: 1
  - name: 订阅节点乙
    type: socks5
    server: 127.0.0.1
    port: 1
  - name: 更新后新增节点
    type: socks5
    server: 127.0.0.1
    port: 1
`
	if _, fresh := client.providerOf("更新后新增节点"); fresh {
		t.Fatal("the new node was known before the update")
	}
	if err := client.SideUpdateProxyProvider("订阅", []byte(updatedBody)); err != nil {
		t.Fatalf("SideUpdateProxyProvider: %v", err)
	}
	if after, ok := client.providerOf("更新后新增节点"); !ok || after != "订阅" {
		t.Fatalf("providerOf after update = (%q, %v), want (订阅, true) without waiting out the TTL",
			after, ok)
	}
}

// The route existed before anything could subscribe to it, which is this batch's fifth
// half-a-surface: /hako/v1/mode was registered and served, and ClashAPIClient -- the only path
// Swift has to the controller -- had no command that reached it and no callback to deliver it.
// A producer with no consumer is as useless as a consumer with no producer, and it fails more
// quietly, because the route answers 200 to anyone who happens to curl it.
//
// The consuming lane found it by preparing to USE the endpoint. That is the general lesson:
// the missing half is visible from the other side, and only from there.
func TestModeCommandDeliversRuntimeSwitchesToTheHandler(t *testing.T) {
	previousMode, previousLan := tunnel.Mode(), listener.AllowLan()
	t.Cleanup(func() {
		tunnel.SetMode(previousMode)
		listener.SetAllowLan(previousLan)
	})
	tunnel.SetMode(tunnel.Rule)
	listener.SetAllowLan(false)

	path := shortClashSocketPath(t)
	if err := startControlPlane(nil, path); err != nil {
		t.Fatalf("startControlPlane: %v", err)
	}
	t.Cleanup(func() { stopClashAPI(path) })

	handler := newRecordingClashAPIHandler()
	options := &ClashAPIClientOptions{}
	options.AddCommand(CommandMode)
	client, err := NewClashAPIClientWithOptions(path, handler, options)
	if err != nil {
		t.Fatalf("NewClashAPIClient: %v", err)
	}
	t.Cleanup(client.Close)
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	first := receiveWithin(t, handler.modes, 5*time.Second, "the snapshot on connect")
	if !strings.Contains(first, `"mode":"rule"`) || !strings.Contains(first, `"allow-lan":false`) {
		t.Fatalf("the first message was %q, not what the tunnel is running", first)
	}

	tunnel.SetMode(tunnel.Global)
	changed := receiveWithin(t, handler.modes, 5*time.Second, "the message after a change")
	if !strings.Contains(changed, `"mode":"global"`) {
		t.Errorf("after SetMode(Global) the handler saw %q", changed)
	}
}

func receiveWithin(t *testing.T, source <-chan string, wait time.Duration, what string) string {
	t.Helper()
	select {
	case message := <-source:
		return message
	case <-time.After(wait):
		t.Fatalf("no %s arrived within %s", what, wait)
		return ""
	}
}

// URLTest hands the client an int and an error whose text is the whole answer,
// so the App had to match a dozen substrings against this tree's English to
// learn anything. Any rewording here moved a category there silently,
// and causes a substring cannot separate arrived on screen as one word: a
// loopback resolver.
//
// URLTestOutcome answers with the same shape the delay route now answers with,
// so both ends read one contract.
func TestURLTestOutcomeAnswersWithClassifiedFields(t *testing.T) {
	options := testOptions(t)
	if err := Setup(options); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	service, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	t.Cleanup(func() { _ = service.Close() })
	// Port 1 on loopback: nothing is listening, so the dial fails with a typed
	// error rather than a timeout, and the test does not wait on the network.
	configuration := `
mode: rule
log-level: info
proxies:
  - name: 不通的节点
    type: socks5
    server: 127.0.0.1
    port: 1
proxy-groups:
  - name: 全部
    type: select
    proxies:
      - 不通的节点
rules:
  - MATCH,全部
`
	if err := service.Start(configuration); err != nil {
		t.Fatalf("Start: %v", err)
	}
	path := shortClashSocketPath(t)
	if err := startControlPlane(nil, path); err != nil {
		t.Fatalf("startClashAPI: %v", err)
	}
	t.Cleanup(func() { stopClashAPI(path) })
	client, err := NewClashAPIClient(path, newRecordingClashAPIHandler())
	if err != nil {
		t.Fatalf("NewClashAPIClient: %v", err)
	}
	t.Cleanup(client.Close)

	payload, err := client.URLTestOutcome("不通的节点", "http://127.0.0.1:1/")
	if err != nil {
		t.Fatalf("URLTestOutcome returned an error instead of an answer: %v", err)
	}
	var answer struct {
		Delay    int  `json:"delay"`
		Deferred bool `json:"deferred"`
		Failure  *struct {
			Kind    string `json:"kind"`
			Errno   string `json:"errno"`
			Message string `json:"message"`
		} `json:"failure"`
	}
	if err := json.Unmarshal([]byte(payload), &answer); err != nil {
		t.Fatalf("answer is not json: %v\n%s", err, payload)
	}
	if answer.Failure == nil {
		t.Fatalf("no classified failure: %s", payload)
	}
	if answer.Failure.Kind == "" || answer.Failure.Kind == "unknown" {
		t.Errorf("kind = %q -- a refused dial has a type to read\n%s", answer.Failure.Kind, payload)
	}
	// the sentence survives beside the classification.
	if answer.Failure.Message == "" {
		t.Errorf("the verbatim sentence was dropped: %s", payload)
	}
}
