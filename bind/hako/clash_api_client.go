package hako

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/miekg/dns"
)

const (
	clashAPIRequestTimeout = 15 * time.Second
	clashAPIDialAttempts   = 10
	clashAPIMaxMessageSize = 16 << 20
	// How long the node-to-provider index answers before it is re-read.
	clashAPIProviderIndexTTL = time.Minute
)

const (
	// CommandLog subscribes mihomo's native /logs WebSocket.
	CommandLog int32 = iota
	// CommandStatus subscribes /traffic and /memory as one logical libbox-style
	// status command.
	CommandStatus
	// CommandConnections subscribes mihomo's /connections WebSocket.
	CommandConnections
	// CommandMode subscribes this binding's /hako/v1/mode WebSocket: the current mode and
	// allow-lan on connect, then one message per change.
	//
	// It exists because those two values acquired writers the app cannot see. Opening
	// PATCH /configs let a dashboard change mode from another device, and allow-lan has three
	// writers at once -- the app's own permission gate, a parsed configuration being applied,
	// and that same PATCH. An app holding the value it last set is holding a cache with no
	// invalidation, which showed up on a device as "switched mode in the panel, app did not
	// change".
	CommandMode
)

// ClashAPIClientOptions selects long-lived streams. REST methods remain
// available regardless of this list, matching libbox CommandClientOptions.
type ClashAPIClientOptions struct {
	LogLevel            string
	StatusInterval      int64
	OnlyStatisticsProxy bool
	commands            []int32
}

func (o *ClashAPIClientOptions) AddCommand(command int32) {
	if o == nil {
		return
	}
	o.commands = append(o.commands, command)
}

// ClashAPIClientHandler mirrors libbox's command-client callback boundary:
// Go owns the socket/protocol lifecycle; Swift only publishes messages.
type ClashAPIClientHandler interface {
	Connected()
	Disconnected(message string)
	WriteTraffic(message string)
	WriteMemory(message string)
	WriteLogs(message string)
	WriteConnections(message string)
	// WriteMode receives {"mode":"...","allow-lan":bool} whenever either changes, and once on
	// connect so a subscriber that attaches late is not left believing what it last knew.
	WriteMode(message string)
}

type clashAPIStream struct {
	path   string
	write  func(string)
	conn   *websocket.Conn
	client *ClashAPIClient
	// retired marks a stream this client deliberately replaced. Its read loop
	// is then expected to fail, and must exit quietly: reporting that failure
	// would call finish() and take /logs, /memory and /connections down with
	// it — the exact teardown a live scope change exists to avoid.
	retired atomic.Bool
}

type clashAPISession struct {
	ctx       context.Context
	cancel    context.CancelFunc
	streams   []*clashAPIStream
	wg        sync.WaitGroup
	closeOnce sync.Once
}

// ClashAPIClient is the app-process command client for mihomo's native API.
// It dials the App Group Unix socket directly from Go, like libbox does for
// command.sock, and exposes only gomobile-safe strings/callbacks to Swift.
type ClashAPIClient struct {
	mu         sync.Mutex
	socketPath string
	handler    ClashAPIClientHandler
	httpClient *http.Client
	session    *clashAPISession
	options    ClashAPIClientOptions

	// scopeMu serialises traffic-scope changes so two callers cannot both
	// decide the value differs and both dial a replacement. It is taken
	// before mu and never while holding it.
	scopeMu sync.Mutex
	// onlyStatisticsProxy is the live traffic scope. It is seeded from the
	// options and then owned here rather than in the options struct, because
	// Connect reads the specs without holding mu and a scope change can
	// arrive at any time.
	onlyStatisticsProxy atomic.Bool

	// Which provider carries which node, for measuring subscription nodes.
	providerIndexMu sync.Mutex
	providerIndex   map[string]string
	providerIndexAt time.Time
}

func NewClashAPIClient(socketPath string, handler ClashAPIClientHandler) (*ClashAPIClient, error) {
	options := &ClashAPIClientOptions{}
	options.AddCommand(CommandStatus)
	options.AddCommand(CommandLog)
	return NewClashAPIClientWithOptions(socketPath, handler, options)
}

// NewClashAPIClientWithOptions constructs a client with selected streams. A
// nil options value preserves the convenience constructor's status+log
// behavior; an empty non-nil value creates a REST-only connected client.
func NewClashAPIClientWithOptions(socketPath string, handler ClashAPIClientHandler, options *ClashAPIClientOptions) (*ClashAPIClient, error) {
	if socketPath == "" {
		return nil, errors.New("hako: Clash API client requires a Unix socket path")
	}
	if len([]byte(socketPath)) > clashAPIMaxUnixPathBytes {
		return nil, fmt.Errorf("hako: Clash API Unix path is %d bytes; Darwin limit is %d", len([]byte(socketPath)), clashAPIMaxUnixPathBytes)
	}
	if handler == nil {
		return nil, errors.New("hako: Clash API client requires a handler")
	}
	if options == nil {
		options = &ClashAPIClientOptions{}
		options.AddCommand(CommandStatus)
		options.AddCommand(CommandLog)
	}
	clientOptions := ClashAPIClientOptions{
		LogLevel:            options.LogLevel,
		StatusInterval:      options.StatusInterval,
		OnlyStatisticsProxy: options.OnlyStatisticsProxy,
		commands:            append([]int32(nil), options.commands...),
	}
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", socketPath)
		},
	}
	client := &ClashAPIClient{
		socketPath: socketPath,
		handler:    handler,
		httpClient: &http.Client{Transport: transport},
		options:    clientOptions,
	}
	client.onlyStatisticsProxy.Store(clientOptions.OnlyStatisticsProxy)
	return client, nil
}

// Connect establishes all long-lived native streams before reporting success.
// Its bounded retry matches libbox's behavior while the extension is starting.
func (c *ClashAPIClient) Connect() error {
	c.mu.Lock()
	if c.session != nil {
		c.mu.Unlock()
		return errors.New("hako: Clash API client already connected")
	}
	ctx, cancel := context.WithCancel(context.Background())
	session := &clashAPISession{ctx: ctx, cancel: cancel}
	c.mu.Unlock()

	streamSpecs, err := c.streamSpecs()
	if err != nil {
		cancel()
		return err
	}
	if len(streamSpecs) == 0 {
		if err := c.probeWithRetry(ctx); err != nil {
			cancel()
			return err
		}
	}
	for _, spec := range streamSpecs {
		conn, err := c.dialWebSocketWithRetry(ctx, spec.path)
		if err != nil {
			cancel()
			for _, stream := range session.streams {
				stream.conn.CloseNow()
			}
			return err
		}
		conn.SetReadLimit(clashAPIMaxMessageSize)
		session.streams = append(session.streams, &clashAPIStream{
			path: spec.path, write: spec.write, conn: conn, client: c,
		})
	}

	c.mu.Lock()
	if c.session != nil {
		c.mu.Unlock()
		cancel()
		for _, stream := range session.streams {
			stream.conn.CloseNow()
		}
		return errors.New("hako: Clash API client connected concurrently")
	}
	c.session = session
	c.mu.Unlock()

	c.handler.Connected()
	for _, stream := range session.streams {
		session.wg.Add(1)
		go stream.read(session)
	}
	return nil
}

type clashAPIStreamSpec struct {
	path  string
	write func(string)
}

func (c *ClashAPIClient) streamSpecs() ([]clashAPIStreamSpec, error) {
	var specs []clashAPIStreamSpec
	seen := make(map[int32]bool)
	for _, command := range c.options.commands {
		if seen[command] {
			continue
		}
		seen[command] = true
		switch command {
		case CommandLog:
			level := strings.ToLower(strings.TrimSpace(c.options.LogLevel))
			if level == "" {
				level = "info"
			}
			switch level {
			case "debug", "info", "warning", "error", "silent":
			default:
				return nil, fmt.Errorf("hako: invalid Clash API log level %q", c.options.LogLevel)
			}
			specs = append(specs, clashAPIStreamSpec{
				path:  "/logs?" + url.Values{"level": []string{level}}.Encode(),
				write: c.handler.WriteLogs,
			})
		case CommandStatus:
			specs = append(specs,
				clashAPIStreamSpec{
					path:  trafficStreamPath(c.onlyStatisticsProxy.Load()),
					write: c.handler.WriteTraffic,
				},
				clashAPIStreamSpec{path: "/memory", write: c.handler.WriteMemory},
			)
		case CommandMode:
			specs = append(specs, clashAPIStreamSpec{
				path:  "/hako/v1/mode",
				write: c.handler.WriteMode,
			})
		case CommandConnections:
			interval := c.options.StatusInterval
			if interval == 0 {
				interval = 1000
			}
			if interval < 100 || interval > 60_000 {
				return nil, fmt.Errorf("hako: connections interval %dms is outside 100...60000", interval)
			}
			specs = append(specs, clashAPIStreamSpec{
				path:  "/connections?" + url.Values{"interval": []string{fmt.Sprint(interval)}}.Encode(),
				write: c.handler.WriteConnections,
			})
		default:
			return nil, fmt.Errorf("hako: unknown Clash API command %d", command)
		}
	}
	return specs, nil
}

// trafficStreamPath is the one thing the traffic scope decides.
func trafficStreamPath(onlyProxy bool) string {
	if onlyProxy {
		return "/traffic?" + url.Values{"only-proxy": []string{"true"}}.Encode()
	}
	return "/traffic"
}

// SetOnlyStatisticsProxy changes which bytes the traffic stream counts, on a
// connection that stays up.
//
// routing, the tunnel or the core. It used to cost the whole control session,
// because the scope was read once at Connect and the only way to re-read it
// was to reconnect — so one query parameter on one of four streams dropped
// /logs, /memory and /connections too, and the app read that as "the session
// is gone" and rebuilt the node inventory off disk. Measured on device: two
// full teardowns per tap and a 690ms worst frame on Home.
//
// Only the traffic stream is re-subscribed. The other three are never touched.
//
// The order is deliberate: the replacement is dialled first and swapped in
// only once it exists, so a re-subscribe that cannot be made leaves the
// reader with the numbers they already had rather than none. A failure does
// not record the new scope either — asking again retries instead of reporting
// the no-op of a value that was never reached.
func (c *ClashAPIClient) SetOnlyStatisticsProxy(enabled bool) error {
	// Serialised, so two callers cannot both find the value different and
	// both dial. The no-op check has to be inside it for the same reason.
	c.scopeMu.Lock()
	defer c.scopeMu.Unlock()
	if c.onlyStatisticsProxy.Load() == enabled {
		return nil
	}

	c.mu.Lock()
	session := c.session
	var current *clashAPIStream
	if session != nil {
		for _, stream := range session.streams {
			if strings.HasPrefix(stream.path, "/traffic") {
				current = stream
				break
			}
		}
	}
	c.mu.Unlock()

	// Nothing live to re-subscribe: record it and let Connect dial the right
	// path. A client that never asked for CommandStatus lands here too.
	if session == nil || current == nil {
		c.onlyStatisticsProxy.Store(enabled)
		return nil
	}

	path := trafficStreamPath(enabled)
	conn, err := c.dialWebSocketWithRetry(session.ctx, path)
	if err != nil {
		return fmt.Errorf("hako: re-subscribe %s: %w", path, err)
	}
	conn.SetReadLimit(clashAPIMaxMessageSize)

	c.mu.Lock()
	// The session is the token. Dialling happens off the lock, and in that
	// window the session can end or be replaced; adopting the new connection
	// into a session that is no longer current would leave a reader nobody
	// closes.
	if c.session != session {
		c.mu.Unlock()
		conn.CloseNow()
		return errors.New("hako: control session changed while re-subscribing traffic")
	}
	index := -1
	for position, stream := range session.streams {
		if stream == current {
			index = position
			break
		}
	}
	if index < 0 {
		c.mu.Unlock()
		conn.CloseNow()
		return errors.New("hako: traffic stream disappeared while re-subscribing")
	}
	replacement := &clashAPIStream{
		path: path, write: current.write, conn: conn, client: c,
	}
	session.streams[index] = replacement
	// Marked before the close, so the old read loop reads the flag rather
	// than racing it and reporting a teardown that never happened.
	current.retired.Store(true)
	c.onlyStatisticsProxy.Store(enabled)
	session.wg.Add(1)
	c.mu.Unlock()

	current.conn.CloseNow()
	go replacement.read(session)
	return nil
}

func (c *ClashAPIClient) probeWithRetry(ctx context.Context) error {
	var lastErr error
	for attempt := 0; attempt < clashAPIDialAttempts; attempt++ {
		attemptCtx, cancel := context.WithTimeout(ctx, clashAPIClientDialDelay(attempt))
		_, lastErr = c.requestWithContext(attemptCtx, http.MethodGet, "/", nil)
		cancel()
		if lastErr == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(clashAPIClientDialDelay(attempt)):
		}
	}
	return fmt.Errorf("hako: probe Clash API: %w", lastErr)
}

func (c *ClashAPIClient) dialWebSocketWithRetry(ctx context.Context, path string) (*websocket.Conn, error) {
	var lastErr error
	for attempt := 0; attempt < clashAPIDialAttempts; attempt++ {
		dialCtx, cancel := context.WithTimeout(ctx, clashAPIClientDialDelay(attempt))
		conn, response, err := websocket.Dial(dialCtx, "ws://localhost"+path, &websocket.DialOptions{
			HTTPClient: c.httpClient,
			Host:       "localhost",
		})
		cancel()
		if err == nil {
			return conn, nil
		}
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(clashAPIClientDialDelay(attempt)):
		}
	}
	return nil, fmt.Errorf("hako: connect Clash API stream %s: %w", path, lastErr)
}

func clashAPIClientDialDelay(attempt int) time.Duration {
	return 100*time.Millisecond + time.Duration(attempt)*50*time.Millisecond
}

func (s *clashAPIStream) read(session *clashAPISession) {
	defer session.wg.Done()
	defer s.conn.CloseNow()
	for {
		messageType, payload, err := s.conn.Read(session.ctx)
		if err != nil {
			if s.retired.Load() {
				return // replaced on purpose; the session is still healthy
			}
			if session.ctx.Err() == nil {
				s.client.finish(session, fmt.Errorf("%s stream: %w", s.path, err))
			}
			return
		}
		if messageType != websocket.MessageText || !json.Valid(payload) {
			s.client.finish(session, fmt.Errorf("%s stream returned invalid JSON text", s.path))
			return
		}
		s.write(string(payload))
	}
}

func (c *ClashAPIClient) finish(session *clashAPISession, cause error) {
	session.closeOnce.Do(func() {
		session.cancel()
		for _, stream := range session.streams {
			stream.conn.CloseNow()
		}
		c.mu.Lock()
		if c.session == session {
			c.session = nil
		}
		c.mu.Unlock()
		message := ""
		if cause != nil {
			message = cause.Error()
		}
		c.handler.Disconnected(message)
	})
}

// Close synchronously cancels every stream. It is idempotent.
func (c *ClashAPIClient) Close() {
	c.mu.Lock()
	session := c.session
	c.mu.Unlock()
	if session == nil {
		return
	}
	c.finish(session, nil)
	session.wg.Wait()
}

func (c *ClashAPIClient) request(method, path string, body any) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), clashAPIRequestTimeout)
	defer cancel()
	return c.requestWithContext(ctx, method, path, body)
}

func (c *ClashAPIClient) requestWithContext(ctx context.Context, method, path string, body any) (string, error) {
	errorEndpoint := clashAPIErrorEndpoint(path)
	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return "", fmt.Errorf("hako: encode Clash API request: %w", err)
		}
		reader = bytes.NewReader(payload)
	}
	request, err := http.NewRequestWithContext(ctx, method, "http://localhost"+path, reader)
	if err != nil {
		return "", fmt.Errorf("hako: build Clash API request %s: %w", errorEndpoint, err)
	}
	request.Host = "localhost"
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}

	response, err := c.httpClient.Do(request)
	if err != nil {
		return "", fmt.Errorf("hako: Clash API %s %s: %w", method, errorEndpoint, err)
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, clashAPIMaxMessageSize+1))
	if err != nil {
		return "", fmt.Errorf("hako: read Clash API %s: %w", errorEndpoint, err)
	}
	if len(payload) > clashAPIMaxMessageSize {
		return "", fmt.Errorf("hako: Clash API %s response exceeds %d bytes", errorEndpoint, clashAPIMaxMessageSize)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", fmt.Errorf("hako: Clash API %s %s: HTTP %d: %s", method, errorEndpoint, response.StatusCode, strings.TrimSpace(string(payload)))
	}
	if len(payload) > 0 && !json.Valid(payload) {
		return "", fmt.Errorf("hako: Clash API %s returned invalid JSON", errorEndpoint)
	}
	return string(payload), nil
}

// clashAPIErrorEndpoint removes user-controlled proxy/group names, connection
// IDs and query strings from errors that may be shown or persisted by the App.
// The real path is still used for the local request; only diagnostics are
// redacted.
func clashAPIErrorEndpoint(rawPath string) string {
	path := rawPath
	if parsed, err := url.Parse(rawPath); err == nil && parsed.Path != "" {
		path = parsed.Path
	} else if before, _, ok := strings.Cut(rawPath, "?"); ok {
		path = before
	}
	segments := strings.Split(strings.Trim(path, "/"), "/")
	if len(segments) < 2 {
		return path
	}
	switch segments[0] {
	case "proxies":
		if len(segments) >= 3 {
			return "/proxies/<redacted>/" + segments[2]
		}
		return "/proxies/<redacted>"
	case "connections":
		return "/connections/<redacted>"
	case "group":
		return "/group/<redacted>"
	case "providers":
		return "/providers/<redacted>"
	default:
		return path
	}
}

func (c *ClashAPIClient) GetConfigs() (string, error) {
	return c.request(http.MethodGet, "/configs", nil)
}

// GetTraffic returns one bounded native traffic snapshot. Streaming clients
// should continue to use CommandStatus instead.
func (c *ClashAPIClient) GetTraffic() (string, error) {
	return c.request(http.MethodGet, "/hako/v1/traffic", nil)
}

// GetMemory returns one bounded native memory snapshot.
func (c *ClashAPIClient) GetMemory() (string, error) {
	return c.request(http.MethodGet, "/hako/v1/memory", nil)
}

// ExplainDNS reports how a name would be resolved: which branch decides it (cache, a
// nameserver-policy, fallback, main, an rcode short-circuit), which policy key caught it,
// and which resolvers are candidates.
//
// It explains rather than resolves. With probe false — the default a screen should use —
// the answer is computed from pure functions and NOTHING is sent, so a reader can ask as
// often as they like. With probe true one exchange runs and the response also carries the
// winner and the answer it produced, from that same exchange: asking twice would race
// twice, and a screen showing an address from one race beside a resolver from another is
// the confusion this exists to remove.
//
// qType is A, AAAA, CNAME or TXT; empty means A. The response is JSON for the client to
// decode, matching the other snapshot getters.
func (c *ClashAPIClient) ExplainDNS(domain string, qType string, probe bool) (string, error) {
	if strings.TrimSpace(domain) == "" {
		return "", errors.New("hako: explain DNS requires a domain")
	}
	query := url.Values{"domain": []string{domain}}
	if trimmed := strings.TrimSpace(qType); trimmed != "" {
		query.Set("type", trimmed)
	}
	if probe {
		query.Set("probe", "1")
	}
	return c.request(http.MethodGet, "/hako/v1/dns/explain?"+query.Encode(), nil)
}

// GetRules returns mihomo's currently active rule catalog.
func (c *ClashAPIClient) GetRules() (string, error) {
	return c.request(http.MethodGet, "/rules", nil)
}

// QueryDNS resolves one name through the running Core resolver. It does not
// bypass the active DNS policy or perform network acquisition in the App.
func (c *ClashAPIClient) QueryDNS(name, qType string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || strings.ContainsAny(name, "\t\r\n /?#") {
		return "", errors.New("hako: DNS query requires a valid name")
	}
	if _, ok := dns.IsDomainName(name); !ok {
		return "", errors.New("hako: DNS query requires a valid name")
	}
	qType = strings.ToUpper(strings.TrimSpace(qType))
	if qType == "" {
		qType = "A"
	}
	if _, ok := dns.StringToType[qType]; !ok {
		return "", errors.New("hako: DNS query requires a valid type")
	}
	query := url.Values{"name": []string{name}, "type": []string{qType}}
	return c.request(http.MethodGet, "/dns/query?"+query.Encode(), nil)
}

// FlushDNSCache invalidates only the running Core DNS cache.
func (c *ClashAPIClient) FlushDNSCache() error {
	_, err := c.request(http.MethodPost, "/cache/dns/flush", nil)
	return err
}

// FlushFakeIPCache invalidates only the running Core fake-IP cache.
func (c *ClashAPIClient) FlushFakeIPCache() error {
	_, err := c.request(http.MethodPost, "/cache/fakeip/flush", nil)
	return err
}

func (c *ClashAPIClient) GetProxies() (string, error) {
	return c.request(http.MethodGet, "/proxies", nil)
}

func (c *ClashAPIClient) GetGroups() (string, error) {
	return c.request(http.MethodGet, "/group", nil)
}

func (c *ClashAPIClient) GetVersion() (string, error) {
	return c.request(http.MethodGet, "/version", nil)
}

func (c *ClashAPIClient) GetConnections() (string, error) {
	return c.request(http.MethodGet, "/connections", nil)
}

func (c *ClashAPIClient) CloseConnection(id string) error {
	if id == "" {
		return errors.New("hako: close connection requires an id")
	}
	_, err := c.request(http.MethodDelete, "/connections/"+url.PathEscape(id), nil)
	return err
}

func (c *ClashAPIClient) CloseConnections() error {
	_, err := c.request(http.MethodDelete, "/connections", nil)
	return err
}

// GetConfigDeviations reports every field this core did not honour as written, with what the
// user wrote, what happens instead, why, and a citation. It is the addressable form of what
// used to exist only as log lines -- seven deviations relied on those and four said nothing.
//
// It answers before Start as an empty list rather than an error, so a client can render it
// unconditionally, and it is republished on every Start and Reload so it always describes the
// configuration that is running.
func (c *ClashAPIClient) GetConfigDeviations() (string, error) {
	return c.request(http.MethodGet, "/hako/v1/deviations", nil)
}

// GetProxyShareStatus reports the controlled LAN listener without returning
// its credentials or a device address.
func (c *ClashAPIClient) GetProxyShareStatus() (string, error) {
	return c.request(http.MethodGet, "/hako/v1/proxy-share", nil)
}

// StartProxyShare opens one authenticated mixed HTTP/SOCKS5 LAN listener in
// the running core. The containing App should keep the credentials in Keychain
// and provide Apple's Local Network usage description before exposing this UI.
func (c *ClashAPIClient) StartProxyShare(port int32, username, password string) error {
	if _, err := newProxyShareConfiguration(port, username, password); err != nil {
		return err
	}
	_, err := c.request(http.MethodPut, "/hako/v1/proxy-share", proxyShareRequest{
		Port:     port,
		Username: username,
		Password: password,
	})
	return err
}

func (c *ClashAPIClient) StopProxyShare() error {
	_, err := c.request(http.MethodDelete, "/hako/v1/proxy-share", nil)
	return err
}

func (c *ClashAPIClient) SetMode(mode string) error {
	normalized := strings.ToLower(mode)
	switch normalized {
	case "rule", "global", "direct":
	default:
		return fmt.Errorf("hako: unknown mode %q", mode)
	}
	_, err := c.request(http.MethodPatch, "/hako/v1/configs/mode", map[string]string{"mode": normalized})
	return err
}

func (c *ClashAPIClient) SelectProxy(group, name string) error {
	if group == "" || name == "" {
		return errors.New("hako: select proxy requires group and name")
	}
	_, err := c.request(
		http.MethodPut,
		"/proxies/"+url.PathEscape(group),
		map[string]string{"name": name},
	)
	return err
}

// UnfixProxy releases a pinned URLTest/Fallback group back to automatic
// selection over the binding-owned socket — the DELETE face of SelectProxy.
// mihomo routes it to ForceSet("") and refuses selectors
// (hub/route/proxies.go).
func (c *ClashAPIClient) UnfixProxy(group string) error {
	if group == "" {
		return errors.New("hako: unfix proxy requires a group")
	}
	_, err := c.request(
		http.MethodDelete,
		"/proxies/"+url.PathEscape(group),
		nil,
	)
	return err
}

// GetProxyProviders returns mihomo's live proxy-provider catalog over the
// binding-owned Unix socket. The response is the native Clash API JSON so the
// App can track upstream fields without a parallel Swift model in the Core.
func (c *ClashAPIClient) GetProxyProviders() (string, error) {
	return c.request(http.MethodGet, "/providers/proxies", nil)
}

// GetProxyProvider returns one live proxy-provider detail document.
func (c *ClashAPIClient) GetProxyProvider(name string) (string, error) {
	if !validProviderSideUpdateName(name) {
		return "", errors.New("hako: proxy provider detail requires a valid name")
	}
	return c.request(http.MethodGet, "/providers/proxies/"+url.PathEscape(name), nil)
}

// HealthCheckProxyProvider asks mihomo to run the configured health check for
// one live proxy provider. Results remain observable through provider detail.
func (c *ClashAPIClient) HealthCheckProxyProvider(name string) error {
	if !validProviderSideUpdateName(name) {
		return errors.New("hako: proxy provider health check requires a valid name")
	}
	_, err := c.request(
		http.MethodGet,
		"/providers/proxies/"+url.PathEscape(name)+"/healthcheck",
		nil,
	)
	return err
}

// GetRuleProviders returns mihomo's live rule-provider catalog. Upstream does
// not expose separate rule-provider detail or health-check routes.
func (c *ClashAPIClient) GetRuleProviders() (string, error) {
	return c.request(http.MethodGet, "/providers/rules", nil)
}

// UpdateProxyProvider asks mihomo to refresh one already-loaded proxy
// provider. On iOS the finalized provider is file-backed, so this only rereads
// its current local path; it never downloads the original remote URL.
func (c *ClashAPIClient) UpdateProxyProvider(name string) error {
	return c.updateProvider("proxies", name)
}

// UpdateRuleProvider asks mihomo to refresh one already-loaded rule provider.
// On iOS the finalized provider is file-backed, so this only rereads its
// current local path; it never downloads the original remote URL.
func (c *ClashAPIClient) UpdateRuleProvider(name string) error {
	return c.updateProvider("rules", name)
}

func (c *ClashAPIClient) updateProvider(kind, name string) error {
	if strings.TrimSpace(name) == "" {
		return errors.New("hako: update provider requires a name")
	}
	_, err := c.request(
		http.MethodPut,
		"/providers/"+kind+"/"+url.PathEscape(name),
		nil,
	)
	if err == nil {
		c.invalidateProviderIndex()
	}
	return err
}

// invalidateProviderIndex forgets the name→provider snapshot now. An update
// changes exactly the fact the index caches; leaving the TTL to run out keeps
// answering from the world before the update for up to a minute — a freshly
// added node keeps 404ing, a removed one measures a ghost.
func (c *ClashAPIClient) invalidateProviderIndex() {
	c.providerIndexMu.Lock()
	c.providerIndex = nil
	c.providerIndexAt = time.Time{}
	c.providerIndexMu.Unlock()
}

// SideUpdateProxyProvider replaces one live file-backed provider from bytes
// over the binding-owned Unix route. The Extension writes only its private
// copy-on-write runtime shadow; the App's published revision remains immutable.
func (c *ClashAPIClient) SideUpdateProxyProvider(name string, payload []byte) error {
	return c.sideUpdateProvider("proxy", name, payload)
}

// SideUpdateRuleProvider is the rule-provider equivalent of
// SideUpdateProxyProvider. Rule behavior and format are taken from the active
// Core configuration rather than trusted from the caller.
func (c *ClashAPIClient) SideUpdateRuleProvider(name string, payload []byte) error {
	return c.sideUpdateProvider("rule", name, payload)
}

func (c *ClashAPIClient) sideUpdateProvider(kind, name string, payload []byte) error {
	if !validProviderSideUpdateName(name) {
		return errors.New("hako: side update requires a valid provider name")
	}
	if len(payload) == 0 || len(payload) > maximumProviderResourceBytes {
		return fmt.Errorf("hako: provider side-update payload size is invalid")
	}
	query := url.Values{"kind": []string{kind}, "name": []string{name}}
	ctx, cancel := context.WithTimeout(context.Background(), clashAPIRequestTimeout)
	defer cancel()
	err := c.requestBinary(ctx, http.MethodPut, "/hako/v1/providers/side-update?"+query.Encode(), payload)
	if err == nil {
		c.invalidateProviderIndex()
	}
	return err
}

func (c *ClashAPIClient) requestBinary(ctx context.Context, method, path string, payload []byte) error {
	errorEndpoint := clashAPIErrorEndpoint(path)
	request, err := http.NewRequestWithContext(ctx, method, "http://localhost"+path, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("hako: build Clash API request %s: %w", errorEndpoint, err)
	}
	request.Host = "localhost"
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/octet-stream")
	response, err := c.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("hako: Clash API %s %s: %w", method, errorEndpoint, err)
	}
	defer response.Body.Close()
	responsePayload, err := io.ReadAll(io.LimitReader(response.Body, clashAPIMaxMessageSize+1))
	if err != nil {
		return fmt.Errorf("hako: read Clash API %s: %w", errorEndpoint, err)
	}
	if len(responsePayload) > clashAPIMaxMessageSize {
		return fmt.Errorf("hako: Clash API %s response exceeds %d bytes", errorEndpoint, clashAPIMaxMessageSize)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("hako: Clash API %s %s: HTTP %d: %s", method, errorEndpoint, response.StatusCode, strings.TrimSpace(string(responsePayload)))
	}
	return nil
}

func (c *ClashAPIClient) URLTest(name, testURL string) (int, error) {
	if name == "" {
		return -1, errors.New("hako: URL test requires a proxy name")
	}
	if testURL == "" {
		testURL = "https://www.gstatic.com/generate_204"
	}
	query := url.Values{
		"url":      []string{testURL},
		"timeout":  []string{"5000"},
		"expected": []string{"200-299"},
	}
	payload, err := c.request(http.MethodGet, "/proxies/"+url.PathEscape(name)+"/delay?"+query.Encode(), nil)
	// A node that lives in a proxy provider is not in the global proxies
	// table: upstream keeps provider nodes under their provider, and the
	// endpoint that measures one is /providers/proxies/{provider}/{name}/
	// healthcheck. Every probe of a subscription node against /proxies came
	// nodes all come from a subscription, which is most readers, could not
	// measure anything.
	if err != nil && isClashAPINotFound(err) {
		if providerName, ok := c.providerOf(name); ok {
			payload, err = c.request(http.MethodGet,
				"/providers/proxies/"+url.PathEscape(providerName)+
					"/"+url.PathEscape(name)+"/healthcheck?"+query.Encode(), nil)
		}
	}
	if err != nil {
		return -1, err
	}
	var response struct {
		Delay int `json:"delay"`
	}
	if err := json.Unmarshal([]byte(payload), &response); err != nil || response.Delay <= 0 {
		return -1, fmt.Errorf("hako: invalid URL test response %q", payload)
	}
	return response.Delay, nil
}

// isClashAPINotFound recognizes the 404 the request helper folds into its
// error string. The helper predates callers that need the status; matching the
// digits it prints is contained here so a second caller never re-derives it.
func isClashAPINotFound(err error) bool {
	return err != nil && strings.Contains(err.Error(), ": HTTP 404:")
}

// providerOf answers which proxy provider carries a node of this name.
//
// The mapping is a snapshot of /providers/proxies, cached briefly: a Test All
// sweeps every node in the profile, and fetching the full provider listing
// once per node would turn one HTTP round trip into two for the whole sweep.
// A refresh after the TTL keeps renamed subscriptions from pinning stale
// answers.
func (c *ClashAPIClient) providerOf(name string) (string, bool) {
	c.providerIndexMu.Lock()
	defer c.providerIndexMu.Unlock()
	if c.providerIndex == nil || time.Since(c.providerIndexAt) > clashAPIProviderIndexTTL {
		payload, err := c.request(http.MethodGet, "/providers/proxies", nil)
		if err != nil {
			return "", false
		}
		var listing struct {
			Providers map[string]struct {
				VehicleType string `json:"vehicleType"`
				Proxies     []struct {
					Name string `json:"name"`
				} `json:"proxies"`
			} `json:"providers"`
		}
		if err := json.Unmarshal([]byte(payload), &listing); err != nil {
			return "", false
		}
		// Two exclusions, both learned from the client code that answered this
		// question first (ProxiesPresentation.isKernelInternal):
		//
		// The listing is not only the reader's subscriptions. Every group has a
		// kernel-made Compatible provider carrying its static members, and the
		// nodes of an include-all group appear under the group's provider too —
		// so without the filter, which provider a node maps to depended on Go's
		// map iteration order, and a health check could land on a group's
		// compatible shell instead of the subscription that owns the node.
		//
		// And two subscriptions may both carry a node of the same name. Guessing
		// between them measures an arbitrary one; recording the collision and
		// declining is the only honest answer, and the probe then reports the
		// original not-found instead of a number that may belong to a different
		// server.
		const ambiguous = "\x00ambiguous"
		index := make(map[string]string)
		for providerName, provider := range listing.Providers {
			if strings.EqualFold(provider.VehicleType, "Compatible") ||
				providerName == "default" {
				continue
			}
			for _, proxy := range provider.Proxies {
				if existing, seen := index[proxy.Name]; seen && existing != providerName {
					index[proxy.Name] = ambiguous
					continue
				}
				index[proxy.Name] = providerName
			}
		}
		for name, providerName := range index {
			if providerName == ambiguous {
				delete(index, name)
			}
		}
		c.providerIndex = index
		c.providerIndexAt = time.Now()
	}
	providerName, ok := c.providerIndex[name]
	return providerName, ok
}
