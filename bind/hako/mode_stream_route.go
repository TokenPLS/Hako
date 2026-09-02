package hako

import (
	"encoding/json"
	"net"
	"sync"

	"github.com/metacubex/chi"
	"github.com/metacubex/http"
	"github.com/TokenPLS/Hako/adapter/outboundgroup"
	"github.com/TokenPLS/Hako/component/profile/cachefile"
	"github.com/TokenPLS/Hako/config"
	"github.com/TokenPLS/Hako/hub/route"
	"github.com/TokenPLS/Hako/listener"
	"github.com/TokenPLS/Hako/tunnel"
)

// runtimeSwitches is what GET /hako/v1/mode carries. Two fields rather than one because the
// consuming lane measured which of PATCH /configs' eleven writable values it actually displays
// as live state: mode and allow-lan, and nothing else. sniffing and interface-name appear only
// in the configuration editor, where the right answer is what the user wrote, not what is
// running; the remaining seven are not shown at all.
//
// allow-lan earns its place more than mode does: it has three writers -- the app's permission
// gate, hub/executor applying a parsed configuration, and the controller's PATCH -- so a
// snapshot is blind to two of them.
type runtimeSwitches struct {
	Mode     string `json:"mode"`
	AllowLan bool   `json:"allow-lan"`
	// Selected is the current node of every MANUAL group, keyed by group name.
	//
	// Manual only, and the exclusion is the honest part: an automatic group's current node is
	// computed when something asks (Fallback.Now() walks its members right then), so there is no
	// moment at which it "changes" and nothing to push. A consumer that needs those has to ask,
	// which is what the consuming lane's proxies page now does on appearing.
	Selected map[string]string `json:"selected"`
}

func currentRuntimeSwitches() runtimeSwitches {
	return runtimeSwitches{
		Mode:     tunnel.Mode().String(),
		AllowLan: listener.AllowLan(),
		Selected: currentSelections(),
	}
}

// currentSelections reads the live selection off the running proxies rather than off the cache
// file, because the cache is written only when store-selected is on and would go blank under a
// setting that has nothing to do with what is selected.
func currentSelections() map[string]string {
	selections := map[string]string{}
	for name, proxy := range tunnel.Proxies() {
		selector, manual := proxy.Adapter().(*outboundgroup.Selector)
		if !manual {
			continue
		}
		selections[name] = selector.Now()
	}
	return selections
}

// modeSubscribers is the fan-out for GET /hako/v1/mode.
//
// It exists because mode gained a second writer. Until PATCH /configs was opened the containing
// app was the only one, so the app knew the current mode by having set it; a dashboard on
// another device can now change it, and the app's copy became a cache with no invalidation.
//
// The consuming lane closed the two cases a refresh can cover -- returning to the foreground,
// re-entering the home screen -- and deliberately stopped at the third: somebody watching the
// screen while the switch happens elsewhere. That one only yields to polling, and polling a
// value that changes zero times on a typical day pays every day for a benefit measured in
// seconds. So it is answered here instead, on a connection that is already open.
var modeSubscribers = struct {
	sync.Mutex
	next    int
	streams map[int]chan runtimeSwitches
}{streams: map[int]chan runtimeSwitches{}}

func init() {
	installRuntimeSwitchSeams()
	route.Register(func(router chi.Router) {
		router.Get("/hako/v1/mode", serveModeStream)
	})
}

// installRuntimeSwitchSeams hangs the publisher on the three seams. Idempotent, and a named
// function rather than the body of init so a test that had to clear a seam can put it back.
func installRuntimeSwitchSeams() {
	// One observer for the process, installed once. tunnel.SetMode is where both writers
	// converge, which is the reason the seam lives there rather than at the call sites: a hook
	// per path is a hook each new path has to remember, and the one that would be forgotten is
	// the controller's, because no default test drives it.
	// Both seams publish the SAME snapshot rather than their own field, so a subscriber never
	// has to merge two partial messages and can never hold a half-updated pair.
	tunnel.SetModeObserver(func(tunnel.TunnelMode) { publishRuntimeSwitches() })
	listener.SetAllowLanObserver(func(bool) { publishRuntimeSwitches() })
	cachefile.SetSelectedObserver(func(string, string) { publishRuntimeSwitches() })
}

// parseWindow is the mute window: while a config.ParseRawConfig this binding started is running,
// the publisher stays quiet.
//
// It exists because the parser applies the candidate's general section to the live core for
// the duration of the parse and rolls it back before returning -- geodata loading reads the
// live settings, so upstream sets them first (config/config.go, ParseRawConfig:
// `rollback := temporaryUpdateGeneral(config.General); defer rollback()`, executed by
// hub/executor's temporaryUpdateGeneral through the same updateGeneral the real apply uses).
// Both steps reach tunnel.SetMode, so one reload used to put new, old, new on the stream, and a
// CheckConfig -- which parses and never applies -- put the candidate's mode and then the live one.
// Upstream's own comment on that mechanism calls it "very disgusting"; it is an implementation
// detail of parsing and nothing a subscriber should ever be told about.
//
// It is a window rather than a per-call flag because only the executor knows which SetMode calls
// are the parser's, and this binding is the only thing that parses on this core: in embed mode
// the controller does not register PUT /configs (hub/route/configs.go, configRouter), so every
// ParseRawConfig on the product goes through parseRawConfigQuietly below.
//
// The window mutes everything, and the parser's own writes are all it should be muting. A write
// by somebody else that lands inside it -- the controller's PATCH, the App's own switch arriving
// while a provider refresh is parsing -- must not vanish: upstream's rollback may undo it, the
// parse may fail so no apply follows to publish, or it may land after the rollback and simply be
// live; in each of those a subscriber holding an optimistic copy is only put right by hearing the
// live value once. So the window counts what it mutes, and the last parse out compares that with
// what the parsers themselves wrote; if there was more, it publishes the live snapshot once.
// Idempotent for the consumer -- a value it already holds changes nothing -- and the plain reload
// still publishes exactly once, from the apply.
//
// One lock, not counters: "is the window open" and "count this muted write" have to be one step.
// Read as two separate atomics, a foreign write could see the window open, be preempted, and count
// itself after the last parse out had already reckoned up and reset -- stranded until the next
// unrelated event, which is exactly the silence this bookkeeping exists to end. Adversarial review
// found that interleaving; the lock makes it impossible rather than unlikely.
var parseWindow struct {
	sync.Mutex
	inFlight int // parses running right now
	parses   int // parses that opened or joined the current window
	muted    int // notifications swallowed since the window opened
}

// parserModeWritesPerParse is how many times one config.ParseRawConfig writes the mode on its
// own: the temporary apply and its rollback. It is the number that lets the closing window tell
// the parser's writes from anybody else's, and it is upstream's number, not ours --
// TestOneParseWritesTheModeExactlyTwice is the positive control that says it still holds.
const parserModeWritesPerParse = 2

// parseRawConfigQuietly is config.ParseRawConfig inside the window. Every parse this binding
// performs must come through here, or the parser's temporary apply leaks onto the stream again;
// TestEveryParseInThisPackageGoesThroughTheQuietOne reads the source to hold that line, and
// TestReloadPublishesTheModeOnceAndOnlyAfterItIsReallyApplied /
// TestCheckConfigPublishesNothingOnTheModeStream hold the behaviour.
func parseRawConfigQuietly(raw *config.RawConfig) (*config.Config, error) {
	return insideParseWindow(func() (*config.Config, error) { return config.ParseRawConfig(raw) })
}

// insideParseWindow runs one parse inside the window and does the bookkeeping around it. It is
// the seam the concurrency test drives with a stand-in for the parser, so that the bookkeeping
// can be hammered without touching upstream's mode variable from two goroutines.
func insideParseWindow(parse func() (*config.Config, error)) (*config.Config, error) {
	parseWindow.Lock()
	parseWindow.inFlight++
	parseWindow.parses++
	parseWindow.Unlock()
	defer func() {
		parseWindow.Lock()
		parseWindow.inFlight--
		republish := false
		if parseWindow.inFlight == 0 {
			republish = parseWindow.muted > parseWindow.parses*parserModeWritesPerParse
			parseWindow.parses, parseWindow.muted = 0, 0
		}
		parseWindow.Unlock()
		if republish {
			publishRuntimeSwitches()
		}
	}()
	return parse()
}

func publishRuntimeSwitches() {
	parseWindow.Lock()
	if parseWindow.inFlight > 0 {
		parseWindow.muted++
		parseWindow.Unlock()
		return
	}
	parseWindow.Unlock()
	// Read the live values rather than trusting the argument: the observer fires from inside
	// the setter, so by the time this runs the package variable is already the new one, and
	// reading both together is what keeps the pair consistent.
	switches := currentRuntimeSwitches()
	modeSubscribers.Lock()
	defer modeSubscribers.Unlock()
	for _, stream := range modeSubscribers.streams {
		// Non-blocking on purpose. A subscriber that is not reading must not be able to stall
		// tunnel.SetMode, which runs on whichever goroutine changed the mode -- including an
		// HTTP handler. The buffer holds the latest value; a slow reader loses intermediate
		// switches and still ends up correct, which is the right trade for a value whose only
		// consumer wants to know what it is now.
		select {
		case stream <- switches:
		default:
			select {
			case <-stream:
			default:
			}
			select {
			case stream <- switches:
			default:
			}
		}
	}
}

// serveModeStream writes the current mode, then every change, as one JSON object per line.
//
// The current mode goes first and that is not a convenience: a subscriber attaching after a
// switch would otherwise keep believing whatever it last knew until the next change, which is
// the same staleness this endpoint exists to end, one layer down. It would also only appear in
// the situation nobody can reproduce on demand.
func serveModeStream(writer http.ResponseWriter, request *http.Request) {
	// WebSocket when asked for, chunked JSON otherwise -- the same two shapes mihomo's own
	// /traffic and /logs offer, and the WebSocket half is not optional: ClashAPIClient reaches
	// every stream through websocket.Dial (clash_api_client.go:397), so a chunked-only endpoint
	// is one the containing app structurally cannot subscribe to. Serving a route nobody can
	// consume is the same half-a-surface this batch has now produced five times.
	if request.Header.Get("Upgrade") == "websocket" {
		connection, err := route.UpgradeWebSocket(request, writer)
		if err != nil {
			return
		}
		serveModeWebSocket(request, connection)
		return
	}

	flusher, ok := writer.(http.Flusher)
	if !ok {
		http.Error(writer, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	stream, release := subscribeRuntimeSwitches()
	defer release()

	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusOK)

	encoder := json.NewEncoder(writer)
	send := func(switches runtimeSwitches) bool {
		if err := encoder.Encode(switches); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}

	if !send(currentRuntimeSwitches()) {
		return
	}
	for {
		select {
		case switches := <-stream:
			if !send(switches) {
				return
			}
		case <-request.Context().Done():
			return
		}
	}
}

// serveModeWebSocket is the same contract over a socket the app can actually dial: the current
// snapshot first, then one message per change.
func serveModeWebSocket(request *http.Request, connection net.Conn) {
	defer connection.Close()

	stream, release := subscribeRuntimeSwitches()
	defer release()

	send := func(switches runtimeSwitches) bool {
		payload, err := json.Marshal(switches)
		if err != nil {
			return false
		}
		return route.WriteWebSocketText(connection, payload) == nil
	}
	if !send(currentRuntimeSwitches()) {
		return
	}
	for {
		select {
		case switches := <-stream:
			if !send(switches) {
				return
			}
		case <-request.Context().Done():
			return
		}
	}
}

// subscribeRuntimeSwitches registers a subscriber and returns it with its own removal, so the
// two transports cannot drift apart on the bookkeeping.
func subscribeRuntimeSwitches() (<-chan runtimeSwitches, func()) {
	stream := make(chan runtimeSwitches, 1)
	modeSubscribers.Lock()
	id := modeSubscribers.next
	modeSubscribers.next++
	modeSubscribers.streams[id] = stream
	modeSubscribers.Unlock()
	return stream, func() {
		modeSubscribers.Lock()
		delete(modeSubscribers.streams, id)
		modeSubscribers.Unlock()
	}
}
