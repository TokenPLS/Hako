package hako

import (
	"encoding/json"
	"net"
	"sync"

	"github.com/metacubex/chi"
	"github.com/metacubex/http"
	"github.com/TokenPLS/Hako/adapter/outboundgroup"
	"github.com/TokenPLS/Hako/component/profile/cachefile"
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
	// One observer for the process, installed once. tunnel.SetMode is where both writers
	// converge, which is the reason the seam lives there rather than at the call sites: a hook
	// per path is a hook each new path has to remember, and the one that would be forgotten is
	// the controller's, because no default test drives it.
	// Both seams publish the SAME snapshot rather than their own field, so a subscriber never
	// has to merge two partial messages and can never hold a half-updated pair.
	tunnel.SetModeObserver(func(tunnel.TunnelMode) { publishRuntimeSwitches() })
	listener.SetAllowLanObserver(func(bool) { publishRuntimeSwitches() })
	cachefile.SetSelectedObserver(func(string, string) { publishRuntimeSwitches() })
	route.Register(func(router chi.Router) {
		router.Get("/hako/v1/mode", serveModeStream)
	})
}

func publishRuntimeSwitches() {
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
