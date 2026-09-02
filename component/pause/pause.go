// Package pause exposes the process-wide device-pause manager.
//
// A proxy core with a live tunnel keeps its health-check tickers running while the device
// sleeps. Each tick URL-tests every proxy in a provider, each test is a TCP connect plus a TLS
// handshake, and on Apple platforms every certificate verification is an XPC round trip to
// trustd. Measured on a real iPhone: 17,568 certificate verifications over 6.7 hours of an
// idle night, about 0.8 per second, with the device asleep the whole time.
//
// sing-box does not do this. Its urltest group registers its ticker with a pause manager
// (protocol/group/urltest.go: pause.RegisterTicker), so the ticker is STOPPED for as long as
// the device reports itself paused and reset on wake. mihomo has the same package available --
// github.com/metacubex/sing/service/pause, byte-identical to sagernet's -- and simply never
// wired it up.
//
// So this is a wiring shim, not a new mechanism. The manager itself is upstream's.
//
// It is inert everywhere except Apple: nothing else in this tree calls DevicePause, so on
// Linux, Windows and Android every ticker behaves exactly as before.
package pause

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/sing/service"
	singpause "github.com/metacubex/sing/service/pause"
)

// Event and Callback are re-exported so callers do not need to import the sing package
// directly alongside this one.
type Callback = singpause.Callback

const (
	EventDevicePaused = singpause.EventDevicePaused
	EventDeviceWake   = singpause.EventDeviceWake
	EventNetworkPause = singpause.EventNetworkPause
	EventNetworkWake  = singpause.EventNetworkWake
)

// manager is process-wide because mihomo has no service container to hang it off, and its
// state is genuinely process-wide: the device is asleep or it is not. Upstream's only
// constructor threads it through a context, so that is how it is built, once.
var manager = service.FromContext[singpause.Manager](
	singpause.WithDefaultManager(context.Background()),
)

// outstanding counts callbacks this process registered and has not released. The manager does
// not expose its list, and a periodic task that forgets to unregister leaks one callback per
// configuration reload for the life of the process -- so the count is the only way to see that
// happening, from a test or from diagnostics.
var outstanding atomic.Int64

// Outstanding reports how many pause callbacks are currently registered. A number that grows
// across configuration reloads is a leak, not load.
func Outstanding() int64 { return outstanding.Load() }

// release wraps an unregister so calling it twice cannot drive the count negative or hand the
// manager a list element it has already removed.
func release(unregister func()) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			unregister()
			outstanding.Add(-1)
		})
	}
}

// DevicePause reports that the device is going to sleep. Callbacks registered through
// RegisterTicker stop their tickers.
func DevicePause() { manager.DevicePause() }

// DeviceWake reports that the device is awake again and resets the stopped tickers.
func DeviceWake() { manager.DeviceWake() }

// IsDevicePaused is for diagnostics and for tests that need to assert the state rather than
// the effect.
func IsDevicePaused() bool { return manager.IsDevicePaused() }

// RegisterTicker stops TICKER while the device is paused and resets it to DURATION on wake,
// and returns the function that unregisters it.
//
// Returning an unregister function rather than the list element is the whole reason this
// wrapper exists: the callback list is process-wide and a periodic task that registers without
// unregistering leaks one callback per configuration reload, forever. Every caller must defer
// the returned function on the same path that stops its ticker.
func RegisterTicker(ticker *time.Ticker, duration time.Duration, resume func()) func() {
	element := singpause.RegisterTicker(manager, ticker, duration, resume)
	outstanding.Add(1)
	return release(func() { manager.UnregisterCallback(element) })
}

// RegisterCallback is for callers that need the raw events rather than ticker behaviour. Same
// contract: the returned function must be called.
func RegisterCallback(callback Callback) func() {
	element := manager.RegisterCallback(callback)
	outstanding.Add(1)
	return release(func() { manager.UnregisterCallback(element) })
}
