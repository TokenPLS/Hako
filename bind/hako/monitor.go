package hako

import (
	"sync"

	"github.com/TokenPLS/Hako/component/dialer"
	"github.com/TokenPLS/Hako/component/iface"
	"github.com/TokenPLS/Hako/component/resolver"
	"github.com/TokenPLS/Hako/log"
)

// interfaceUpdater is the Go end of the NWPathMonitor callback.
// Swift's monitor calls UpdateDefaultInterface on every default-route
// change; we push the new interface name into the dialer and drop stale
// caches so subsequent dials and DNS use the current physical egress.
// Since mihomo's own sing-tun monitor is disabled,
// this is the sole source of default-interface truth on iOS.
type interfaceUpdater struct {
	mu                   sync.Mutex
	bindDefaultInterface bool
	initialized          bool
	name                 string
	index                int32
	isExpensive          bool
	isConstrained        bool
	supportsIPv4         bool
	supportsIPv6         bool
	received             uint64
	applied              uint64
	identityChanges      uint64
	connectionResets     uint64
}

type interfaceUpdateSnapshot struct {
	received         uint64
	applied          uint64
	identityChanges  uint64
	connectionResets uint64
}

var (
	flushInterfaceCache     = iface.FlushCache
	resetResolverConnection = resolver.ResetConnection
	clearResolverCache      = resolver.ClearCache
	closeTrackedConnections = CloseAllConnections
)

func (u *interfaceUpdater) UpdateDefaultInterface(name string, index int32, isExpensive bool, isConstrained bool, supportsIPv4 bool, supportsIPv6 bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.received++
	wasInitialized := u.initialized
	identityChanged := u.name != name || u.index != index
	addressFamiliesChanged := u.supportsIPv4 != supportsIPv4 || u.supportsIPv6 != supportsIPv6
	changed := !u.initialized || u.name != name || u.index != index ||
		u.isExpensive != isExpensive || u.isConstrained != isConstrained || addressFamiliesChanged
	if !changed {
		return
	}
	u.applied++
	u.initialized = true
	u.name = name
	u.index = index
	u.isExpensive = isExpensive
	u.isConstrained = isConstrained
	u.supportsIPv4 = supportsIPv4
	u.supportsIPv6 = supportsIPv6
	setPhysicalNetworkCapabilities(supportsIPv4, supportsIPv6)

	// iOS explicitly binds every outbound to the path published by Swift.
	// macOS Packet Tunnel providers already receive NECP's default exclusion
	// from their own tunnel, so they consume the same invalidation callback
	// without pinning new sockets to one physical interface.
	if u.bindDefaultInterface {
		dialer.DefaultInterface.Store(name)
	}
	// Existing TCP/UDP flows are scoped to the old physical path. Closing them
	// only on an identity/index change lets applications reconnect through the
	// new interface without needlessly disrupting Low Data Mode changes.
	if wasInitialized && (identityChanged || addressFamiliesChanged) {
		if identityChanged {
			u.identityChanges++
		}
		u.connectionResets++
		closeTrackedConnections()
	}
	// Cached per-interface addresses are cheap to rebuild and can be wrong after any
	// applied update, so they are always flushed.
	flushInterfaceCache()
	// Upstream DNS connections are not cheap to rebuild: every stateful transport
	// re-dials and re-handshakes, and on iOS each handshake is an XPC round trip to
	// trustd. Reset only when the old sockets really are bound to a path that is gone --
	// the same condition the connection teardown above uses. An expensive/constrained
	// flag flipping, or a capability change on the same interface, leaves working sockets
	// that would be discarded for nothing.
	if shouldResetResolverForPathUpdate(wasInitialized, identityChanged, addressFamiliesChanged) {
		// Answers and connections are invalidated together: both are state scoped to the
		// path that just went away. Dropping the connections while keeping the answers left
		// an unexpired entry to be served with no re-query, so the first thing an
		// application did on the new network could be to connect to an address that only
		// existed on the old one. Upstream mihomo already pairs these two for its own
		// mobile platform in dns/patch_android.go, which is not compiled on iOS.
		clearResolverCache()
		resetResolverConnection()
	}
	log.Infoln("[Apple] default path -> %s (index=%d expensive=%v constrained=%v ipv4=%v ipv6=%v)",
		name, index, isExpensive, isConstrained, supportsIPv4, supportsIPv6)
}

func (u *interfaceUpdater) snapshot() interfaceUpdateSnapshot {
	u.mu.Lock()
	defer u.mu.Unlock()
	return interfaceUpdateSnapshot{
		received:         u.received,
		applied:          u.applied,
		identityChanges:  u.identityChanges,
		connectionResets: u.connectionResets,
	}
}

// startInterfaceMonitor asks the platform to start NWPathMonitor and push
// updates into interfaceUpdater. iOS couples monitoring to its explicit
// socket binding. macOS Packet Tunnel keeps monitoring for cache/connection
// invalidation while relying on Apple's provider-originated NECP routing.
func startInterfaceMonitor(platform PlatformInterface) (InterfaceUpdateListener, error) {
	if platform == nil {
		return nil, nil
	}
	bindDefaultInterface := platform.UsePlatformAutoDetectInterfaceControl()
	monitorWithoutBinding := currentRuntimeProfile() == runtimeProfileMacOSPacketTunnel
	if !bindDefaultInterface && !monitorWithoutBinding {
		return nil, nil
	}
	listener := &interfaceUpdater{bindDefaultInterface: bindDefaultInterface}
	if err := platform.StartDefaultInterfaceMonitor(listener); err != nil {
		// A platform monitor may fail after allocating native resources. Its
		// Close operation is required to be idempotent, so unwind it here before
		// refusing to start the core.
		_ = platform.CloseDefaultInterfaceMonitor(listener)
		return nil, err
	}
	return listener, nil
}

// shouldResetResolverForPathUpdate decides whether an applied path update invalidates the
// resolver's upstream connections. It answers yes for every applied update.
//
// It was briefly gated on identity-or-address-family change, to match the connection
// teardown above and to avoid paying a re-dial -- and a trustd round trip per stateful
// transport on iOS -- for an update where nothing meaningful moved. Adversarial review
// showed that trade is wrong, because the flags this process is given are not enough to
// tell "nothing moved" from "the path was replaced".
//
// The counterexample is ordinary: moving from Wi-Fi to a Personal Hotspot keeps the same
// interface name and index and can keep both address families, so neither gate condition
// fires -- while the source address and gateway change and the old socket is bound to a
// path that is gone. DHCP address replacement and same-interface Wi-Fi roaming have the
// same shape. The consequence is not a slower query but a failed one: a cached DoT
// connection is allowed five seconds before retrying, and the DNS request carries the same
// five-second deadline, so on a black-holed old path the deadline expires before the retry
// can connect.
//
// A failed DNS request is worse than a redundant handshake, so the reset stays
// unconditional. The handshake cost is real and stays worth removing -- but the way to
// remove it is the certificate-pool fix, which makes each verification in-process, not
// skipping resets that turn out to be necessary.
//
// The connection teardown above remains gated, and that asymmetry is deliberate: TCP flows
// through the tunnel survive a path change and recover on their own, while a DNS socket
// pinned to a dead source address does not.
func shouldResetResolverForPathUpdate(wasInitialized, identityChanged, addressFamiliesChanged bool) bool {
	return true
}
