package hako

import (
	"sync/atomic"
	"testing"
)

// A path change dropped the DNS upstream connections but kept the DNS answers. An
// unexpired entry therefore survived the move to a new network and was served with no
// re-query at all, so the first thing an application did after switching networks could be
// to connect to an address that only existed on the old one.
//
// Upstream mihomo already pairs the two calls for its own mobile platform --
// dns/patch_android.go's FlushCacheWithDefaultResolver is ClearCache plus ResetConnection --
// but that file is behind an android build tag, so iOS got half of it. On iOS
// resolver.ClearCache was reachable only from the REST endpoint.
//
// Gated identically to the connection reset, and that is not incidental: clearing the cache
// causes a re-query burst, every uncached query on a stateful transport is a handshake, and
// on iOS every handshake is an XPC round trip to trustd. Flushing on an update where the
// interface did not change would pay that burst for answers that were still correct.
//
// Honest about the size: with public DoH/DoT nameservers, which is the normal Hako
// configuration, a split-horizon network never puts RFC1918 addresses into our cache, so the
// usual cost of the old behaviour was geo-suboptimal routing rather than breakage. Breakage
// needs a system, dhcp:// or LAN-pointed policy nameserver.

func TestDNSCacheFlushTracksTheResolverReset(t *testing.T) {
	oldFlush, oldReset, oldClose, oldClear :=
		flushInterfaceCache, resetResolverConnection, closeTrackedConnections, clearResolverCache
	var flushes, resets, closes, clears atomic.Int64
	flushInterfaceCache = func() { flushes.Add(1) }
	resetResolverConnection = func() { resets.Add(1) }
	closeTrackedConnections = func() { closes.Add(1) }
	clearResolverCache = func() { clears.Add(1) }
	t.Cleanup(func() {
		flushInterfaceCache, resetResolverConnection, closeTrackedConnections, clearResolverCache =
			oldFlush, oldReset, oldClose, oldClear
	})

	updater := &interfaceUpdater{}

	// First observed path: nothing established, so everything publishes.
	updater.UpdateDefaultInterface("en0", 4, false, false, true, true)
	if clears.Load() != 1 {
		t.Fatalf("first path did not flush the DNS cache: clears=%d", clears.Load())
	}

	// Identical callback: a no-op.
	updater.UpdateDefaultInterface("en0", 4, false, false, true, true)
	if clears.Load() != 1 {
		t.Fatalf("identical path flushed the DNS cache again: clears=%d", clears.Load())
	}

	// Capability-only change on the same interface. This DOES flush: the forwarded flags
	// cannot distinguish "nothing moved" from "the path was replaced", and a Personal
	// Hotspot switch presents exactly this way -- same interface, same families, only
	// "expensive" moves, while the source address and gateway change. Answers resolved on
	// the old path can be wrong on the new one.
	updater.UpdateDefaultInterface("en0", 4, false, true, true, true)
	if clears.Load() != 2 {
		t.Fatalf("capability-only change did not flush the DNS cache: clears=%d", clears.Load())
	}

	// Address-family transition: answers from the old family may be unreachable.
	updater.UpdateDefaultInterface("en0", 4, false, true, false, true)
	if clears.Load() != 3 {
		t.Fatalf("address-family transition did not flush the DNS cache: clears=%d", clears.Load())
	}

	// Interface switch: a different network entirely.
	updater.UpdateDefaultInterface("pdp_ip0", 10, true, false, true, true)
	if clears.Load() != 4 {
		t.Fatalf("interface switch did not flush the DNS cache: clears=%d", clears.Load())
	}

	// The cache flush and the connection reset must agree on every one of those, because
	// they answer the same question: is state from the previous path still usable.
	if clears.Load() != resets.Load() {
		t.Fatalf("cache flush (%d) and connection reset (%d) disagree; both are invalidating "+
			"state scoped to the old path and must fire together", clears.Load(), resets.Load())
	}
}
