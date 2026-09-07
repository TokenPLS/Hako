package hako

import (
	"net"
	"sort"
	"strconv"

	C "github.com/TokenPLS/Hako/constant"
	P "github.com/TokenPLS/Hako/constant/provider"
	"github.com/TokenPLS/Hako/tunnel"
)

// dialTarget is one host this configuration will dial, and what a caller needs to decide
// whether it can act on that host.
type dialTarget struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Addr string `json:"addr"`
	Host string `json:"host"`
	Port int    `json:"port"`
	// The subscription this node came from; absent for a node written in `proxies:`.
	Provider string `json:"provider,omitempty"`
	// Non-empty means this node's host is resolved by the node named here, not by this
	// device -- so a local DNS probe against it reads as a false red.
	DialerProxy string `json:"dialerProxy,omitempty"`
}

// DialTargetsJSON names every host this running configuration will dial, and which
// subscription each one came from.
//
// The question behind it is a reader's: their nodes test fine but nothing works, and the
// thing worth checking is whether the device can resolve the hosts those nodes dial. To ask
// that, the caller needs the hosts -- and today it gets them by re-reading the working
// configuration, scanning it for `path:` lines and hand-parsing every provider file it
// finds. That is a second parser, and it has to guess a field per dialect (vmess
// `vnext[].address`, wireguard's peers, the ssr/snell aliases); guessing wrong loses a batch
// of nodes silently, which is the failure mode this surface exists to end.
//
// The answer here cannot disagree with the dialer, because it is what the dialer uses:
// C.ProxyAdapter.Addr() is written at construction from the same option the outbound dials
// (every constructor in adapter/outbound, e.g. wireguard.go NewWireGuard). Nothing is
// re-derived and no dialect is enumerated.
//
// Two things a caller must know:
//
//   - Providers are walked separately. tunnel.Proxies() is built from the `proxies:` section
//     and the groups; a provider's members go to providersMap and are not in it (upstream's
//     own /proxies reads the same table, hub/route/proxies.go getProxies). A reader whose
//     nodes all come from a subscription would otherwise get an empty answer.
//   - Multi-endpoint protocols report their primary endpoint only. A wireguard outbound with
//     several peers, or hysteria2 port hopping, dials more than this row names; Addr() is
//     what the adapter was built with, and this does not invent the rest.
//
// Rows a prober can only skip are left out: groups, DIRECT and REJECT are in the same table
// and have no address of their own, and "no address" is the absence of a target rather than
// a target with an empty one.
//
// Everything else about a node -- udp, alive, the delay history -- is in ProxiesJSON, where
// whoever needs it can go. This row carries only what is needed to decide whether the row
// can be acted on at all, which is why `dialerProxy` is here and the rest is not.
//
// A name can appear twice -- once from `proxies:`, once from a provider with a namesake --
// and `provider` is what tells them apart. The order is sorted, by provider then name,
// because map iteration in Go is randomised and a list that reorders itself between calls
// reads as change to anything that diffs it.
func DialTargetsJSON() string {
	targets := make([]dialTarget, 0, 32)
	add := func(proxy C.Proxy, provider string) {
		address := proxy.Addr()
		if address == "" {
			return
		}
		target := dialTarget{
			Name:        proxy.Name(),
			Type:        proxy.Type().String(),
			Addr:        address,
			Provider:    provider,
			DialerProxy: proxy.ProxyInfo().DialerProxy,
		}
		// A malformed address is still the address this outbound holds, so it is reported
		// verbatim and only the split halves are left unset. Dropping the row would hide the
		// one node whose address is wrong, which is the node most worth seeing.
		if host, port, err := net.SplitHostPort(address); err == nil {
			target.Host = host
			if number, err := strconv.Atoi(port); err == nil {
				target.Port = number
			}
		}
		targets = append(targets, target)
	}

	for _, proxy := range tunnel.Proxies() {
		add(proxy, "")
	}
	for name, provider := range tunnel.Providers() {
		// The compatible provider is not a subscription: it is the synthetic one the config
		// builds over the `proxies:` section, so every node in it was already reported from
		// tunnel.Proxies() above. Walking it too reported each hand-written node twice, the
		// second time attributed to a "provider" the reader never wrote (found by this
		// surface's own test, which asserted a `proxies:` node carries no provider).
		if provider.VehicleType() == P.Compatible {
			continue
		}
		for _, proxy := range provider.Proxies() {
			add(proxy, name)
		}
	}

	sort.SliceStable(targets, func(left, right int) bool {
		if targets[left].Provider != targets[right].Provider {
			return targets[left].Provider < targets[right].Provider
		}
		return targets[left].Name < targets[right].Name
	})
	return bridgeSafeString(mustJSON(map[string]any{"targets": targets}))
}
