package hako

import (
	"github.com/TokenPLS/Hako/adapter/outboundgroup"
	C "github.com/TokenPLS/Hako/constant"
	"github.com/TokenPLS/Hako/tunnel"
	"github.com/TokenPLS/Hako/tunnel/statistic"
)

// WidgetStatsJSON is the one call a home-screen widget makes when it reloads: the
// tunnel mode, the session's byte totals split by the outbound the bytes finally left
// through (proxy / direct / reject), the connection counts, and the name of the node
// traffic is leaving through right now. Everything is since this process started -- a
// reload keeps counting, a restart starts over -- and nothing here is a rate: rates
// need two samples and a widget takes one.
//
// group names the proxy group whose selection the egress line follows, in rule mode;
// the widget owns the configuration and knows which group comes first. In global mode
// the GLOBAL group is followed instead and group is ignored. An empty group, or a name
// the running core does not have, leaves the egress key out rather than guessing.
func WidgetStatsJSON(group string) string {
	manager := statistic.DefaultManager
	totals := manager.OutboundTotals()
	upTotal, downTotal := manager.Total()
	stats := map[string]any{
		"mode":      tunnel.Mode().String(),
		"upTotal":   upTotal,
		"downTotal": downTotal,
		"byOutbound": map[string]any{
			"proxy":  map[string]int64{"up": totals.Proxy.Up, "down": totals.Proxy.Down},
			"direct": map[string]int64{"up": totals.Direct.Up, "down": totals.Direct.Down},
			"reject": map[string]int64{"up": totals.Reject.Up, "down": totals.Reject.Down, "count": totals.Rejected},
		},
		"connections": map[string]int64{
			"opened":   totals.Opened,
			"active":   totals.Active,
			"rejected": totals.Rejected,
		},
	}
	if egress := widgetEgress(group); egress != "" {
		stats["egress"] = egress
	}
	return bridgeSafeString(mustJSON(stats))
}

// WidgetGroupJSON is the small slice of a group a widget draws: its name, type, current
// selection and the first limit member names in the group's own order. limit <= 0 means
// every member. A name that is not a group of the running core answers an empty
// object, so the widget can tell "not a group" from "a group with no members".
func WidgetGroupJSON(group string, limit int) string {
	proxy, ok := tunnel.Proxies()[group]
	if !ok {
		return bridgeSafeString("{}")
	}
	members, ok := proxy.Adapter().(outboundgroup.ProxyGroup)
	if !ok {
		return bridgeSafeString("{}")
	}
	all := members.Proxies()
	names := make([]string, 0, len(all))
	for _, member := range all {
		if limit > 0 && len(names) == limit {
			break
		}
		names = append(names, member.Name())
	}
	return bridgeSafeString(mustJSON(map[string]any{
		"name": proxy.Name(),
		"type": proxy.Type().String(),
		"now":  members.Now(),
		"all":  names,
	}))
}

// widgetEgress follows a group's selection down to the node traffic leaves through.
// A selection that names something the proxy map does not hold is a node from a
// provider, which is exactly a leaf; the walk is capped so a cycle of selectors cannot
// spin it.
func widgetEgress(group string) string {
	if tunnel.Mode() == tunnel.Global {
		group = "GLOBAL"
	}
	if group == "" {
		return ""
	}
	proxies := tunnel.Proxies()
	name := group
	for depth := 0; depth < 32; depth++ {
		proxy, ok := proxies[name]
		if !ok {
			if depth == 0 {
				return ""
			}
			return name
		}
		members, isGroup := proxy.Adapter().(outboundgroup.ProxyGroup)
		if !isGroup {
			return proxy.Name()
		}
		now := members.Now()
		if now == "" || now == name {
			return proxy.Name()
		}
		name = now
	}
	return name
}

var _ = C.Selector // the group type strings come from the constant package
