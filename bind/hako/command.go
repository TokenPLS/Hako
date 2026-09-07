package hako

import (
	"encoding/json"
	"sync"

	P "github.com/TokenPLS/Hako/constant/provider"
	"github.com/TokenPLS/Hako/tunnel"
	"github.com/TokenPLS/Hako/tunnel/statistic"
)

// command.go is the in-process control-plane surface: the NE
// answers app queries by calling the statistic manager and proxy tables
// directly and returning JSON, WITHOUT starting an HTTP/clash controller.
// gomobile-safe: every getter returns a plain JSON string (no maps, slices,
// or (string, error) across the boundary). The NE routes app requests here
// via handleAppMessage.

// StatusJSON reports lifecycle + routing mode: {"status","mode"}.
func StatusJSON() string {
	return bridgeSafeString(mustJSON(map[string]string{
		"status": tunnel.Status().String(),
		"mode":   tunnel.Mode().String(),
	}))
}

// TrafficJSON reports headline traffic: per-second up/down (bytes/s, computed
// by the manager's 1s ticker so Swift needs no timer) plus cumulative totals
// and the core's RSS estimate.
func TrafficJSON() string {
	up, down := statistic.DefaultManager.Now()
	upTotal, downTotal := statistic.DefaultManager.Total()
	return bridgeSafeString(mustJSON(map[string]int64{
		"up":        up,
		"down":      down,
		"upTotal":   upTotal,
		"downTotal": downTotal,
		"memory":    MemoryFootprint(), // phys_footprint (jetsam metric)
	}))
}

// ConnectionsJSON returns the live connection snapshot (connections + totals +
// memory), matching the clash /connections shape.
func ConnectionsJSON() string {
	return bridgeSafeString(mustJSON(statistic.DefaultManager.Snapshot()))
}

// ProxiesJSON returns every proxy and group keyed by name (clash /proxies
// shape). Groups serialize with their members and current selection via each
// proxy's MarshalJSON.
func ProxiesJSON() string {
	return bridgeSafeString(mustJSON(map[string]any{"proxies": tunnel.Proxies()}))
}

// RuleProvidersJSON reports live rule-provider metadata and loaded cache checksums.
// MD5 checksums test payload consistency, not authenticity. This is an on-demand
// in-process query; it does not require a socket controller or read cache files.
func RuleProvidersJSON() string {
	return bridgeSafeString(mustJSON(ruleProvidersCatalog(tunnel.SnapshotRuleProviders())))
}

func ruleProvidersCatalog(providers map[string]P.RuleProvider) map[string]any {
	rows := make(map[string]any, len(providers))
	for name, provider := range providers {
		if provider == nil {
			continue
		}
		var data []byte
		var err error
		if cached, ok := provider.(interface{ LoadedMetadataJSON() ([]byte, error) }); ok {
			data, err = cached.LoadedMetadataJSON()
		} else {
			data, err = json.Marshal(provider)
		}
		if err != nil {
			continue
		}
		var row map[string]any
		if json.Unmarshal(data, &row) != nil || row == nil {
			continue
		}
		// Inline payloads have no cache file identity.
		if provider.VehicleType() == P.Inline {
			row["loaded"] = true
			delete(row, "payload")
		}
		rows[name] = row
	}
	return map[string]any{"providers": rows}
}

// ringBuffer keeps the last N log lines for the RecentLogsJSON getter
// (diagnostics without device log capture).
type ringBuffer struct {
	mu    sync.Mutex
	lines []string
	max   int
}

const defaultLogMaxLines = 400

func (r *ringBuffer) add(line string) {
	r.mu.Lock()
	r.lines = append(r.lines, line)
	if len(r.lines) > r.max {
		r.lines = r.lines[len(r.lines)-r.max:]
	}
	r.mu.Unlock()
}

func (r *ringBuffer) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.lines))
	copy(out, r.lines)
	return out
}

func (r *ringBuffer) setMax(max int) {
	if max <= 0 {
		max = defaultLogMaxLines
	}
	r.mu.Lock()
	r.max = max
	if len(r.lines) > max {
		r.lines = append([]string(nil), r.lines[len(r.lines)-max:]...)
	}
	r.mu.Unlock()
}

var recentLogs = &ringBuffer{max: defaultLogMaxLines}

// RecentLogsJSON returns the last ~400 core log lines as a JSON array, newest
// last. For in-app diagnostics.
func RecentLogsJSON() string {
	return bridgeSafeString(mustJSON(recentLogs.snapshot()))
}

// mustJSON marshals v, returning a JSON error object rather than failing the
// boundary call (the getters never return an error type per gomobile rules).
func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		eb, _ := json.Marshal(map[string]string{"error": err.Error()})
		return string(eb)
	}
	return string(b)
}
