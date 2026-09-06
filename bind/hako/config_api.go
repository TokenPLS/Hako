package hako

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"

	"github.com/TokenPLS/Hako/config"
	"gopkg.in/yaml.v3"
)

type platformConfigIntent struct {
	IntentSchemaVersion     int    `json:"intentSchemaVersion"`
	TunRestartFingerprint   string `json:"tunRestartFingerprint"`
	StrictRoute             bool   `json:"strictRoute"`
	IncludedRouteCount      int    `json:"includedRouteCount"`
	ExcludedRouteCount      int    `json:"excludedRouteCount"`
	HasLegacyIncludedRoutes bool   `json:"hasLegacyIncludedRoutes"`
	HasLegacyExcludedRoutes bool   `json:"hasLegacyExcludedRoutes"`
}

const platformConfigIntentSchemaVersion = 2

// tunRestartIntent contains only source-controlled fields that survive the
// Network Extension normalizer and affect either Apple's network settings or
// the live tun instance. Fixed Hako fields (stack, MTU, bridge fd, DNS hijack,
// auto-route) are deliberately absent. The hash lets the app compare exact
// intent without persisting private route/address values in the VPN profile.
type tunRestartIntent struct {
	IPv4Address                     string   `json:"ipv4Address"`
	IPv6Enabled                     bool     `json:"ipv6Enabled"`
	IPv6Addresses                   []string `json:"ipv6Addresses"`
	LoopbackAddresses               []string `json:"loopbackAddresses"`
	StrictRoute                     bool     `json:"strictRoute"`
	RouteAddresses                  []string `json:"routeAddresses"`
	RouteExcludeAddresses           []string `json:"routeExcludeAddresses"`
	LegacyIPv4RouteAddresses        []string `json:"legacyIPv4RouteAddresses"`
	LegacyIPv6RouteAddresses        []string `json:"legacyIPv6RouteAddresses"`
	LegacyIPv4RouteExcludeAddresses []string `json:"legacyIPv4RouteExcludeAddresses"`
	LegacyIPv6RouteExcludeAddresses []string `json:"legacyIPv6RouteExcludeAddresses"`
	EndpointIndependentNAT          bool     `json:"endpointIndependentNAT"`
	UDPTimeout                      int64    `json:"udpTimeout"`
	ICMPTimeout                     int64    `json:"icmpTimeout"`
}

// CheckConfig runs the exact typed parse and iOS preflight used by Start,
// without applying the config or starting listeners. Setup must run first so
// relative provider/geodata paths resolve exactly as they will in the NE.
func CheckConfig(configContent string) error {
	setupMu.Lock()
	ready := setupDone
	setupMu.Unlock()
	if !ready {
		return bridgeSafeError(fmt.Errorf("hako: call Setup before CheckConfig"))
	}
	_, err := parseConfigForIOS(configContent, true)
	return bridgeSafeError(err)
}

// ValidateConfigShape answers the only question a source validator asks: would
// mihomo accept the typed shape of this document? Its thirteen callers all
// reach FormatConfig today and discard the document it returns; the second
// yaml.Node parse, the full re-encode, the 4 MiB check on that re-encode, and
// the whole document crossing the bridge back are all spent on nothing.
//
// This is a NEW contract, not FormatConfig-equivalence: the discarded-result
// size limit is dropped on purpose (see the pinned divergence test). And it is
// deliberately not CheckConfig, which requires Setup and runs the full iOS
// preflight -- that one would report "your subscription is broken" for a
// config that is fine but fails a device-local check.
func ValidateConfigShape(configContent string) error {
	if err := validateConfigurationInput(configContent); err != nil {
		return bridgeSafeError(err)
	}
	if _, err := config.UnmarshalRawConfig([]byte(configContent)); err != nil {
		return bridgeSafeError(fmt.Errorf("hako: parse config: %w", err))
	}
	return nil
}

// PlatformConfigIntentJSON extracts the Apple-profile routing intent without
// requiring Setup or starting the core. The client must call this before it
// saves NETunnelProviderProtocol, because enforceRoutes is app-owned and cannot
// be changed from inside the packet-tunnel extension.
func PlatformConfigIntentJSON(configContent string) (*StringBox, error) {
	if err := validateConfigurationInput(configContent); err != nil {
		return nil, bridgeSafeError(err)
	}
	raw, err := config.UnmarshalRawConfig([]byte(configContent))
	if err != nil {
		return nil, bridgeSafeError(fmt.Errorf("hako: parse config: %w", err))
	}
	if err := validateRawNetworkExtensionIntent(raw); err != nil {
		return nil, bridgeSafeError(err)
	}
	tun := raw.Tun
	fingerprint, err := tunRestartFingerprint(raw)
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	intent := platformConfigIntent{
		IntentSchemaVersion:     platformConfigIntentSchemaVersion,
		TunRestartFingerprint:   fingerprint,
		StrictRoute:             tun.StrictRoute,
		IncludedRouteCount:      len(tun.RouteAddress) + len(tun.Inet4RouteAddress) + len(tun.Inet6RouteAddress),
		ExcludedRouteCount:      len(tun.RouteExcludeAddress) + len(tun.Inet4RouteExcludeAddress) + len(tun.Inet6RouteExcludeAddress),
		HasLegacyIncludedRoutes: len(tun.Inet4RouteAddress) > 0 || len(tun.Inet6RouteAddress) > 0,
		HasLegacyExcludedRoutes: len(tun.Inet4RouteExcludeAddress) > 0 || len(tun.Inet6RouteExcludeAddress) > 0,
	}
	data, err := json.Marshal(intent)
	if err != nil {
		return nil, bridgeSafeError(fmt.Errorf("hako: encode platform config intent: %w", err))
	}
	return WrapString(string(data)), nil
}

func tunRestartFingerprint(raw *config.RawConfig) (string, error) {
	// An omitted or explicitly empty (IPv6-only) dns.fake-ip-range is valid:
	// upstream only parses fake-ip-range when non-empty and parseTun falls back to
	// the DefaultRawConfig 198.18.0.1/16 for the tun IPv4, and Hako's own
	// CheckConfig/Start accept it. Mirror that default so the intent hashes a
	// stable IPv4 instead of rejecting the config. A NON-empty value must still be
	// a valid IPv4 prefix: upstream ParseRawConfig rejects a non-empty malformed or
	// IPv6 fake-ip-range, so accepting it here would let the client persist Apple
	// VPN intent for a config CheckConfig/Start later reject.
	var address netip.Prefix
	if raw.DNS.FakeIPRange == "" {
		address = netip.MustParsePrefix("198.18.0.1/16")
	} else {
		parsed, err := netip.ParsePrefix(raw.DNS.FakeIPRange)
		if err != nil || !parsed.Addr().Is4() {
			return "", fmt.Errorf("hako: inspect Apple tun intent: invalid IPv4 dns.fake-ip-range %q", raw.DNS.FakeIPRange)
		}
		address = parsed
	}
	intent := tunRestartIntent{
		IPv4Address:                     netip.PrefixFrom(address.Addr(), 30).String(),
		IPv6Enabled:                     raw.IPv6,
		LoopbackAddresses:               sortedAddresses(raw.Tun.LoopbackAddress),
		StrictRoute:                     raw.Tun.StrictRoute,
		RouteAddresses:                  sortedPrefixes(raw.Tun.RouteAddress),
		RouteExcludeAddresses:           sortedPrefixes(raw.Tun.RouteExcludeAddress),
		LegacyIPv4RouteAddresses:        sortedPrefixes(raw.Tun.Inet4RouteAddress),
		LegacyIPv6RouteAddresses:        sortedPrefixes(raw.Tun.Inet6RouteAddress),
		LegacyIPv4RouteExcludeAddresses: sortedPrefixes(raw.Tun.Inet4RouteExcludeAddress),
		LegacyIPv6RouteExcludeAddresses: sortedPrefixes(raw.Tun.Inet6RouteExcludeAddress),
		EndpointIndependentNAT:          raw.Tun.EndpointIndependentNat,
		UDPTimeout:                      raw.Tun.UDPTimeout,
		ICMPTimeout:                     raw.Tun.ICMPTimeout,
	}
	if raw.IPv6 {
		intent.IPv6Addresses = sortedPrefixes(raw.Tun.Inet6Address)
	}
	data, err := json.Marshal(intent)
	if err != nil {
		return "", fmt.Errorf("hako: encode Apple tun restart intent: %w", err)
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum), nil
}

func sortedPrefixes(prefixes []netip.Prefix) []string {
	result := make([]string, len(prefixes))
	for index, prefix := range prefixes {
		result[index] = prefix.String()
	}
	sort.Strings(result)
	return result
}

func sortedAddresses(addresses []netip.Addr) []string {
	result := make([]string, len(addresses))
	for index, address := range addresses {
		result[index] = address.String()
	}
	sort.Strings(result)
	return result
}

// FormatConfig validates the typed mihomo YAML shape, then formats the source
// YAML node rather than a default-filled RawConfig. This avoids injecting
// hundreds of omitted defaults and preserves source comments where yaml.v3
// can associate them with a node.
func FormatConfig(configContent string) (*StringBox, error) {
	if err := validateConfigurationInput(configContent); err != nil {
		return nil, bridgeSafeError(err)
	}
	if _, err := config.UnmarshalRawConfig([]byte(configContent)); err != nil {
		return nil, bridgeSafeError(fmt.Errorf("hako: parse config: %w", err))
	}

	var document yaml.Node
	if err := yaml.Unmarshal([]byte(configContent), &document); err != nil {
		return nil, bridgeSafeError(fmt.Errorf("hako: parse YAML for formatting: %w", err))
	}
	var buffer bytes.Buffer
	encoder := yaml.NewEncoder(&buffer)
	encoder.SetIndent(2)
	if err := encoder.Encode(&document); err != nil {
		return nil, bridgeSafeError(fmt.Errorf("hako: format config: %w", err))
	}
	if err := encoder.Close(); err != nil {
		return nil, bridgeSafeError(fmt.Errorf("hako: finish config formatting: %w", err))
	}
	if err := validateConfigurationResult(buffer.String()); err != nil {
		return nil, bridgeSafeError(err)
	}
	return WrapString(buffer.String()), nil
}
