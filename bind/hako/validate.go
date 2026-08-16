package hako

import (
	"fmt"
	"math"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/TokenPLS/Hako/common/utils"
	"github.com/TokenPLS/Hako/config"
	P "github.com/TokenPLS/Hako/constant/provider"
	"github.com/TokenPLS/Hako/dns"
	T "github.com/TokenPLS/Hako/transport/tuic"
	TC "github.com/TokenPLS/Hako/transport/tuic/congestion"
	XH "github.com/TokenPLS/Hako/transport/xhttp"
	"github.com/metacubex/quic-go/quicvarint"
)

var unavailableMetadataRuleToken = regexp.MustCompile(`(?i)(?:^|\()\s*(PROCESS-(?:NAME|PATH)(?:-REGEX|-WILDCARD)?|UID|IN-USER|SOURCE-APP-(?:SIGNING-ID|TEAM-ID))\s*,`)
var hysteriaRateToken = regexp.MustCompile(`^(\d+)\s*([KMGT]?)([Bb])ps$`)

const minimumSafeHysteria2UDPMTU = 272

// validateRawNetworkExtensionIntent rejects only the intent that iOS can neither
// consume NOR safely strip. One case remains:
//
//   - a wireguard/openvpn/masque outbound with remote-dns-resolve and an
//     embedded dns server that resolves through a named proxy
//     (firstOutboundEmbeddedDNSFragment). Silently stripping it would change the
//     outbound's DNS-leak posture, so it is rejected rather than tolerated; the
//     client must remove or rewrite it before activation.
//
// Every OTHER host-route knob iOS cannot execute — top-level interface-name /
// routing-mark / find-process-mode, every tun UID/package/MAC/port/interface
// filter and auto-redirect/iproute2 mark, per-proxy interface-name / routing-mark
// egress overrides, and PROCESS/UID/IN-USER rules — is NOT rejected here.
// normalizeRawNetworkExtensionSurfaces and stripOutboundEgressOverrides strip
// them (tolerate + strip) and warn, so any upstream mihomo config still starts on
// iOS. This is the "every upstream config must start; unsupported settings are tolerated and stripped" contract.
func validateRawNetworkExtensionIntent(raw *config.RawConfig) error {
	return validateRawNetworkExtensionIntentForApple(raw, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true))
}

func validateRawNetworkExtensionIntentForApple(raw *config.RawConfig, policy appleRuntimePolicy) error {
	// tun.route-address-set / route-exclude-address-set used to be rejected here, on the
	// ground that they decide which traffic enters the tunnel. They do not. In sing-tun the
	// value reaches only redirect_linux.go and the two nftables files, always through
	// autoRedirect, which is Linux-only -- upstream's documentation says "Linux only, and
	// requires nftables". mihomo on darwin parses the field and ignores it, so rejecting it
	// was stricter than upstream without being required by the platform, which calls a
	// defect. It is now accepted, inert, and reported through the deviation list.
	unsupported := make([]string, 0, 1)
	if field := firstOutboundEmbeddedDNSFragment(raw); field != "" {
		unsupported = append(unsupported, field)
	}
	if len(unsupported) > 0 {
		return fmt.Errorf(
			"hako: Apple %s cannot consume %s; remove or materialize it client-side before activation",
			policy.profile.String(),
			strings.Join(unsupported, ", "),
		)
	}
	return nil
}

// forEachOutboundMapping calls fn for every outbound configuration map in raw —
// proxies, proxy-groups, and each proxy-provider's override plus inline payload
// items — with a human-readable location prefix. It is the single traversal the
// egress-override strip, the embedded-DNS-fragment reject and the plan notices
// all share.
func forEachOutboundMapping(raw *config.RawConfig, fn func(location string, mapping map[string]any)) {
	for index, outbound := range raw.Proxy {
		fn(fmt.Sprintf("proxies[%d]", index), outbound)
	}
	for index, group := range raw.ProxyGroup {
		fn(fmt.Sprintf("proxy-groups[%d]", index), group)
	}
	providerNames := make([]string, 0, len(raw.ProxyProvider))
	for name := range raw.ProxyProvider {
		providerNames = append(providerNames, name)
	}
	sort.Strings(providerNames)
	for _, name := range providerNames {
		provider := raw.ProxyProvider[name]
		if override, ok := provider["override"].(map[string]any); ok {
			fn(fmt.Sprintf("proxy-providers.%s.override", name), override)
		}
		for index, outbound := range providerPayloadMappings(provider["payload"]) {
			fn(fmt.Sprintf("proxy-providers.%s.payload[%d]", name, index), outbound)
		}
	}
}

// firstOutboundEmbeddedDNSFragment returns the first outbound that pins an L3
// nested DNS to a proxy fragment (wireguard/openvpn/masque remote-dns-resolve).
// Unlike a per-proxy interface-name/routing-mark override — which is stripped
// (tolerate + strip) — a bare DNS fragment would be silently ignored and change
// resolution, so it stays a hard reject until it can be materialized app-side.
func firstOutboundEmbeddedDNSFragment(raw *config.RawConfig) string {
	found := ""
	forEachOutboundMapping(raw, func(location string, mapping map[string]any) {
		if found == "" && outboundEmbeddedDNSHasFragment(mapping) {
			found = location + ".dns"
		}
	})
	return found
}

// outboundEgressOverrideLocations lists every per-proxy interface-name /
// routing-mark egress override in raw. stripOutboundEgressOverrides removes them
// (tolerate + strip); the plan reports the same locations as notices.
func outboundEgressOverrideLocations(raw *config.RawConfig) []string {
	locations := []string{}
	forEachOutboundMapping(raw, func(location string, mapping map[string]any) {
		for _, field := range outboundEgressOverrideFields(mapping) {
			locations = append(locations, location+"."+field)
		}
	})
	return locations
}

func firstUnsafeOutboundRuntimeOption(raw *config.RawConfig) (string, string) {
	for index, outbound := range raw.Proxy {
		if field, reason := unsafeOutboundRuntimeOption(outbound); field != "" {
			return fmt.Sprintf("proxies[%d].%s", index, field), reason
		}
	}
	providerNames := make([]string, 0, len(raw.ProxyProvider))
	for name := range raw.ProxyProvider {
		providerNames = append(providerNames, name)
	}
	sort.Strings(providerNames)
	for _, name := range providerNames {
		for index, outbound := range providerPayloadMappings(raw.ProxyProvider[name]["payload"]) {
			if field, reason := unsafeOutboundRuntimeOption(outbound); field != "" {
				return fmt.Sprintf("proxy-providers.%s.payload[%d].%s", name, index, field), reason
			}
		}
	}
	return "", ""
}

func unsafeOutboundRuntimeOption(mapping map[string]any) (string, string) {
	typeName, _ := mapping["type"].(string)
	normalizedType := strings.ToLower(typeName)
	network, _ := outboundScalarString(mapping["network"])
	if strings.EqualFold(network, "grpc") && (normalizedType == "vmess" || normalizedType == "trojan" || normalizedType == "vless") {
		if grpcOptions, ok := mapping["grpc-opts"].(map[string]any); ok {
			if _, err := providerNonPositiveDurationAllowedUnits(grpcOptions["ping-interval"], time.Second, "gRPC ping interval", "second"); err != nil {
				return "grpc-opts.ping-interval", err.Error()
			}
		}
	}
	if normalizedType == "vless" && strings.EqualFold(network, "xhttp") {
		if xhttpOptions, ok := mapping["xhttp-opts"].(map[string]any); ok {
			if field, reason := unsafeXHTTPGeneratedBuffer(xhttpOptions); field != "" {
				return "xhttp-opts." + field, reason
			}
			if xhttpUsesPacketUp(mapping, xhttpOptions) {
				if err := validateXHTTPPacketUpSchedule(xhttpOptions["sc-min-posts-interval-ms"]); err != nil {
					return "xhttp-opts.sc-min-posts-interval-ms", err.Error()
				}
			}
			uploadReuseEnabled := false
			if reuseSettings, ok := xhttpOptions["reuse-settings"].(map[string]any); ok {
				uploadReuseEnabled = true
				if field, reason := unsafeXHTTPReuseSettings(reuseSettings); field != "" {
					return "xhttp-opts.reuse-settings." + field, reason
				}
				if _, err := providerNonPositiveDurationAllowedUnits(reuseSettings["h-keep-alive-period"], time.Second, "XHTTP keepalive period", "second"); err != nil {
					return "xhttp-opts.reuse-settings.h-keep-alive-period", err.Error()
				}
			}
			if downloadSettings, ok := xhttpOptions["download-settings"].(map[string]any); ok {
				if reuseSettings, ok := downloadSettings["reuse-settings"].(map[string]any); ok {
					if uploadReuseEnabled {
						if field, reason := unsafeXHTTPReuseSettings(reuseSettings); field != "" {
							return "xhttp-opts.download-settings.reuse-settings." + field, reason
						}
					}
					if _, err := providerNonPositiveDurationAllowedUnits(reuseSettings["h-keep-alive-period"], time.Second, "XHTTP download keepalive period", "second"); err != nil {
						return "xhttp-opts.download-settings.reuse-settings.h-keep-alive-period", err.Error()
					}
				}
			}
		}
	}
	if normalizedType == "vmess" && strings.EqualFold(network, "mekya") {
		if mekyaOptions, ok := mapping["mekya-opts"].(map[string]any); ok {
			if _, err := providerNonPositiveDurationAllowedUnits(mekyaOptions["polling-interval-initial"], time.Millisecond, "Mekya polling interval", "millisecond"); err != nil {
				return "mekya-opts.polling-interval-initial", err.Error()
			}
			if _, err := providerNonPositiveDurationAllowedUnits(mekyaOptions["max-write-delay"], time.Millisecond, "Mekya write delay", "millisecond"); err != nil {
				return "mekya-opts.max-write-delay", err.Error()
			}
		}
	}
	if normalizedType == "hysteria" || normalizedType == "tuic" {
		for _, field := range []string{"recv-window-conn", "recv-window"} {
			if err := validateQUICFlowControlWindow(mapping[field], normalizedType+" "+field); err != nil {
				return field, err.Error()
			}
		}
	}
	if normalizedType == "hysteria" {
		for _, field := range []string{"up-speed", "down-speed"} {
			if err := validateHysteriaCompatibleSpeed(mapping[field], "Hysteria "+field); err != nil {
				return field, err.Error()
			}
		}
		for _, field := range []string{"up", "down"} {
			if err := validateHysteriaRate(mapping[field], "Hysteria "+field); err != nil {
				return field, err.Error()
			}
		}
	}
	if normalizedType == "hysteria2" {
		if err := validateHysteria2UDPMTU(mapping["udp-mtu"]); err != nil {
			return "udp-mtu", err.Error()
		}
		for _, field := range []string{"up", "down"} {
			if err := validateHysteriaRate(mapping[field], "Hysteria2 "+field); err != nil {
				return field, err.Error()
			}
		}
		for _, field := range []string{
			"initial-stream-receive-window",
			"max-stream-receive-window",
			"initial-connection-receive-window",
			"max-connection-receive-window",
		} {
			if err := validateQUICFlowControlWindow(mapping[field], "Hysteria2 "+field); err != nil {
				return field, err.Error()
			}
		}
	}
	if smux, ok := mapping["smux"].(map[string]any); ok {
		smuxEnabled, _ := smux["enabled"].(bool)
		brutal, hasBrutal := smux["brutal-opts"].(map[string]any)
		brutalEnabled, _ := brutal["enabled"].(bool)
		if smuxEnabled && hasBrutal && brutalEnabled {
			for _, field := range []string{"up", "down"} {
				if err := validateHysteriaRate(brutal[field], "sing-mux Brutal "+field); err != nil {
					return "smux.brutal-opts." + field, err.Error()
				}
			}
		}
	}
	if err := validateActiveBBRCongestionWindow(mapping, normalizedType); err != nil {
		return "cwnd", err.Error()
	}
	switch normalizedType {
	case "ss":
		plugin, _ := outboundScalarString(mapping["plugin"])
		if plugin != "kcptun" {
			return "", ""
		}
		if pluginOptions, ok := mapping["plugin-opts"].(map[string]any); ok {
			connections, err := providerIntegerUnits(pluginOptions["conn"], "kcptun connection count", "connection")
			if err != nil {
				return "plugin-opts.conn", err.Error()
			}
			if connections < 0 || connections > math.MaxUint16 {
				return "plugin-opts.conn", "kcptun connection count must be 0 (default) through 65535"
			}
			if field, err := validateKcptunFECShards(pluginOptions); err != nil {
				return "plugin-opts." + field, err.Error()
			}
			if field, err := validateKcptunTransportSettings(pluginOptions); err != nil {
				return "plugin-opts." + field, err.Error()
			}
			keepAliveSeconds, err := providerDurationUnits(pluginOptions["keepalive"], time.Second, "kcptun keepalive interval", "second")
			if err != nil {
				return "plugin-opts.keepalive", err.Error()
			}
			if field, err := validateKcptunSmuxSettings(pluginOptions, keepAliveSeconds); err != nil {
				return "plugin-opts." + field, err.Error()
			}
			autoExpire, err := providerNonPositiveDurationAllowedUnits(pluginOptions["autoexpire"], time.Second, "kcptun auto-expire interval", "second")
			if err != nil {
				return "plugin-opts.autoexpire", err.Error()
			}
			if autoExpire > 0 {
				if _, err := providerNonPositiveDurationAllowedUnits(pluginOptions["scavengettl"], time.Second, "kcptun scavenge TTL", "second"); err != nil {
					return "plugin-opts.scavengettl", err.Error()
				}
			}
		}
	case "hysteria":
		ports, hasPorts := outboundScalarString(mapping["ports"])
		if !hasPorts || strings.TrimSpace(ports) == "" {
			return "", ""
		}
		protocol, _ := outboundScalarString(mapping["protocol"])
		if override, ok := outboundScalarString(mapping["obfs-protocol"]); ok && override != "" {
			protocol = override
		}
		if protocol != "" && !strings.EqualFold(protocol, "udp") {
			return "", ""
		}
		if _, err := providerDurationUnits(mapping["hop-interval"], time.Second, "Hysteria hop interval", "second"); err != nil {
			return "hop-interval", err.Error()
		}
	case "hysteria2":
		ports, hasPorts := outboundScalarString(mapping["ports"])
		if !hasPorts || strings.TrimSpace(ports) == "" {
			return "", ""
		}
		rawInterval, exists := mapping["hop-interval"]
		if !exists {
			return "", ""
		}
		interval, ok := outboundScalarString(rawInterval)
		if !ok || strings.TrimSpace(interval) == "" {
			return "", ""
		}
		hopRange, err := utils.NewUnsignedRange[uint64](interval)
		if err != nil {
			return "hop-interval", "Hysteria2 hop interval must be an unsigned second or range"
		}
		maximumSeconds := uint64(math.MaxInt64 / int64(time.Second))
		if hopRange.Start() > maximumSeconds || hopRange.End() > maximumSeconds {
			return "hop-interval", "Hysteria2 hop interval is out of range"
		}
	case "tuic":
		if err := validateTUICMaxOpenStreams(mapping["max-open-streams"]); err != nil {
			return "max-open-streams", err.Error()
		}
		if _, err := providerNonPositiveDurationAllowedUnits(mapping["heartbeat-interval"], time.Millisecond, "TUIC heartbeat interval", "millisecond"); err != nil {
			return "heartbeat-interval", err.Error()
		}
		if field, reason := unsafeTUICDatagramSize(mapping); field != "" {
			return field, reason
		}
		token, _ := outboundScalarString(mapping["token"])
		if token != "" {
			if _, err := providerDurationUnits(mapping["request-timeout"], time.Millisecond, "TUIC v4 request timeout", "millisecond"); err != nil {
				return "request-timeout", err.Error()
			}
		}
	case "masque":
		if _, err := providerDurationUnits(mapping["handshake-timeout"], time.Second, "MASQUE handshake timeout", "second"); err != nil {
			return "handshake-timeout", err.Error()
		}
	case "openvpn":
		if _, err := providerDurationUnits(mapping["ping"], time.Second, "OpenVPN ping interval", "second"); err != nil {
			return "ping", err.Error()
		}
		if _, err := providerDurationUnits(mapping["ping-restart"], time.Second, "OpenVPN ping restart interval", "second"); err != nil {
			return "ping-restart", err.Error()
		}
		if _, err := providerDurationUnits(mapping["handshake-timeout"], time.Second, "OpenVPN handshake timeout", "second"); err != nil {
			return "handshake-timeout", err.Error()
		}
	case "anytls":
		if _, err := providerNonPositiveDurationAllowedUnits(mapping["idle-session-check-interval"], time.Second, "AnyTLS idle session check interval", "second"); err != nil {
			return "idle-session-check-interval", err.Error()
		}
		if _, err := providerNonPositiveDurationAllowedUnits(mapping["idle-session-timeout"], time.Second, "AnyTLS idle session timeout", "second"); err != nil {
			return "idle-session-timeout", err.Error()
		}
	case "wireguard":
		if _, err := providerDurationUnits(mapping["refresh-server-ip-interval"], time.Second, "WireGuard server IP refresh interval", "second"); err != nil {
			return "refresh-server-ip-interval", err.Error()
		}
	}
	return "", ""
}

func validateKcptunFECShards(options map[string]any) (string, error) {
	const (
		defaultDataShards   = int64(10)
		defaultParityShards = int64(3)
		maximumTotalShards  = int64(256)
	)
	dataShards, err := providerIntegerUnits(options["datashard"], "kcptun FEC data shard count", "shard")
	if err != nil {
		return "datashard", err
	}
	if dataShards < 0 || dataShards > maximumTotalShards {
		return "datashard", fmt.Errorf("kcptun FEC data shard count must be 0 (default) through %d", maximumTotalShards)
	}
	if dataShards == 0 {
		dataShards = defaultDataShards
	}

	parityShards, err := providerIntegerUnits(options["parityshard"], "kcptun FEC parity shard count", "shard")
	if err != nil {
		return "parityshard", err
	}
	if parityShards < 0 || parityShards > maximumTotalShards {
		return "parityshard", fmt.Errorf("kcptun FEC parity shard count must be 0 (default) through %d", maximumTotalShards)
	}
	if parityShards == 0 {
		parityShards = defaultParityShards
	}
	if dataShards > maximumTotalShards-parityShards {
		return "parityshard", fmt.Errorf("kcptun FEC data and parity shard total must not exceed %d", maximumTotalShards)
	}
	return "", nil
}

func validateKcptunTransportSettings(options map[string]any) (string, error) {
	mtu, err := providerIntegerUnits(options["mtu"], "kcptun MTU", "byte")
	if err != nil {
		return "mtu", err
	}
	if mtu != 0 {
		// kcp-go subtracts crypto/FEC framing before requiring a 50-byte KCP
		// MTU. The caller ignores SetMtu(false), so reject values that would
		// otherwise silently leave the session at its unrelated default.
		minimumMTU := int64(78) // 50 KCP + 20 classic crypto + 8 FEC
		crypt, _ := outboundScalarString(options["crypt"])
		switch crypt {
		case "null":
			minimumMTU = 58 // no crypto framing + 8 FEC
		case "aes-128-gcm":
			minimumMTU = 86 // 12 nonce + 16 AEAD overhead + 8 FEC
		}
		if mtu < minimumMTU {
			return "mtu", fmt.Errorf("kcptun MTU must be 0 (default) or at least %d bytes for the selected cipher", minimumMTU)
		}
	}

	rateLimit, err := providerIntegerUnits(options["ratelimit"], "kcptun rate limit", "byte-per-second")
	if err != nil {
		return "ratelimit", err
	}
	if rateLimit < 0 || rateLimit > math.MaxUint32 {
		return "ratelimit", fmt.Errorf("kcptun rate limit must be 0 (disabled) through %d bytes per second", uint64(math.MaxUint32))
	}

	for _, field := range []string{"sndwnd", "rcvwnd"} {
		window, err := providerIntegerUnits(options[field], "kcptun "+field+" window", "packet")
		if err != nil {
			return field, err
		}
		if window < 0 || window > math.MaxUint16 {
			return field, fmt.Errorf("kcptun %s window must be 0 (default) through %d packets", field, uint64(math.MaxUint16))
		}
	}

	socketBuffer, err := providerIntegerUnits(options["sockbuf"], "kcptun socket buffer", "byte")
	if err != nil {
		return "sockbuf", err
	}
	if socketBuffer < 0 || socketBuffer > math.MaxInt32 {
		return "sockbuf", fmt.Errorf("kcptun socket buffer must be 0 (default) through %d bytes", int64(math.MaxInt32))
	}

	dscp, err := providerIntegerUnits(options["dscp"], "kcptun DSCP", "value")
	if err != nil {
		return "dscp", err
	}
	if dscp < 0 || dscp > 63 {
		return "dscp", fmt.Errorf("kcptun DSCP must fit its six-bit field (0 through 63)")
	}
	return "", nil
}

func validateKcptunSmuxSettings(options map[string]any, keepAliveSeconds int64) (string, error) {
	const (
		defaultReceiveBuffer = int64(4 * 1024 * 1024)
		defaultStreamBuffer  = int64(2 * 1024 * 1024)
		defaultFrameSize     = int64(8192)
		maximumFrameSize     = int64(65535)
	)
	version, err := providerIntegerUnits(options["smuxver"], "kcptun smux version", "version")
	if err != nil {
		return "smuxver", err
	}
	// FillDefaults maps zero to v1 and deliberately clamps versions above v2
	// to v2. Negative values survive FillDefaults and fail only when the first
	// network connection reaches smux.VerifyConfig.
	if version < 0 {
		return "smuxver", fmt.Errorf("kcptun smux version must not be negative")
	}

	receiveBuffer, err := providerIntegerUnits(options["smuxbuf"], "kcptun smux receive buffer", "byte")
	if err != nil {
		return "smuxbuf", err
	}
	if receiveBuffer == 0 {
		receiveBuffer = defaultReceiveBuffer
	}
	if receiveBuffer < 0 || receiveBuffer > math.MaxInt32 {
		return "smuxbuf", fmt.Errorf("kcptun smux receive buffer must be 0 (default) or 1 through %d bytes", int64(math.MaxInt32))
	}

	frameSize, err := providerIntegerUnits(options["framesize"], "kcptun smux frame size", "byte")
	if err != nil {
		return "framesize", err
	}
	if frameSize == 0 {
		frameSize = defaultFrameSize
	}
	if frameSize < 0 || frameSize > maximumFrameSize {
		return "framesize", fmt.Errorf("kcptun smux frame size must be 0 (default) or 1 through %d bytes", maximumFrameSize)
	}

	streamBuffer, err := providerIntegerUnits(options["streambuf"], "kcptun smux stream buffer", "byte")
	if err != nil {
		return "streambuf", err
	}
	if streamBuffer == 0 {
		streamBuffer = defaultStreamBuffer
	}
	if streamBuffer < 0 || streamBuffer > math.MaxInt32 {
		return "streambuf", fmt.Errorf("kcptun smux stream buffer must be 0 (default) or 1 through %d bytes", int64(math.MaxInt32))
	}
	if streamBuffer > receiveBuffer {
		return "streambuf", fmt.Errorf("kcptun smux stream buffer must not exceed its receive buffer")
	}

	// createConn triples intervals at or above smux's default timeout. Bound
	// the multiplication here so it cannot wrap time.Duration negative before
	// smux verifies the first live connection.
	if keepAliveSeconds > math.MaxInt64/int64(3*time.Second) {
		return "keepalive", fmt.Errorf("kcptun keepalive timeout is out of range")
	}
	return "", nil
}

func unsafeXHTTPGeneratedBuffer(options map[string]any) (string, string) {
	fields := []struct {
		name     string
		fallback string
		label    string
	}{
		{name: "x-padding-bytes", fallback: "100-1000", label: "XHTTP padding"},
		{name: "sc-max-each-post-bytes", fallback: "1000000", label: "XHTTP stream-up post buffer"},
	}
	for _, field := range fields {
		if err := validateBoundedXHTTPRange(options[field.name], field.fallback, field.label); err != nil {
			return field.name, err.Error()
		}
	}

	sessionTable, _ := outboundScalarString(options["session-table"])
	if sessionTable != "" && sessionTable != "uuid" {
		if err := validateBoundedXHTTPRange(options["session-length"], "16-32", "XHTTP session identifier"); err != nil {
			return "session-length", err.Error()
		}
	}
	return "", ""
}

func xhttpUsesPacketUp(mapping, options map[string]any) bool {
	mode, _ := outboundScalarString(options["mode"])
	if mode == "" {
		mode = "auto"
	}
	if mode != "auto" {
		return mode == "packet-up"
	}
	if realityOptions, ok := mapping["reality-opts"].(map[string]any); ok {
		publicKey, _ := outboundScalarString(realityOptions["public-key"])
		if publicKey != "" {
			return false
		}
	}
	return true
}

func validateXHTTPPacketUpSchedule(raw any) error {
	parsed, err := parseXHTTPRange(raw, "30", "XHTTP packet-up post interval")
	if err != nil {
		return err
	}
	if parsed.Max == 0 {
		return fmt.Errorf("XHTTP packet-up post interval must be greater than zero")
	}
	if parsed.Min != parsed.Max && parsed.Max-parsed.Min == math.MaxInt {
		return fmt.Errorf("XHTTP packet-up post interval range overflows its random selection width")
	}
	if int64(parsed.Max) > math.MaxInt64/int64(time.Millisecond) {
		return fmt.Errorf("XHTTP packet-up post interval is out of time.Duration range")
	}
	return nil
}

func validateBoundedXHTTPRange(raw any, fallback, label string) error {
	parsed, err := parseXHTTPRange(raw, fallback, label)
	if err != nil {
		return err
	}
	if parsed.Max > maximumConfigurationBytes {
		return fmt.Errorf("%s exceeds the %d-byte iOS configuration-derived buffer limit", label, maximumConfigurationBytes)
	}
	return nil
}

func unsafeXHTTPReuseSettings(settings map[string]any) (string, string) {
	for _, field := range []string{"max-concurrency", "max-connections", "c-max-reuse-times", "h-max-request-times", "h-max-reusable-secs"} {
		parsed, err := parseXHTTPRange(settings[field], "0", "XHTTP "+field)
		if err != nil {
			return field, err.Error()
		}
		if parsed.Min != parsed.Max && parsed.Max-parsed.Min == math.MaxInt {
			return field, "XHTTP " + field + " range overflows its random selection width"
		}
		switch field {
		case "c-max-reuse-times", "h-max-request-times":
			if parsed.Max > math.MaxInt32 {
				return field, "XHTTP " + field + " exceeds its 32-bit runtime counter"
			}
		case "h-max-reusable-secs":
			if int64(parsed.Max) > math.MaxInt64/int64(time.Second) {
				return field, "XHTTP " + field + " is out of time.Duration range"
			}
		}
	}
	return "", ""
}

func parseXHTTPRange(raw any, fallback, label string) (XH.Range, error) {
	value := ""
	if raw != nil {
		var ok bool
		value, ok = outboundScalarString(raw)
		if !ok {
			return XH.Range{}, nil // preserve the real decoder's type diagnostic
		}
	}
	parsed, err := XH.ParseRange(value, fallback)
	if err != nil {
		return XH.Range{}, fmt.Errorf("%s range is invalid: %w", label, err)
	}
	return parsed, nil
}

func validateTUICMaxOpenStreams(raw any) error {
	value, err := providerIntegerUnits(raw, "TUIC maximum open streams", "stream")
	if err != nil {
		return err
	}
	if value < 0 {
		return fmt.Errorf("TUIC maximum open streams must not be negative")
	}
	if value == 0 {
		return nil // upstream selects its 100-stream default
	}
	// NewTuic reserves another ceil(10%) incoming streams. Mirror its float64
	// conversion exactly, then prove the subsequent int64 addition cannot wrap.
	reserve := int64(math.Ceil(float64(value) / 10.0))
	if value > math.MaxInt64-reserve {
		return fmt.Errorf("TUIC maximum open streams is out of range")
	}
	return nil
}

func validateHysteria2UDPMTU(raw any) error {
	value, err := providerIntegerUnits(raw, "Hysteria2 UDP MTU", "byte")
	if err != nil {
		return err
	}
	if value == 0 {
		return nil // upstream selects its 1197-byte default
	}
	// sing-quic subtracts an eight-byte Hysteria header, a QUIC varint and the
	// destination's host:port string before entering its fragmentation loop.
	// A SOCKS FQDN may contain 255 bytes and ":65535" adds six; the resulting
	// maximum header is 271 bytes. At least one payload byte is required so the
	// loop always advances instead of slicing with a zero or negative length.
	if value < minimumSafeHysteria2UDPMTU {
		return fmt.Errorf("Hysteria2 UDP MTU must be 0 (default) or at least %d bytes", minimumSafeHysteria2UDPMTU)
	}
	return nil
}

func validateActiveBBRCongestionWindow(mapping map[string]any, normalizedType string) error {
	var controller string
	switch normalizedType {
	case "hysteria2":
		// Hysteria2 always installs mihomo's BBR controller when Brutal is not
		// negotiated, so cwnd is active without a congestion-controller field.
		controller = "bbr"
	case "tuic", "masque":
		controller, _ = mapping["congestion-controller"].(string)
	case "trusttunnel":
		quicEnabled, _ := mapping["quic"].(bool)
		if !quicEnabled {
			return nil
		}
		controller, _ = mapping["congestion-controller"].(string)
	default:
		return nil
	}

	switch controller {
	case "bbr", "bbr_meta_v1", "bbr_meta_v2":
	default:
		return nil
	}
	value, err := providerIntegerUnits(mapping["cwnd"], normalizedType+" BBR congestion window", "packet")
	if err != nil {
		return err
	}
	if value < 0 {
		return fmt.Errorf("%s BBR congestion window must not be negative", normalizedType)
	}
	if value > math.MaxInt64/int64(TC.InitialMaxDatagramSize) {
		return fmt.Errorf("%s BBR congestion window is out of range", normalizedType)
	}
	return nil
}

func validateQUICFlowControlWindow(raw any, label string) error {
	value, err := providerIntegerUnits(raw, label, "byte")
	if err != nil {
		return err
	}
	if value < 0 {
		return fmt.Errorf("%s must not be negative", label)
	}
	if uint64(value) > quicvarint.Max {
		return fmt.Errorf("%s exceeds the QUIC flow-control limit", label)
	}
	return nil
}

func validateHysteriaCompatibleSpeed(raw any, label string) error {
	value, err := providerIntegerUnits(raw, label, "Mbps")
	if err != nil {
		return err
	}
	const mbpsToBytesPerSecond int64 = 125000
	if value < 0 {
		return fmt.Errorf("%s must not be negative", label)
	}
	if value > math.MaxInt64/mbpsToBytesPerSecond {
		return fmt.Errorf("%s is out of range", label)
	}
	return nil
}

func validateHysteriaRate(raw any, label string) error {
	value, ok := raw.(string)
	if !ok || value == "" {
		return nil
	}
	if plain, err := strconv.ParseInt(value, 10, 64); err == nil {
		if plain < 0 {
			return nil // upstream rejects the resulting invalid rate
		}
		const megabitMultiplier uint64 = 1000 * 1000
		if uint64(plain) > math.MaxUint64/megabitMultiplier {
			return fmt.Errorf("%s is out of range", label)
		}
		return nil
	}
	match := hysteriaRateToken.FindStringSubmatch(value)
	if len(match) != 4 {
		return nil // preserve upstream's own syntax diagnostic
	}
	magnitude, err := strconv.ParseUint(match[1], 10, 64)
	if err != nil {
		return nil // upstream resolves an unparseable magnitude to zero
	}
	multiplier := uint64(1)
	switch match[2] {
	case "T":
		multiplier *= 1000
		fallthrough
	case "G":
		multiplier *= 1000
		fallthrough
	case "M":
		multiplier *= 1000
		fallthrough
	case "K":
		multiplier *= 1000
	}
	if magnitude > math.MaxUint64/multiplier {
		return fmt.Errorf("%s is out of range", label)
	}
	return nil
}

func unsafeTUICDatagramSize(mapping map[string]any) (string, string) {
	token, _ := outboundScalarString(mapping["token"])
	packetOverhead := int64(T.PacketOverHeadV5)
	if token != "" {
		packetOverhead = int64(T.PacketOverHeadV4)
	}

	frameSize, err := providerIntegerUnits(mapping["max-datagram-frame-size"], "TUIC maximum datagram frame size", "byte")
	if err != nil {
		return "max-datagram-frame-size", err.Error()
	}
	if frameSize != 0 {
		if frameSize <= packetOverhead {
			return "max-datagram-frame-size", "TUIC maximum datagram frame size must exceed its protocol packet overhead"
		}
		// An explicit frame size replaces the raw UDP relay packet size in
		// NewTuic, so validating that now-unconsumed value would reject an
		// upstream-compatible configuration for no runtime safety benefit.
		return "", ""
	}

	packetSize, err := providerIntegerUnits(mapping["max-udp-relay-packet-size"], "TUIC maximum UDP relay packet size", "byte")
	if err != nil {
		return "max-udp-relay-packet-size", err.Error()
	}
	if packetSize < 0 {
		return "max-udp-relay-packet-size", "TUIC maximum UDP relay packet size must not be negative"
	}
	if packetSize > math.MaxInt64-packetOverhead {
		return "max-udp-relay-packet-size", "TUIC maximum UDP relay packet size is out of range"
	}
	return "", ""
}

func outboundScalarString(raw any) (string, bool) {
	switch value := raw.(type) {
	case string:
		return value, true
	case int:
		return fmt.Sprint(value), true
	case int32:
		return fmt.Sprint(value), true
	case int64:
		return fmt.Sprint(value), true
	case uint:
		return fmt.Sprint(value), true
	case uint32:
		return fmt.Sprint(value), true
	case uint64:
		return fmt.Sprint(value), true
	default:
		return "", false
	}
}

func providerPayloadMappings(raw any) []map[string]any {
	switch payload := raw.(type) {
	case []map[string]any:
		return payload
	case []any:
		mappings := make([]map[string]any, 0, len(payload))
		for _, item := range payload {
			if mapping, ok := item.(map[string]any); ok {
				mappings = append(mappings, mapping)
			}
		}
		return mappings
	default:
		return nil
	}
}

// outboundEgressOverrideFields returns every interface-name / routing-mark
// egress override present on an outbound. These select a physical interface /
// mark the NE does not expose, but they never change which proxy handles a flow,
// so stripOutboundEgressOverrides strips them (tolerate + strip). The embedded
// L3 DNS fragment (outboundEmbeddedDNSHasFragment) is handled separately and
// stays rejected.
func outboundEgressOverrideFields(mapping map[string]any) []string {
	fields := make([]string, 0, 2)
	for _, field := range []string{"interface-name", "routing-mark"} {
		if value, exists := mapping[field]; exists && !isZeroish(value) {
			fields = append(fields, field)
		}
	}
	return fields
}

func outboundEmbeddedDNSHasFragment(mapping map[string]any) bool {
	typeName, _ := mapping["type"].(string)
	switch typeName {
	case "wireguard", "openvpn", "masque":
	default:
		return false
	}
	remoteDNSResolve, _ := mapping["remote-dns-resolve"].(bool)
	if !remoteDNSResolve {
		return false
	}
	for _, server := range dnsServerStrings(mapping["dns"]) {
		if dnsFragmentProxyName(server) != "" {
			return true
		}
	}
	return false
}

type metadataRuleOccurrence struct {
	kind     string
	location string
}

// unavailableMetadataRuleOccurrences returns every Apple-unavailable metadata
// rule in deterministic order without retaining or reporting its payload. The
// caller can therefore produce complete, bounded warnings without leaking
// process paths, user names, or other policy values into logs.
// metadataRuleKeptExplanation is the single sentence every surface uses for
// these rules. It says what happens, not what a platform forbids: the rule is
// kept and evaluated, and what is missing is the metadata to evaluate it
// against. "Stripped, matches nothing, falls through to the next rule" was the
// old wording and it was false for logic rules, which were removed whole.
const metadataRuleKeptExplanation = "the owner metadata it tests cannot be resolved in this profile; " +
	"the rule is kept and evaluated against empty metadata, exactly as mihomo does with find-process-mode off"

// summarizeMetadataRuleOccurrences folds a full occurrence list into one line
// per kind. A configuration may carry twenty thousand rules; a log stream and a
// notice list both need a bound, while the occurrence list itself keeps every
// location for callers that can hold it.
func summarizeMetadataRuleOccurrences(raw *config.RawConfig, capability appleProcessMetadataCapability) []string {
	occurrences := unavailableMetadataRuleOccurrences(raw, capability)
	occurrences = append(occurrences, inlineRuleProviderMetadataOccurrences(raw, capability)...)
	return summarizeOccurrenceList(occurrences)
}

func summarizeOccurrenceList(occurrences []metadataRuleOccurrence) []string {
	counts := make(map[string]int, len(occurrences))
	first := make(map[string]string, len(occurrences))
	order := make([]string, 0, len(occurrences))
	for _, occurrence := range occurrences {
		if _, seen := counts[occurrence.kind]; !seen {
			order = append(order, occurrence.kind)
			first[occurrence.kind] = occurrence.location
		}
		counts[occurrence.kind]++
	}
	summaries := make([]string, 0, len(order))
	for _, kind := range order {
		switch counts[kind] {
		case 1:
			summaries = append(summaries, fmt.Sprintf("%s rule at %s", kind, first[kind]))
		default:
			summaries = append(summaries, fmt.Sprintf("%d %s rules, first at %s", counts[kind], kind, first[kind]))
		}
	}
	return summaries
}

// unavailableMetadataRuleOccurrences reports EVERY rule whose owner metadata
// this profile cannot resolve, not one per kind. Deduping by kind was fine
// while the answer was "and it was stripped", because one example explained a
// uniform outcome. It is not fine now: the rules are kept, so a reader asking
// "which of my rules are affected" needs the list, and a second PROCESS-NAME
// rule is a different rule from the first. Callers that must stay bounded
// aggregate with summarizeMetadataRuleOccurrences instead of dropping data here.
func unavailableMetadataRuleOccurrences(raw *config.RawConfig, capability appleProcessMetadataCapability) []metadataRuleOccurrence {
	occurrences := make([]metadataRuleOccurrence, 0)
	appendOccurrence := func(kind, location string) {
		occurrences = append(occurrences, metadataRuleOccurrence{kind: kind, location: location})
	}
	for index, rule := range raw.Rule {
		if kind := unavailableMetadataRuleKind(rule, capability); kind != "" {
			appendOccurrence(kind, fmt.Sprintf("rules[%d]", index))
		}
	}
	names := make([]string, 0, len(raw.SubRules))
	for name := range raw.SubRules {
		names = append(names, name)
	}
	sort.Strings(names)
	for groupIndex, name := range names {
		for ruleIndex, rule := range raw.SubRules[name] {
			if kind := unavailableMetadataRuleKind(rule, capability); kind != "" {
				appendOccurrence(kind, fmt.Sprintf("sub-rules[%d][%d]", groupIndex, ruleIndex))
			}
		}
	}
	return occurrences
}

// inlineRuleProviderMetadataOccurrences reports every affected payload entry,
// for the same reason unavailableMetadataRuleOccurrences does.
func inlineRuleProviderMetadataOccurrences(raw *config.RawConfig, capability appleProcessMetadataCapability) []metadataRuleOccurrence {
	occurrences := make([]metadataRuleOccurrence, 0)
	names := make([]string, 0, len(raw.RuleProvider))
	for name := range raw.RuleProvider {
		names = append(names, name)
	}
	sort.Strings(names)
	for providerIndex, name := range names {
		definition := raw.RuleProvider[name]
		typeName, _ := definition["type"].(string)
		behavior, _ := definition["behavior"].(string)
		if typeName != "inline" || behavior != "classical" {
			continue
		}
		var entries []string
		switch payload := definition["payload"].(type) {
		case []any:
			for _, item := range payload {
				if rule, ok := item.(string); ok {
					entries = append(entries, rule)
				}
			}
		case []string:
			entries = payload
		}
		for ruleIndex, rule := range entries {
			if kind := unavailableMetadataRuleKind(rule, capability); kind != "" {
				occurrences = append(occurrences, metadataRuleOccurrence{
					kind: kind, location: fmt.Sprintf("rule-providers[%d].payload[%d]", providerIndex, ruleIndex),
				})
			}
		}
	}
	return occurrences
}

// unavailableMetadataRuleKind returns the owner-metadata rule kind when THIS profile cannot
// resolve the source that kind needs, and "" otherwise. It answers "must this rule be
// stripped", not "is this a metadata rule" -- the same rule is executable on the macOS Packet
// Tunnel and inert on iOS, so the capability has to be part of the question.
// metadataRuleKindNames are the ten kinds whose owner metadata no Apple
// packet tunnel can resolve. They do not share an identity source, which is
// why they are listed rather than matched by shape.
var metadataRuleKindNames = [...]string{
	"PROCESS-NAME", "PROCESS-NAME-REGEX", "PROCESS-NAME-WILDCARD",
	"PROCESS-PATH", "PROCESS-PATH-REGEX", "PROCESS-PATH-WILDCARD",
	"UID", "IN-USER", "SOURCE-APP-SIGNING-ID", "SOURCE-APP-TEAM-ID",
}

func matchesMetadataRuleKindName(token string) string {
	for _, name := range metadataRuleKindNames {
		if strings.EqualFold(token, name) {
			return name
		}
	}
	return ""
}

func unavailableMetadataRuleKind(rule string, capability appleProcessMetadataCapability) string {
	// unavailableMetadataRuleToken only matches at the start of the rule or
	// just after a '(', so a rule with no parenthesis can be answered by
	// looking at the token before its first comma -- no regexp, no allocation.
	// That is every ordinary rule, and running the regexp over all of them
	// cost 29ms of a 33ms normalize pass on a twenty-thousand-rule
	// configuration. Logic rules, which do carry parentheses, still take the
	// full pattern.
	var kind string
	if strings.IndexByte(rule, '(') < 0 {
		comma := strings.IndexByte(rule, ',')
		if comma < 0 {
			return ""
		}
		kind = matchesMetadataRuleKindName(strings.TrimSpace(rule[:comma]))
		if kind == "" {
			return ""
		}
	} else {
		match := unavailableMetadataRuleToken.FindStringSubmatch(rule)
		if len(match) != 2 {
			return ""
		}
		kind = strings.ToUpper(match[1])
	}
	if capability.resolves(kind) {
		return ""
	}
	return kind
}

func isUnavailableMetadataRuleType(kind string, capability appleProcessMetadataCapability) bool {
	if capability.resolves(kind) {
		return false
	}
	switch strings.ToUpper(strings.TrimSpace(kind)) {
	case "PROCESS-NAME", "PROCESS-NAME-REGEX", "PROCESS-NAME-WILDCARD",
		"PROCESS-PATH", "PROCESS-PATH-REGEX", "PROCESS-PATH-WILDCARD",
		"UID", "IN-USER", "SOURCE-APP-SIGNING-ID", "SOURCE-APP-TEAM-ID":
		return true
	default:
		return false
	}
}

// validateForIOS rejects parsed configurations that cannot work inside the NE
// before Start applies them, with readable errors. Runs after parse,
// before overrideForIOS.
func validateForIOS(cfg *config.Config, underNE bool) error {
	return validateForApple(cfg, runtimePolicyFor(runtimeProfileIOSPacketTunnel, underNE))
}

func validateForApple(cfg *config.Config, policy appleRuntimePolicy) error {
	if !policy.useSystemDNS {
		if err := validateDNSForIOS(cfg, policy.requirePacketTunnelDNS); err != nil {
			return err
		}
	}
	if policy.packetTunnel {
		if err := validateTunForIOS(cfg); err != nil {
			return err
		}
	}
	return validateProvidersForIOS(cfg)
}

// validateTunForIOS has nothing left to refuse. It kept the same route-address-set rejection
// as validateRawNetworkExtensionIntentForApple, one layer further in, and it went for the same
// reason: the field is an nftables bypass switch that upstream itself ignores off Linux.
// The function stays as the place a genuine tun refusal would go, rather than being deleted
// and re-invented at the next one.
func validateTunForIOS(cfg *config.Config) error {
	return nil
}

func validateDNSForIOS(cfg *config.Config, underNE bool) error {
	// DNS being off is not a refusal, on any profile. mihomo accepts it, tears the resolver
	// down (hub/executor/executor.go:238-247) and leaves tun hijacking port 53 anyway,
	// because hijack-all is its own default (config.go:544) -- so a configuration with no
	// dns block has broken DNS in a tunnel under mihomo too. That is upstream's behaviour,
	// and a reader who wrote such a configuration meets it wherever they run it.
	//
	// Refusing it here made this the only tunnel that would not start; the repair that
	// replaced the refusal made it the only tunnel where such a configuration
	// worked. Both are the same mistake measured from opposite sides. The yardstick is
	// mihomo, and mihomo neither refuses nor repairs.
	if cfg.DNS == nil || !cfg.DNS.Enable {
		return nil
	}
	// No resolver SCHEME is refused here. dhcp:// and system:// used to be, in
	// every slot, on the grounds that "the NE cannot run DHCP" and that system://
	// escapes the core. Neither is a platform prohibition:
	//
	//   - Upstream carries both as ordinary transports and reports their failure
	//     per query, never at load -- a DHCP probe with no answer surfaces as
	//     ErrNotResponding (component/dhcp/dhcp.go:15) from the resolver.
	//   - sing-box compiles its DHCP transport INTO the Apple build
	//     (cmd/internal/build_libbox/main.go:67 adds with_dhcp to darwinTags) and
	//     still refuses nothing: Start() logs a failed interface fetch from a
	//     goroutine and returns nil regardless (dns/transport/dhcp/dhcp.go:95-113),
	//     and the build without the tag errors at transport CONSTRUCTION with
	//     "rebuild with -tags with_dhcp" (include/dhcp_stub.go). An actionable
	//     message where the transport is built, not a refusal to load a profile.
	//
	// The true constraint is narrower and belongs to the transport rather than the
	// sandbox: mihomo's DHCP client binds 0.0.0.0:68 (component/dhcp/conn.go:13),
	// a privileged port no unprivileged Apple process can bind -- the containing
	// App as much as the extension -- and resolves a physical interface by name
	// (dhcp.go:30), which the tunnel is not. system:// reads the system resolver,
	// which inside the packet tunnel is NEDNSSettings pointing back at us.
	//
	// Both of those are reasons to strip and WARN, which the packet-tunnel path
	// already does before this runs (stripNEIncompatibleNameservers, called at
	// config_pipeline.go:159 with a per-entry log line). Neither was ever a
	// reason to refuse the configuration, and refusing it here did real damage:
	// the strip is gated on policy.networkExtension, so a packet-tunnel profile
	// evaluated from the App process (service.go:174 passes
	// platform.UnderNetworkExtension()) reached this function with the schemes
	// still present and would not start at all -- while the very same config
	// started fine inside the extension.
	//
	// Require explicit nameservers so the core never falls back to the
	// hardcoded 114.114.114.114/8.8.8.8 system defaults (dns/system.go:71),
	// which would leak DNS and likely be unreachable through the tunnel.
	if len(cfg.DNS.NameServer) == 0 {
		return fmt.Errorf("hako: dns.nameserver must be set explicitly on iOS (no system-DNS fallback available in the NE)")
	}
	return nil
}

func firstDNSPhysicalInterfaceFragment(raw *config.RawConfig) string {
	knownProxies := map[string]struct{}{
		"DIRECT": {}, "REJECT": {}, "REJECT-DROP": {}, "COMPATIBLE": {},
		"PASS": {}, "PASS-RULE": {}, "GLOBAL": {}, dns.RespectRules: {},
	}
	for _, proxy := range raw.Proxy {
		if name, _ := proxy["name"].(string); name != "" {
			knownProxies[name] = struct{}{}
		}
	}
	for _, group := range raw.ProxyGroup {
		if name, _ := group["name"].(string); name != "" {
			knownProxies[name] = struct{}{}
		}
	}

	groups := []struct {
		field   string
		servers []string
	}{
		{field: "dns.nameserver", servers: raw.DNS.NameServer},
		{field: "dns.fallback", servers: raw.DNS.Fallback},
		{field: "dns.default-nameserver", servers: raw.DNS.DefaultNameserver},
		{field: "dns.proxy-server-nameserver", servers: raw.DNS.ProxyServerNameserver},
		{field: "dns.direct-nameserver", servers: raw.DNS.DirectNameServer},
	}
	for _, group := range groups {
		if hasUnknownDNSFragmentProxy(group.servers, knownProxies) {
			return group.field
		}
	}
	if raw.DNS.NameServerPolicy != nil {
		for pair := raw.DNS.NameServerPolicy.Oldest(); pair != nil; pair = pair.Next() {
			if hasUnknownDNSFragmentProxy(dnsServerStrings(pair.Value), knownProxies) {
				return "dns.nameserver-policy"
			}
		}
	}
	if raw.DNS.ProxyServerNameserverPolicy != nil {
		for pair := raw.DNS.ProxyServerNameserverPolicy.Oldest(); pair != nil; pair = pair.Next() {
			if hasUnknownDNSFragmentProxy(dnsServerStrings(pair.Value), knownProxies) {
				return "dns.proxy-server-nameserver-policy"
			}
		}
	}
	return ""
}

func dnsServerStrings(raw any) []string {
	switch value := raw.(type) {
	case string:
		return []string{value}
	case []string:
		return value
	case []any:
		servers := make([]string, 0, len(value))
		for _, item := range value {
			if server, ok := item.(string); ok {
				servers = append(servers, server)
			}
		}
		return servers
	default:
		return nil
	}
}

func hasUnknownDNSFragmentProxy(servers []string, knownProxies map[string]struct{}) bool {
	for _, server := range servers {
		proxyName := dnsFragmentProxyName(server)
		if proxyName == "" {
			continue
		}
		if _, known := knownProxies[proxyName]; !known {
			return true
		}
	}
	return false
}

func dnsFragmentProxyName(server string) string {
	fragmentIndex := strings.IndexByte(server, '#')
	if fragmentIndex < 0 || fragmentIndex == len(server)-1 {
		return ""
	}
	var proxyName string
	for _, component := range strings.Split(server[fragmentIndex+1:], "&") {
		if !strings.Contains(component, "=") {
			decoded, err := url.PathUnescape(component)
			if err != nil {
				return component
			}
			proxyName = decoded
		}
	}
	return proxyName
}

// validateProvidersForIOS rejects remote (HTTP) rule/proxy providers.
// Their Initial() fetches from the network during ApplyConfig,
// which blocks Start and can spike memory inside the NE. Downstream must
// pre-download them app-side and reference file-based providers.
func validateProvidersForIOS(cfg *config.Config) error {
	proxyProviderNames := make([]string, 0, len(cfg.Providers))
	for name := range cfg.Providers {
		proxyProviderNames = append(proxyProviderNames, name)
	}
	sort.Strings(proxyProviderNames)
	for _, name := range proxyProviderNames {
		p := cfg.Providers[name]
		if p.VehicleType() == P.HTTP {
			return fmt.Errorf("hako: proxy-provider %q is remote (HTTP) — parse-time fetch is unsupported on iOS; pre-download it app-side and use a file provider", name)
		}
	}
	ruleProviderNames := make([]string, 0, len(cfg.RuleProviders))
	for name := range cfg.RuleProviders {
		ruleProviderNames = append(ruleProviderNames, name)
	}
	sort.Strings(ruleProviderNames)
	for _, name := range ruleProviderNames {
		p := cfg.RuleProviders[name]
		if p.VehicleType() == P.HTTP {
			return fmt.Errorf("hako: rule-provider %q is remote (HTTP) — parse-time fetch is unsupported on iOS; pre-download it app-side and use a file provider", name)
		}
	}
	return nil
}
