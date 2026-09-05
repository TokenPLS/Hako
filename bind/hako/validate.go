package hako

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/TokenPLS/Hako/common/utils"
	"github.com/TokenPLS/Hako/config"
	"github.com/TokenPLS/Hako/dns"
	"github.com/TokenPLS/Hako/transport/xhttp"
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
	// A nested outbound `dns:` carrying a '#fragment' used to be rejected here
	// too, and that was the same mistake one paragraph later. Upstream accepts
	// it: adapter/outbound/wireguard.go:496-508 parses the nested servers with
	// dns.ParseNameServer and then assigns nss[i].ProxyAdapter = outbound, so
	// the fragment selects nothing and the outbound is built regardless. The
	// fragment is inert upstream, not fatal.
	//
	// downgraded the PLAN's copy of this refusal to a notice and stopped
	// there, so the configuration got a notice saying it would still start and
	// then did not: this function runs from config_pipeline.go:62-76, on the
	// real activation path, and refused the whole document. Found by Codex on
	// 2026-08-27 with a valid WireGuard fixture that mihomo accepts.
	//
	// Nothing replaces it. The plan's notice already says the fragment does
	// nothing, which is the whole truth there is to tell.
	_ = policy
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
	"the rule is kept and evaluated against empty metadata, exactly as with find-process-mode off"

// summarizeMetadataRuleOccurrences folds a full occurrence list into one line
// per kind. A configuration may carry twenty thousand rules; a log stream and a
// notice list both need a bound, while the occurrence list itself keeps every
// location for callers that can hold it.
func summarizeMetadataRuleOccurrences(raw *config.RawConfig, capability appleProcessMetadataCapability) []string {
	occurrences := unavailableMetadataRuleOccurrences(raw, capability)
	occurrences = append(occurrences, inlineRuleProviderMetadataOccurrences(raw, capability)...)
	return summarizeOccurrenceList(occurrences)
}

// metadataRuleOccurrenceSummary is one kind's summary with the kind and count kept as data.
type metadataRuleOccurrenceSummary struct {
	kind    string
	count   int
	summary string
}

// summarizeMetadataRuleOccurrenceKinds is summarizeMetadataRuleOccurrences with the kind
// and the count still separate, for the plan's structured notices.
func summarizeMetadataRuleOccurrenceKinds(raw *config.RawConfig, capability appleProcessMetadataCapability) []metadataRuleOccurrenceSummary {
	occurrences := unavailableMetadataRuleOccurrences(raw, capability)
	occurrences = append(occurrences, inlineRuleProviderMetadataOccurrences(raw, capability)...)
	counts := make(map[string]int, len(occurrences))
	order := make([]string, 0, len(occurrences))
	for _, occurrence := range occurrences {
		if _, seen := counts[occurrence.kind]; !seen {
			order = append(order, occurrence.kind)
		}
		counts[occurrence.kind]++
	}
	summaries := summarizeOccurrenceList(occurrences)
	out := make([]metadataRuleOccurrenceSummary, 0, len(order))
	for i, kind := range order {
		out = append(out, metadataRuleOccurrenceSummary{kind: kind, count: counts[kind], summary: summaries[i]})
	}
	return out
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
	return validateForApple(cfg, nil, runtimePolicyFor(runtimeProfileIOSPacketTunnel, underNE))
}

func validateForApple(cfg *config.Config, raw *config.RawConfig, policy appleRuntimePolicy) error {
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
	// Remote providers are no longer refused here; see validateRawProvidersForIOS
	// in config_pipeline.go for why.
	return nil
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
		// refusal-id: Validate.dnsNameserverRequired
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

// unfetchableProviderNames lists the providers whose url this build could never
// issue a request for, so no layer refuses one on a ground that cannot apply to
// it. url.Parse fails before any socket, so's reason -- parse-time
// network I/O blocking Start or spiking the NE's memory -- is not reachable.
//
// It is computed from the RAW configuration because that is the only place the
// url text survives: by the time providers are parsed, constant/provider's
// interface exposes VehicleType() and no accessor for the vehicle itself.
// A nil raw (the CheckConfig entry, which has no raw to hand over) yields an
// empty set and every HTTP provider is judged as before.
func unfetchableProviderNames(raw *config.RawConfig) map[string]bool {
	out := map[string]bool{}
	if raw == nil {
		return out
	}
	for _, group := range []map[string]map[string]any{raw.ProxyProvider, raw.RuleProvider} {
		for name, def := range group {
			if t, _ := def["type"].(string); !strings.EqualFold(t, "http") {
				continue
			}
			// An absent url belongs here too, and the `continue` that used to
			// skip it was the same mistake this function exists to correct. The
			// stated ground is that's reason -- parse-time network I/O --
			// cannot reach a url no request can be made from, and an empty url
			// is the clearest case of that: NewHTTPVehicle("") opens nothing.
			// normalizeResourceURL("") already rejects it (url.Parse succeeds
			// and leaves Scheme empty), so it only had to stop being skipped
			// before the question was asked.
			//
			// What the skip cost was not just a refusal but a sentence that did
			// not fit: an http provider with no url was told to "pre-download it
			// app-side and use a file provider", about an address that does not
			// exist. Upstream declares url as `provider:"url,omitempty"`
			// (adapter/provider/parser.go:21, rules/provider/parse.go:18), never
			// checks it, and accepts both shapes -- measured, not read.
			//
			// Found by the macOS lane while re-auditing its own registry, one
			// commit after this function was written.
			rawURL, _ := def["url"].(string)
			if _, err := normalizeResourceURL(rawURL, "provider"); err != nil {
				out[name] = true
			}
		}
	}
	return out
}

// outboundOptionIssue names one outbound option this build cannot represent.
type outboundOptionIssue struct {
	Field  string
	Reason string
}

// unrepresentableOutboundOptions reports values that cannot survive the trip
// into the transport's own types -- a duration past time.Duration's range being
// the case that exists today. This is NOT a judgement about whether a range is
// sensible: those checks are gone, because upstream makes none of them.
// It is the narrower fact that the number the reader wrote is not the number
// the transport will read, which is worth saying even though the node loads and
// dials either way. Upstream reads the same value the same way and says
// nothing; saying it is the one thing this layer adds.
// upstreamRefusedOutboundOptions walks the same outbounds as
// unrepresentableOutboundOptions and reports the ones upstream itself refuses.
// Same walk, different question: this one predicts a refusal mihomo will make,
// so the plan can say so instead of promising a start that does not happen.
func upstreamRefusedOutboundOptions(raw *config.RawConfig) []outboundOptionIssue {
	issues := []outboundOptionIssue{}
	for index, outbound := range raw.Proxy {
		if field, reason := upstreamRefusedOutboundOption(outbound); field != "" {
			issues = append(issues, outboundOptionIssue{Field: fmt.Sprintf("proxies[%d].%s", index, field), Reason: reason})
		}
	}
	names := make([]string, 0, len(raw.ProxyProvider))
	for name := range raw.ProxyProvider {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for index, outbound := range providerPayloadMappings(raw.ProxyProvider[name]["payload"]) {
			if field, reason := upstreamRefusedOutboundOption(outbound); field != "" {
				issues = append(issues, outboundOptionIssue{
					Field: fmt.Sprintf("proxy-providers.%s.payload[%d].%s", name, index, field), Reason: reason})
			}
		}
	}
	return issues
}

func unrepresentableOutboundOptions(raw *config.RawConfig) []outboundOptionIssue {
	issues := []outboundOptionIssue{}
	for index, outbound := range raw.Proxy {
		if field, reason := unrepresentableOutboundOption(outbound); field != "" {
			issues = append(issues, outboundOptionIssue{Field: fmt.Sprintf("proxies[%d].%s", index, field), Reason: reason})
		}
	}
	names := make([]string, 0, len(raw.ProxyProvider))
	for name := range raw.ProxyProvider {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for index, outbound := range providerPayloadMappings(raw.ProxyProvider[name]["payload"]) {
			if field, reason := unrepresentableOutboundOption(outbound); field != "" {
				issues = append(issues, outboundOptionIssue{
					Field: fmt.Sprintf("proxy-providers.%s.payload[%d].%s", name, index, field), Reason: reason})
			}
		}
	}
	return issues
}

// upstreamRefusedOutboundOption reports an outbound option value that UPSTREAM
// itself refuses, by asking upstream's own parsers rather than re-deriving what
// they accept.
//
// removed seventeen value checks on the stated ground that "not one of
// them was a check upstream makes". Seven of those were mixed, and the ground
// was false for the mixed half. The line should have drawn is visible in
// upstream's own code: it REFUSES a value it cannot parse and CLAMPS one that
// parses but sits out of range. adapter/outbound/hysteria2.go:280-291 does both
// in six lines -- NewUnsignedRange returns an error for malformed input, and a
// hop interval below minHopInterval is silently raised to it. Deleting the
// clamped half was right; deleting the refused half made the plan promise a
// start that mihomo then refuses, which is a false positive at exactly the
// moment a user is deciding whether their configuration is good.
//
// Nothing here invents a bound. Every verdict is upstream's own function
// returning upstream's own error, so this cannot drift stricter than upstream
// without upstream moving first. Found by Codex 2026-08-27.
//
// The boundary, so nobody reads this as complete: it judges values that are
// PRESENT and unparseable. It does not predict upstream's missing-required-field
// refusals -- a hysteria proxy with no `up` is refused by mihomo as "has unset
// fields: up", from the decoder rather than from Speed(), and every proxy type
// has its own such set. Reproducing that would mean reimplementing the decoder,
// which is a far larger surface to drift stricter on than it is worth. So an
// empty value is skipped here on purpose, and the plan will tolerate a document
// mihomo then refuses for a missing field. That is a known gap, not an
// oversight.
func upstreamRefusedOutboundOption(mapping map[string]any) (string, string) {
	proxyType, _ := outboundScalarString(mapping["type"])

	switch strings.ToLower(proxyType) {
	case "hysteria":
		// HysteriaOption.Speed (adapter/outbound/hysteria.go:131-143): a rate
		// StringToBps cannot read comes back 0 and the constructor rejects it.
		// StringToBps alone returns no error, which is the half-read that put
		// this family on the delete list.
		for _, field := range []string{"up", "down"} {
			value, _ := outboundScalarString(mapping[field])
			if value == "" {
				continue
			}
			if utils.StringToBps(value) == 0 {
				return field, fmt.Sprintf("invaild %s speed: %s", map[string]string{"up": "upload", "down": "download"}[field], value)
			}
		}
	case "hysteria2":
		// adapter/outbound/hysteria2.go:271-283.
		ports, _ := outboundScalarString(mapping["ports"])
		if ports != "" {
			if _, err := utils.NewUnsignedRanges[uint16](ports); err != nil {
				return "ports", err.Error()
			}
			hop, _ := outboundScalarString(mapping["hop-interval"])
			if hop != "" {
				if _, err := utils.NewUnsignedRange[uint64](hop); err != nil {
					return "hop-interval", err.Error()
				}
			}
		}
	}

	// xhttp ranges. transport/xhttp/client.go builds the config for every
	// xhttp outbound and adapter/outbound/vless.go:904-907 hands the error to
	// config.Parse, so a range upstream cannot parse refuses the document.
	// ParseRange's own defaults are used, because a field left unset must be
	// judged exactly as upstream judges it -- by its fallback, not by ours.
	network, _ := outboundScalarString(mapping["network"])
	if strings.EqualFold(network, "xhttp") {
		if opts, ok := mapping["xhttp-opts"].(map[string]any); ok {
			// Exactly two, because exactly two were MEASURED to reach
			// config.Parse. transport/xhttp/config.go:327-358 shows ParseRange
			// refusing malformed input for every xhttp range, and reading only
			// that would put five fields here -- but a parser is refused by
			// whoever calls it, and three of the five are not called during
			// parse. Driving mihomo over all five settles it:
			//
			//	sc-max-each-post-bytes    bad-range / 0   REFUSED
			//	sc-min-posts-interval-ms  bad-range / 0   REFUSED
			//	sc-max-buffered-posts     bad-range / 0   accepted
			//	sc-stream-up-server-secs  bad-range / 0   accepted
			//	x-padding-bytes           bad-range / 0   accepted
			//
			// The three accepted ones are resolved later, so refusing them here
			// would be exactly the overreach set out to remove.
			// TestPlanRefusesExactlyWhatUpstreamRefuses asks mihomo before
			// asking the plan, which is how x-padding-bytes was caught in this
			// list before it shipped.
			for _, r := range []struct{ key, fallback string }{
				{"sc-max-each-post-bytes", "1000000"},
				{"sc-min-posts-interval-ms", "30"},
			} {
				value, ok := outboundScalarString(opts[r.key])
				if !ok || value == "" {
					continue
				}
				parsed, err := xhttp.ParseRange(value, r.fallback)
				if err != nil {
					return "xhttp-opts." + r.key, fmt.Sprintf("invalid %s: %v", r.key, err)
				}
				if parsed.Max == 0 {
					return "xhttp-opts." + r.key, fmt.Sprintf("invalid %s: must be greater than zero", r.key)
				}
			}
		}
	}
	return "", ""
}

func unrepresentableOutboundOption(mapping map[string]any) (string, string) {
	network, _ := outboundScalarString(mapping["network"])
	if strings.EqualFold(network, "grpc") {
		if opts, ok := mapping["grpc-opts"].(map[string]any); ok {
			if _, err := providerNonPositiveDurationAllowedUnits(
				opts["ping-interval"], time.Second, "gRPC ping interval", "second"); err != nil {
				return "grpc-opts.ping-interval", err.Error()
			}
		}
	}
	return "", ""
}
