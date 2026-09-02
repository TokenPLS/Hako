package hako

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"net"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/TokenPLS/Hako/common/orderedmap"
	"github.com/TokenPLS/Hako/component/geodata"
	"github.com/TokenPLS/Hako/component/process"
	"github.com/TokenPLS/Hako/config"
	C "github.com/TokenPLS/Hako/constant"
	"github.com/TokenPLS/Hako/dns"
	"github.com/TokenPLS/Hako/log"
)

// disabledGeoURL is deliberately not a network URL. The readable preflight
// below catches every supported geodata consumer; these values are a final
// fail-closed guard if upstream adds another parse-time consumer.
const disabledGeoURL = "hako-ne-disabled://prestage-required"

// parseConfigForIOS is the only Start/Reload configuration entry point. Fields
// which affect parsing side effects are normalized on typed RawConfig before
// ParseRawConfig; runtime fields remain post-parse overrides.
func parseConfigForIOS(content string, underNE bool) (*config.Config, error) {
	cfg, _, err := parseConfigForIOSInternal(content, underNE, false)
	return cfg, err
}

// parseConfigForIOSRuntime is the Start/Reload entry point. Unlike CheckConfig,
// it redirects file providers to a private runtime shadow before constructing
// provider objects, so native side updates never mutate a published revision.
func parseConfigForIOSRuntime(content string, underNE bool, entry string) (*config.Config, *providerRuntime, error) {
	cfg, runtime, err := parseConfigForIOSInternal(content, underNE, true)
	if err != nil {
		return cfg, runtime, err
	}
	// Publishing here rather than in Start covers Reload with the same line, which matters
	// more than it looks: a report that is only computed once describes a configuration that
	// may have been replaced hours ago, and a stale answer served confidently is a worse
	// failure than the log stream it replaced. CheckConfig deliberately does not come through
	// here -- validating a candidate must not overwrite what the running core decided.
	deviations, deviationErr := collectConfigDeviations(content, currentRuntimePolicy(underNE))
	if deviationErr != nil {
		// The configuration already parsed, so this can only be the deviation walk itself
		// failing. Never fail a start over the report about the start.
		log.Warnln("[Apple] could not compute the configuration deviation report: %v", deviationErr)
	} else {
		publishDeviations(entry, content, deviations)
	}
	return cfg, runtime, nil
}

func parseConfigForIOSInternal(content string, underNE bool, stageRuntime bool) (*config.Config, *providerRuntime, error) {
	if err := validateConfigurationInput(content); err != nil {
		return nil, nil, err
	}
	raw, err := config.UnmarshalRawConfig([]byte(content))
	if err != nil {
		return nil, nil, fmt.Errorf("hako: parse config: %w", err)
	}
	startupStage("bind:unmarshalled")
	canonicalizeProviderDefinitionKeys(raw)
	policy := currentRuntimePolicy(underNE)
	if policy.networkExtension {
		if err := validateRawNetworkExtensionIntentForApple(raw, policy); err != nil {
			return nil, nil, err
		}
	}
	normalizeRawConfigForApple(raw, policy)
	startupStage("bind:normalized")
	applyStoreFakeIPDefault(raw)
	applyUnifiedDelayDefault(raw, configExplicitlySetsUnifiedDelay([]byte(content)))
	startupStage("bind:fakeip-default")
	if err := validateRawConfigForIOS(raw); err != nil {
		return nil, nil, err
	}
	startupStage("bind:ios-validated")
	var runtime *providerRuntime
	if stageRuntime {
		// The extension never compiles — a compile peaks in the hundreds of
		// megabytes and this process has fifty. It serves whatever verdicts a
		// publish left behind, and a set nobody compiled rides as text.
		runtime, err = stageProviderRuntime(raw, policy, false)
		if err != nil {
			return nil, nil, err
		}
	} else {
		stripProviderSideUpdateMetadata(raw)
	}
	startupStage("bind:providers-staged")

	// Quietly: the parser applies the candidate's general to the live core and rolls it back
	// before returning, and the mode stream must not narrate that (see parseRawConfigQuietly).
	cfg, err := parseRawConfigQuietly(raw)
	if err != nil {
		if runtime != nil {
			runtime.close()
		}
		// mihomo's verdict stands; when it refused a Clash-style domain pattern, say which
		// field and which entry, because upstream's own message carries only one of the two.
		return nil, nil, fmt.Errorf("hako: parse config: %w", explainInvalidDomainPatterns(raw, err))
	}
	startupStage("bind:apple-validate-in")
	if err := validateForApple(cfg, raw, policy); err != nil {
		if runtime != nil {
			runtime.close()
		}
		return nil, nil, err
	}
	return cfg, runtime, nil
}

// canonicalizeProviderDefinitionKeys lowercases the top-level keys of every
// provider definition, before anything in this fork reads one.
//
// Provider definitions arrive as the reader's literal YAML -- RawConfig holds
// them as map[string]map[string]any (config/config.go:475-476), untouched by
// the typed decoder -- while upstream's own decoder matches field names
// case-INSENSITIVELY (common/structure/structure.go:522, strings.EqualFold).
// Every guard here that reads definition["type"] or definition["path"] by
// literal lowercase therefore had a bypass spelled `Type:`: this fork saw a
// definition it did not recognize and skipped it, upstream built the provider
// anyway. That gap covered the remote-provider refusal, the http→file
// materialization, side-update safety marking, and all of staging -- which is
// where a file provider's payload is sanitized. One subscription line
// (`Type: file`) delivered an unsanitized payload to the core; another
// (`Type: http`) put a live downloader inside the extension.
//
// Canonicalizing once, here, fixes every one of those readers at the same
// time, which is the point: adding EqualFold to each call site would leave the
// next reader to remember. A key that is already lowercase always wins -- a
// mixed-case duplicate must never overwrite what the reader wrote in the
// canonical spelling, or `Type: http` would beat `type: file`. Only the
// definition's own top level is touched; nested payload values are the
// provider's data, not this fork's control surface.
func canonicalizeProviderDefinitionKeys(raw *config.RawConfig) {
	if raw == nil {
		return
	}
	for _, namespace := range []map[string]map[string]any{raw.ProxyProvider, raw.RuleProvider} {
		for _, definition := range namespace {
			if definition == nil {
				continue
			}
			for key, value := range definition {
				lowered := strings.ToLower(key)
				if lowered == key {
					continue
				}
				if _, exists := definition[lowered]; !exists {
					definition[lowered] = value
				}
				delete(definition, key)
			}
		}
	}
}

// canonicalizeProviderDefinitionKeysInDocument is the free-form-document twin
// of canonicalizeProviderDefinitionKeys, for the App-side entries that walk a
// decoded YAML map rather than a RawConfig (FinalizeForIOS). Same rule, same
// reason: canonical spelling wins, only the definition's own top level moves.
func canonicalizeProviderDefinitionKeysInDocument(root map[string]any) {
	for _, namespace := range []string{"proxy-providers", "rule-providers"} {
		providers, ok := root[namespace].(map[string]any)
		if !ok {
			continue
		}
		for _, raw := range providers {
			definition, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			for key, value := range definition {
				lowered := strings.ToLower(key)
				if lowered == key {
					continue
				}
				if _, exists := definition[lowered]; !exists {
					definition[lowered] = value
				}
				delete(definition, key)
			}
		}
	}
}

// applyStoreFakeIPDefault defaults fake-ip persistence on -- so fake-ip mappings
// survive an NE restart -- but only when the user did not set store-fake-ip
// themselves. Upstream defaults it false (a bounded in-memory pool); silently
// forcing it true over an explicit store-fake-ip:false would convert that into an
// unbounded on-disk record of every resolved domain, overriding a deliberate
// privacy choice. Restart-consistency is a soft UX preference, not an Apple/NE
// requirement, so an explicit value always wins.
func applyStoreFakeIPDefault(raw *config.RawConfig) {
	if raw.Profile.StoreFakeIPSet {
		return
	}
	raw.Profile.StoreFakeIP = true
}

// applyUnifiedDelayDefault defaults unified delay on -- so a probe reports the
// second, comparable round trip instead of billing the whole cold start
// (TCP+TLS+protocol handshake) to whichever proxy was probed first. Upstream
// defaults it false; FlClash ships true, and on device the difference for a
// proxied node is the difference between 900-2400ms and 90-456ms, with numbers
// that cannot be compared across protocols. An explicit true or false always
// wins: the top-level key has no Set flag on RawConfig, so presence comes from
// the caller's typed probe over the document bytes.
func applyUnifiedDelayDefault(raw *config.RawConfig, explicitlySet bool) {
	if explicitlySet {
		return
	}
	raw.UnifiedDelay = true
}

// configExplicitlySetsUnifiedDelay reports whether the document names
// unified-delay. A typed *bool probe distinguishes an explicit false from an
// omitted key (both decode to false in the RawConfig struct) without
// re-marshalling the config.
func configExplicitlySetsUnifiedDelay(content []byte) bool {
	var probe struct {
		UnifiedDelay *bool `yaml:"unified-delay"`
	}
	if err := yaml.Unmarshal(content, &probe); err != nil {
		return false
	}
	return probe.UnifiedDelay != nil
}

// configExplicitlySetsStoreFakeIP reports whether the raw config declares
// profile.store-fake-ip. A typed *bool probe distinguishes an explicit false from
// an omitted key (both decode to false in the RawConfig struct) without
// re-marshalling the config.

func normalizeRawConfigForIOS(raw *config.RawConfig, underNE bool) {
	normalizeRawConfigForApple(raw, runtimePolicyFor(runtimeProfileIOSPacketTunnel, underNE))
}

func normalizeRawConfigForApple(raw *config.RawConfig, policy appleRuntimePolicy) {
	// These values are consumed while ParseRawConfig constructs rules and DNS;
	// applying them to Config afterwards is too late.
	if policy.memoryConservativeGeodata {
		raw.GeodataLoader = "memconservative"
	}
	// Process-wide rather than carried on the config, because the loader is
	// reached from rules and from DNS policies alike and both are built inside
	// ParseRawConfig, below this point.
	geodata.SetCompiledGeoSiteOnly(policy.compiledGeoSiteOnly)
	geodata.SetCompiledGeoIPOnly(policy.compiledGeoIPOnly)
	// Under a packet tunnel, record which geo resource is being built before building it.
	// jetsam runs no handler, so an account written after the fact is an account that
	// never gets written; this is the only thing that survives a kill.
	setStartupBreadcrumbRecording(policy.networkExtension)
	if policy.networkExtension {
		geodata.SetGeodataProgressReporter(recordStartupResource)
	} else {
		geodata.SetGeodataProgressReporter(nil)
	}
	raw.GeoAutoUpdate = false
	raw.GeoXUrl = config.RawGeoXUrl{
		GeoIp:   disabledGeoURL,
		Mmdb:    disabledGeoURL,
		ASN:     disabledGeoURL,
		GeoSite: disabledGeoURL,
	}
	if policy.networkExtension {
		normalizeRawNetworkExtensionSurfaces(raw, policy.processMetadata())
		// Every Network Extension profile is now a Packet Tunnel: the Transparent Proxy
		// profile was removed with its data plane, and the containing-App profile runs
		// outside the extension. The !packetTunnel and useSystemDNS branches that used to
		// live here were reachable only by that profile, so they went with it rather than
		// staying as unreachable code that reads like a supported shape.
		// Packet Tunnel DNS stays inside the core. The two reasons are not the
		// same reason, and neither is "the NE forbids it" -- an earlier wording
		// here said dhcp:// "cannot probe from the extension", which claimed a
		// sandbox rule we never verified and which sing-box contradicts by
		// compiling its DHCP transport into the Apple build
		// (cmd/internal/build_libbox/main.go:67). What is actually true:
		//
		//   - system:// reads the system resolver, which inside a packet tunnel
		//     is NEDNSSettings pointing back at us -- a loop, and NE-specific.
		//   - dhcp:// needs to bind 0.0.0.0:68 (component/dhcp/conn.go:13) and
		//     resolve a physical interface by name (dhcp.go:30). No unprivileged
		//     Apple process can bind a port below 1024, extension or App, so this
		//     is a property of the transport rather than of the sandbox.
		//
		// Both are reasons to strip and warn. Neither is a reason to refuse the
		// configuration, and nothing downstream does any more.
		for _, ns := range stripNEIncompatibleNameservers(raw) {
			// "resolves back through NEDNSSettings" stood here until 2026-08-27 and
			// described a loop upstream does not leave open. Measured on macOS 26.6.1,
			// twice -- the second time with the host's other VPN stopped, so the
			// baseline is a clean one:
			//
			//	tunnel down   /etc/resolv.conf: 119.29.29.29, 223.5.5.5
			//	tunnel up     /etc/resolv.conf: 198.18.0.2          (only)
			//	tunnel up     scutil --dns:     198.18.0.2 on utun9 (Supplemental)
			//	                                119.29.29.29, 223.5.5.5 on en0 (Scoped, Reachable)
			//
			// The machine does not lose its resolvers. They go Scoped, and macOS
			// mirrors only the primary resolver into /etc/resolv.conf, so a scoped one
			// never appears there. dns/system_posix.go:13 reads that FILE, not scutil,
			// so what the system resolver can see is one address -- the tunnel's own.
			//
			// And that address is the one upstream blacklists itself: parseTun narrows
			// the tun prefix to /30 (config.go:1729-1733), sing_tun computes
			// Inet4Address.Addr().Next() (server.go:298) and hands it to
			// AddSystemDnsBlacklist (server.go:489), which getDnsClients skips
			// (system_common.go:26). So a system resolver here does not loop, and it
			// does not fail for want of a working nameserver either. It fails because
			// the only file it is allowed to read has stopped listing the ones that
			// work.
			//
			// That is platform-specific and worth keeping straight: on Linux
			// /etc/resolv.conf is authoritative, on macOS it is a compatibility mirror.
			//
			// That is why the entry goes: not to break a cycle, but because it is a
			// dead nameserver, and leaving it would cost the queries that fall to it.
			// Upstream leaves it dead; this refills instead, which is the deviation --
			// more functional, not stricter, so's principle does not reach it.
			//
			// The dhcp:// half of this sentence is NOT measured. It claims a bind on
			// 0.0.0.0:68 over a physical interface, which is a different mechanism
			// (dns/dhcp.go) and still has no evidence behind it either way.
			log.Warnln("[Apple %s] DNS %s cannot work from a packet tunnel (system resolves only to the tunnel's own DNS address, which mihomo blacklists, so it yields nothing; dhcp:// must bind 0.0.0.0:68 on a physical interface -- unverified); stripped, resolution stays inside the core and the config still starts", policy.profile.String(), ns)
		}
		// There is no "kept as written" warning any more, because nothing is
		// kept: filterBootstrap may hand its list through verbatim, but the
		// repair below runs for every Apple packet tunnel and removes each
		// system/dhcp entry the strip declined to, refilling an emptied
		// bootstrap with mihomo's own defaults. The warning that used to sit
		// here fired one line before the repair falsified it — "kept as
		// written" followed by "was replaced" in the same start.
		if policy.repairPacketTunnelDNS {
			for _, repair := range repairApplePacketTunnelDNS(raw) {
				log.Warnln("[Apple %s] DNS %s", policy.profile.String(), repair)
			}
			// Say what is about to happen, and change nothing about it.
			//
			// With dns.enable false mihomo tears the resolver down entirely and tun goes on
			// hijacking port 53, so hijacked queries reach a server that is not there. This
			// core neither refuses that nor repairs it -- but a packet tunnel is not
			// optional here the way tun is on a desktop, so where a mihomo user can simply
			// not enable tun, a reader here always lands in the combination. Refusing used to
			// tell them something was wrong; accepting silently tells them nothing while
			// every name fails to resolve.
			//
			// A warning is the only response that is neither a refusal nor a repair.
			if !raw.DNS.Enable {
				log.Warnln("[Apple %s] DNS is disabled by this configuration. Inside a packet "+
					"tunnel that means name resolution will not work: the core stops serving "+
					"DNS while the tunnel still captures port 53, which is also what mihomo "+
					"does with tun and dns.enable false. Set dns.enable true to resolve names.",
					policy.profile.String())
			}
		}
		// A nameserver fragment naming a physical interface (or a proxy the
		// static config does not define) cannot be routed by an Apple extension.
		// Keep it verbatim: stripping it could silently reroute DNS to a different
		// proxy or DIRECT. It fails closed per query unless the name materializes.
		for _, ns := range detectUnroutableDNSFragments(raw) {
			log.Warnln("[Apple %s] DNS %s names a physical interface or an unknown proxy in its fragment; kept as-is — it will fail closed at runtime unless the name materializes (config still starts)", policy.profile.String(), ns)
		}
		// Per-proxy interface-name/routing-mark egress overrides cannot take
		// effect (NWPathMonitor owns physical egress) and never change proxy
		// selection — strip them so a proxy carrying one still loads.
		for _, field := range stripOutboundEgressOverrides(raw) {
			log.Warnln("[Apple %s] outbound egress override %s has no Network Extension equivalent and is stripped; the config still starts", policy.profile.String(), field)
		}
		// Owner-metadata rules are KEPT and handed to the upstream parser unchanged.
		//
		// This used to remove the whole rule string, which is wrong twice over. A
		// logic rule is a container, not a condition: upstream's rules/logic/logic.go
		// evaluates OR branch by branch, so `OR,((PROCESS-NAME,x),(DOMAIN-SUFFIX,y))`
		// only needed its PROCESS branch to answer false -- instead the executable
		// DOMAIN-SUFFIX branch went with it and a REJECT silently became whatever the
		// next rule said. A SUB-RULE dispatch line took its whole target group down
		// the same way.
		//
		// And removal was never needed. This fork forces find-process-mode off, which
		// is a value any mihomo user can also write, and upstream under it leaves
		// Process/ProcessPath empty and Uid 0. Every one of the ten kinds then
		// evaluates exactly as upstream does: PROCESS-NAME does not match,
		// PROCESS-NAME-REGEX,.* and PROCESS-NAME-WILDCARD,* do (they match the empty
		// string), and UID,0 does. That last one is upstream's own darwin behaviour
		// rather than an artifact of this platform -- component/process/process_darwin.go
		// returns uid 0 on every path including success. keeps one yardstick, so
		// this core inherits all of it instead of inventing a safer semantics.
		//
		// What the user loses is the resolution itself, and that is already announced
		// once by the find-process-mode notice. These lines name the affected rules.
		capability := policy.processMetadata()
		// UID alone is removed, and not for the reason the other nine were: upstream refuses to
		// CONSTRUCT it off linux/android/darwin, so keeping it fails config.Parse for the whole
		// configuration rather than evaluating to false. See uid_construction_gate.go.
		// Two conditions, deliberately OR'd. The capability is the one that fires in tests: it
		// says "this profile is the iOS packet tunnel", and that profile only ever runs on
		// GOOS=ios in production. The GOOS check is the backstop for the other direction -- if
		// somebody later marks the iOS profile as resolving UID, this still strips on a build
		// where upstream cannot construct the rule, and a wrong capability costs a warning
		// instead of a configuration that will not start.
		//
		// Gating on GOOS alone was the first attempt and it is untestable: the test host is
		// darwin, which upstream allows, so the strip never ran and the tests stayed green for
		// exactly the reason the original bug stayed invisible.
		if !capability.resolves("UID") || !uidRuleConstructible(runtime.GOOS) {
			for _, occurrence := range summarizeOccurrenceList(stripUnconstructibleUIDRules(raw)) {
				log.Warnln("[Apple %s] %s: %s", policy.profile.String(), occurrence, uidRuleExplanation)
			}
		}
		for _, notice := range unguardedControllerNotices(raw) {
			log.Warnln("[Apple %s] %s", policy.profile.String(), notice)
		}
		for _, notice := range unauthenticatedLANListenerNotices(raw) {
			log.Warnln("[Apple %s] %s", policy.profile.String(), notice)
		}
		for _, rule := range summarizeMetadataRuleOccurrences(raw, capability) {
			log.Warnln("[Apple %s] %s: %s", policy.profile.String(), rule, metadataRuleKeptExplanation)
		}
	}
}

// normalizeRawNetworkExtensionSurfaces removes server/listener configuration
// before ParseRawConfig. Clearing only the parsed Config is too late: upstream
// validates external-ui paths and constructs listener/server objects while
// parsing. The packet tunnel consumes proxies, DNS policy, rules and one Hako-
// owned tun; it must never expose user-configured local servers.
// unauthenticatedLANListenerNotices reports a listener the user exposed to the local network
// without credentials. mihomo behaves the same way and this core now does too -- that is the
// point of honouring the field -- but a phone carries its owner onto other people's networks,
// so the blast radius is not a desktop's. Saying so is not the same as refusing.
func unauthenticatedLANListenerNotices(raw *config.RawConfig) []string {
	notices := make([]string, 0, 4)
	// The three shared ports obey allow-lan: without it they sit on 127.0.0.1
	// and reach nobody else (listener/listener.go genAddr).
	if raw.AllowLan && !authenticationCoversRemoteSources(raw) {
		for _, listener := range []struct {
			field string
			port  int
		}{{"port", raw.Port}, {"socks-port", raw.SocksPort}, {"mixed-port", raw.MixedPort}} {
			if listener.port != 0 {
				notices = append(notices, fmt.Sprintf(
					"%s %d is reachable from the local network with allow-lan and no effective authentication: "+
						"any device on any network this one joins can use it as a proxy. Set "+
						"authentication, or lan-allowed-ips, to narrow it",
					listener.field, listener.port))
			}
		}
	}
	// These do NOT obey allow-lan: each carries its own listen address and
	// upstream defaults it to 0.0.0.0 (listener/inbound/base.go), so they are
	// reachable from the local network whether or not allow-lan was ever
	// granted. This core honours them (the zero-squeeze ruling), which makes
	// saying so the whole of the reader's protection.
	if len(raw.Listeners) > 0 {
		notices = append(notices, fmt.Sprintf(
			"listeners declares %d inbound listener(s), each on its own listen address — "+
				"upstream defaults that to 0.0.0.0, and the allow-lan permission does not cover it. "+
				"Every device on every network this one joins can reach them unless each entry "+
				"names a narrower listen address and its own authentication",
			len(raw.Listeners)))
	}
	if len(raw.Tunnels) > 0 {
		notices = append(notices, fmt.Sprintf(
			"tunnels declares %d static tunnel listener(s), which are opened as written and are "+
				"not covered by the allow-lan permission", len(raw.Tunnels)))
	}
	for _, server := range []struct {
		field   string
		present bool
	}{
		{"ss-config", strings.TrimSpace(raw.ShadowSocksConfig) != ""},
		{"vmess-config", strings.TrimSpace(raw.VmessConfig) != ""},
		{"tuic-server", raw.TuicServer.Enable},
	} {
		if server.present {
			notices = append(notices, fmt.Sprintf(
				"%s starts a protocol server on this device, opened as written and not covered by "+
					"the allow-lan permission; its listen address is the one that entry names",
				server.field))
		}
	}
	return notices
}

// authenticationCoversRemoteSources reports whether the configured
// authentication actually applies to a connection arriving from off-device.
//
// skip-auth-prefixes is an allow list that bypasses authentication entirely
// (adapter/inbound/auth.go), so `authentication: [user:pass]` together with
// `skip-auth-prefixes: [0.0.0.0/0]` is an open proxy that reads, to anything
// keyed on "is authentication set", as a protected one. That combination is
// two ordinary-looking lines in a subscription.
func authenticationCoversRemoteSources(raw *config.RawConfig) bool {
	if len(raw.Authentication) == 0 {
		return false
	}
	for _, prefix := range raw.SkipAuthPrefixes {
		if !prefix.Addr().IsLoopback() || prefix.Bits() == 0 {
			return false
		}
	}
	return true
}

// unguardedControllerNotices reports a RESTful API the user exposed beyond loopback with no
// secret. That API can change proxies, rules and mode on a running tunnel, so an unguarded one
// on a shared network is a different thing from an unguarded local proxy. mihomo allows it and
// so do we; the notice never renders the secret itself.
func unguardedControllerNotices(raw *config.RawConfig) []string {
	if raw.Secret != "" {
		return nil
	}
	notices := make([]string, 0, 2)
	for _, endpoint := range []struct {
		field   string
		address string
	}{{"external-controller", raw.ExternalController}, {"external-controller-tls", raw.ExternalControllerTLS}} {
		if endpoint.address == "" || isLoopbackListenAddress(endpoint.address) {
			continue
		}
		// allow-lan is named on purpose, and it was added the day PATCH /configs was opened.
		// Before that the worst an unauthenticated reacher could do was reconfigure someone
		// else's tunnel; now allow-lan is in the PATCH body, so they can make the device serve
		// them -- an open proxy on whatever network it has joined.
		//
		// That is the same exposure the allow-lan permission gate exists to prevent, arriving
		// by a route the gate does not watch: nobody has to write allow-lan in the
		// configuration, and nobody has to agree to anything in the app. Two steps, each
		// unremarkable alone. Closing PATCH would not fix it -- whoever can reach an
		// unauthenticated controller has lighter ways to misuse it -- so the honest response is
		// that this sentence names the worst outcome instead of the tidiest one.
		notices = append(notices, fmt.Sprintf(
			"%s listens on %s with no secret: anything that can reach it can change proxies, "+
				"rules and mode on the running tunnel, and can switch allow-lan on -- which "+
				"makes this device an open proxy for whoever is on the same network. "+
				"Set secret, or bind it to 127.0.0.1",
			endpoint.field, endpoint.address))
	}
	return notices
}

// isLoopbackListenAddress answers for the shapes a listen address is written in. An empty host
// ("​:9090") is NOT loopback -- it binds every interface, which is the case most likely to be
// written by accident.
func isLoopbackListenAddress(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	switch host {
	case "127.0.0.1", "::1", "localhost", "[::1]":
		return true
	default:
		return false
	}
}

func normalizeRawNetworkExtensionSurfaces(raw *config.RawConfig, capability appleProcessMetadataCapability) {
	// allow-lan is the one member of this group that is gated, and not by the platform: it is
	// what moves the listener from 127.0.0.1 to every interface (listener/listener.go:709-718
	// genAddr). Honouring it straight out of an imported subscription would have changed the
	// exposure of already-shipped users with nobody pressing anything. See allow_lan_gate.go
	// for why the permission is a zero-value-safe bool rather than a parameter.
	// Recorded on every parse, next to the line that applies it, and regardless of whether the
	// configuration mentions allow-lan at all.
	//
	// Measured before adding this: of the four combinations of (written, permitted), three left
	// no record. The one that spoke was allow-lan written with permission DENIED -- the safe
	// case. The dangerous state, permission granted, was silent, and a configuration that opens
	// no ports leaves no listen address to read back either. A gate whose failure direction is
	// silent exposure must not also be silent about which way it went.
	//
	// The containing app logs what it TOLD the extension. This is what the kernel HOLDS when it
	// applies the gate. Those two disagreeing is the failure this whole batch kept finding, and
	// only this line can show it.
	permitted := allowLanPermitted.Load()
	log.Infoln("[Apple] allow-lan permitted=%v", permitted)
	if !permitted {
		raw.AllowLan = false
	}
	// The rest of the local proxy surface is honoured as written: port, socks-port, mixed-port,
	// bind-address, authentication, skip-auth-prefixes, lan-allowed-ips,
	// lan-disallowed-ips, inbound-tfo and inbound-mptcp all reach the parser untouched,
	// and hub/executor's updateListeners -- which this fork never modified -- opens them.
	//
	// They used to be zeroed here, justified by "a Network Extension cannot open a listening
	// socket". That claim was false in the one place anybody could check it: this core's own
	// proxy_share.go opens an authenticated mixed listener on 0.0.0.0 in this same process.
	// Apple's actual position is TN3120's "Do not use a packet tunnel provider to host a
	// network listener or proxy server" -- advice, not a mechanism, and the market answers it
	// plainly: Shadowrocket ships exactly this from a sandboxed packet tunnel on the Mac App
	// Store, declaring NSLocalNetworkUsageDescription "Use local networking to provice local
	// proxy service" in the extension's own Info.plist, importing listen/bind/accept, and
	// carrying com.apple.security.network.server. sing-box and hakosfm carry that entitlement
	// too. Following the advice was a product choice; it was written down as a platform wall,
	// and a wall is never revisited.
	//
	// macOS needs com.apple.security.network.server for any of this to bind -- see
	// application.sb:111 and :753-761. That entitlement lives in the client project and is
	// tracked as T-1; without it the listener fails closed on macOS rather than misbehaving.
	//
	// Still cleared below: redir-port and tproxy-port (no Apple facility exists), the
	// protocol-server surfaces, and the RESTful API. Those are separate decisions with their
	// own reasons, not this one.
	// Only the two ports no Apple platform can serve. redir-port needs /dev/pf and root;
	// tproxy-port is refused by upstream's own non-Linux build. Everything else in the inbound
	// server surface is honoured as written.
	//
	// ss-config, vmess-config, tuic-server, listeners and tunnels used to go here too, under a
	// ledger note that said "the capability is proven by this core's own proxy_share.go; not
	// opening it is a product decision". That sentence was the entire case, and the standard is
	// now stated: upstream allows it and the platform allows it, therefore it is allowed. Not
	// "we think the user should not use it this way", not "that is a different product form".
	// The only exception left is App Review actually refusing the surface, on the evidence of
	// the review text.
	raw.RedirPort = 0
	raw.TProxyPort = 0

	// The physical egress is selected by NWPathMonitor plus the Apple socket
	// hook. A YAML interface/mark would overwrite that state in updateGeneral,
	// including on Reload; routing marks are not an iOS routing primitive. The
	// tun UID/package/MAC/port filters and auto-redirect/iproute2 marks are
	// host-route-manager primitives the NE has no equivalent for. None of these
	// change which proxy handles a flow, so strip them (tolerate + strip) rather
	// than reject the config, and warn once per knob so the drop is visible.
	for _, knob := range strippedHostRouteKnobs(raw) {
		log.Warnln("[Apple NetworkExtension] %s has no Network Extension equivalent and is stripped; the config still starts", knob)
	}
	raw.Interface = ""
	raw.RoutingMark = 0
	// find-process-mode is forced Off only where nothing in this process can name the
	// owner of a connection. That is iOS. On a macOS Packet Tunnel mihomo resolves it
	// itself from the socket table -- it never asks the Network Extension -- so the
	// configured value stands, and mihomo's own default of Strict means the lookup runs
	// only when a rule actually needs it.
	if !capability.processPath {
		raw.FindProcessMode = process.FindProcessOff
	}
	raw.Tun.AutoRedirect = false
	raw.Tun.IPRoute2TableIndex = 0
	raw.Tun.IPRoute2RuleIndex = 0
	raw.Tun.AutoRedirectInputMark = 0
	raw.Tun.AutoRedirectOutputMark = 0
	raw.Tun.AutoRedirectIPRoute2FallbackRuleIndex = 0
	raw.Tun.IncludeInterface = nil
	raw.Tun.ExcludeInterface = nil
	raw.Tun.IncludeUID = nil
	raw.Tun.IncludeUIDRange = nil
	raw.Tun.ExcludeUID = nil
	raw.Tun.ExcludeUIDRange = nil
	raw.Tun.ExcludeSrcPort = nil
	raw.Tun.ExcludeSrcPortRange = nil
	raw.Tun.ExcludeDstPort = nil
	raw.Tun.ExcludeDstPortRange = nil
	raw.Tun.IncludeAndroidUser = nil
	raw.Tun.IncludePackage = nil
	raw.Tun.ExcludePackage = nil
	raw.Tun.IncludeMACAddress = nil
	raw.Tun.ExcludeMACAddress = nil

	// The RESTful API is honoured as written, by the same rule as the listener surface: a
	// shipping Mac App Store app carries it (sing-box.app's core contains clash_api,
	// external_controller, external_ui and secret), so the platform is not the obstacle. It
	// stays opt-in exactly as upstream has it -- a config that never names external-controller
	// gets no API, which is mihomo's own default.
	//
	// external-ui is HONOURED, not stripped. This paragraph used to say it "still goes" on
	// grounds (external-ui triggers AutoDownloadUI inside the extension) -- and the code
	// never cleared it, which made the comment the only thing claiming a strip. The claim was
	// also wrong by then: external-ui was deliberately opened, and the defect that followed was
	// the opposite one -- the dashboard was downloaded and then NOT served, because only half of
	// upstream's applyRoute had been ported. external_ui_served_test.go pins the whole behaviour.
	//
	// Recorded because chasing a community template's `external-ui: /usr/share/zashboard` led
	// straight back here, and reading this paragraph alone would have justified clearing a field
	// the product means to support.
	//
	// SO_MARK does not exist on Darwin; a Windows named pipe is a Windows facility.
	raw.ExternalControllerRoutingMark = 0
	raw.ExternalControllerPipe = ""

	// Inbound TLS material. Its only consumers are the listeners cleared above, so nothing used
	// it -- but the disposition catalog labelled these five "strip" with no code stripping them,
	// which is a claim nothing can verify and one that turns false the moment a consumer appears.
	// tls.private-key is also credential material, and it has no business sitting in a parsed
	// config that gets logged and diffed.
	//
	// raw.TLS.CustomTrustCert is deliberately NOT cleared: hub/executor/executor.go feeds it to
	// component/ca as additional trust anchors, so it is an OUTBOUND verification input and the
	// one live field in this struct. It layers on top of whichever certificate store is selected
	// which means with `store: none` it becomes the only trust source.
	// tls.* is no longer stripped. It was stripped on the stated ground that its only consumer
	// -- the configured inbound listeners -- was stripped with it. The controller listener is
	// back (external_controller.go), and upstream feeds exactly these five fields to it
	// (hub/hub.go:71-75), so external-controller-tls without a certificate would be a listener
	// that cannot start. The ground for stripping them is gone with the ground for stripping
	// the listener.
	//
	// tls.private-key is credential material. It is not logged and it is withheld from the
	// deviation report; being carried in a parsed config is what any consumer needs.
	raw.IPTables.Enable = false
	// dns.listen is honoured. It was the last field held back by a judgement rather than a
	// platform fact: the address itself carries the exposure, so unlike allow-lan there is no
	// boolean to put behind the permission, and the note on record proposed gating it anyway --
	// which could only have meant rewriting 0.0.0.0 to 127.0.0.1, inventing a value the user
	// never wrote. hub/executor/executor.go:362 hands it to dns.ReCreateServer on every apply,
	// and dns/server.go:84-110 binds UDP and TCP there. If the host refuses the bind (a
	// privileged port being the obvious case) dns/server.go:87 logs it and the tunnel starts
	// anyway, which is what desktop mihomo does on any non-root machine.
	//
	// The mark that travels with it does not survive: SO_MARK is Linux-only and iPhoneOS's
	// sys/socket.h does not define it, so no value here can reach a kernel with a place to put
	// it. That is the line the ruling draws -- platform walls stay, guesses about intent go.
	raw.DNS.ListenRoutingMark = 0
	// Keep mihomo's NTP offset service (protocol handshakes can consume it),
	// but an extension must not attempt to change the device system clock.
	raw.NTP.WriteToSystem = false
}

// strippedHostRouteKnobs lists the host-route knobs present in raw that iOS
// cannot execute and normalizeRawNetworkExtensionSurfaces therefore strips. The
// names drive a per-knob warning so the operator sees which desktop/Android
// routing primitive was dropped (the config still starts — tolerate + strip).
// find-process-mode is intentionally omitted here: upstream's DefaultRawConfig seeds it to
// FindProcessStrict, so warning on it would fire for every config. (The older wording said
// "a non-zero value", which is wrong -- FindProcessStrict is the iota zero. The reason still
// holds, because what makes the warning useless is that every config carries the default,
// not what the default's numeric value happens to be.) It is forced Off
// silently, matching overrideForIOS.
func strippedHostRouteKnobs(raw *config.RawConfig) []string {
	knobs := make([]string, 0, 8)
	if raw.Interface != "" {
		knobs = append(knobs, "interface-name")
	}
	if raw.RoutingMark != 0 {
		knobs = append(knobs, "routing-mark")
	}
	tun := raw.Tun
	if tun.AutoRedirect {
		knobs = append(knobs, "tun.auto-redirect")
	}
	if tun.IPRoute2TableIndex != 0 || tun.IPRoute2RuleIndex != 0 ||
		tun.AutoRedirectInputMark != 0 || tun.AutoRedirectOutputMark != 0 ||
		tun.AutoRedirectIPRoute2FallbackRuleIndex != 0 {
		knobs = append(knobs, "tun.iproute2/auto-redirect marks")
	}
	if len(tun.IncludeInterface) > 0 || len(tun.ExcludeInterface) > 0 {
		knobs = append(knobs, "tun.include-interface/exclude-interface")
	}
	if len(tun.IncludeUID) > 0 || len(tun.IncludeUIDRange) > 0 ||
		len(tun.ExcludeUID) > 0 || len(tun.ExcludeUIDRange) > 0 {
		knobs = append(knobs, "tun.include-uid/exclude-uid")
	}
	if len(tun.IncludeAndroidUser) > 0 || len(tun.IncludePackage) > 0 || len(tun.ExcludePackage) > 0 {
		knobs = append(knobs, "tun.include-android-user/include-package/exclude-package")
	}
	if len(tun.IncludeMACAddress) > 0 || len(tun.ExcludeMACAddress) > 0 {
		knobs = append(knobs, "tun.include-mac-address/exclude-mac-address")
	}
	if len(tun.ExcludeSrcPort) > 0 || len(tun.ExcludeSrcPortRange) > 0 ||
		len(tun.ExcludeDstPort) > 0 || len(tun.ExcludeDstPortRange) > 0 {
		knobs = append(knobs, "tun.exclude-src-port/exclude-dst-port")
	}
	return knobs
}

// isNEIncompatibleNameserver reports whether a raw DNS nameserver string names a
// scheme the Network Extension cannot consume: system:// (uses the OS resolver,
// so it can bypass the tunnel) or dhcp:// (needs a DHCP probe the sandbox
// forbids). It mirrors config.parseNameServer's scheme detection —
// parsePureDNSServer rewrites a bare "system" to "system://", and "dhcp://system"
// is a dhcp entry mihomo maps to system, so stripping either is correct. A
// nameserver whose fragment merely contains "system" (e.g. https://…#system, a
// proxy name) is NOT matched, because the scheme prefix does not apply.
func isNEIncompatibleNameserver(server string) bool {
	s := strings.ToLower(strings.TrimSpace(server))
	return s == "system" || strings.HasPrefix(s, "system:") || strings.HasPrefix(s, "dhcp:")
}

// isUsableBootstrapNameserver reports whether a raw default-nameserver entry is
// a genuine pure-IP bootstrap resolver — the only kind mihomo accepts there
// ("default nameserver should be pure IP", config.go). It excludes system/dhcp
// and anything without a real IP host: "", ":53", "udp://:53", or a hostname.
// This closes the hole where mihomo's own pure-IP check lets a hostless ":53"
// through (url.Parse(":53") errors, so the rejection is skipped). It is the
// shared predicate for deciding whether stripping leaves a usable bootstrap.
func isUsableBootstrapNameserver(server string) bool {
	s := strings.TrimSpace(server)
	if s == "" || isNEIncompatibleNameserver(s) {
		return false
	}
	// Scheme forms (https://1.1.1.1/dns-query, tls://1.1.1.1, quic://[2401::1]:853):
	// mihomo validates the URL host, so parse it out and require an IP — a path or
	// fragment on the URL must not defeat the check.
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil && net.ParseIP(u.Hostname()) != nil {
			return true
		}
		return false
	}
	// Bare form: host, host:port, [ipv6], or [ipv6]:port.
	host := s
	if h, _, err := net.SplitHostPort(s); err == nil {
		host = h // had a port
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	return net.ParseIP(host) != nil
}

// stripNEIncompatibleNameservers filters system/dhcp entries out of the DNS
// resolver lists (nameserver, fallback, proxy-server-nameserver,
// direct-nameserver, default-nameserver) so the config starts (tolerate +
// strip); resolution then stays inside the core. default-nameserver is the
// bootstrap resolver and is special two ways. Stripping it to EMPTY would
// refuse the config -- an explicit list overwrites mihomo's prefilled defaults
// and mihomo requires at least one entry (config/config.go:1453-1454) -- so
// system/dhcp entries are stripped only while a usable pure-IP resolver
// remains (filterBootstrap). When none remains, the list passes through
// verbatim WITHOUT a report: repairApplePacketTunnelDNS runs next on every
// Apple packet tunnel, removes each system/dhcp entry this pass declined to,
// refills an emptied bootstrap with mihomo's own defaults, and its repair
// descriptions are the user-facing story. This function used to report kept
// entries on a second channel so the caller could warn "kept as written" --
// a warning the repair falsified one line later, every time.
//
// Returns per-entry "<field> <entry>" descriptions for the entries stripped
// here; repair reporting belongs to the repair.
func stripNEIncompatibleNameservers(raw *config.RawConfig) []string {
	stripped := []string{}
	filter := func(field string, list []string) []string {
		kept := make([]string, 0, len(list))
		for _, ns := range list {
			if isNEIncompatibleNameserver(ns) {
				stripped = append(stripped, field+" "+ns)
				continue
			}
			kept = append(kept, ns)
		}
		return kept
	}
	// filterBootstrap is filter for default-nameserver: it strips system/dhcp
	// only while a usable PURE-IP bootstrap remains. If stripping would leave
	// no usable bootstrap, the original list is returned unchanged -- emptying
	// it would trip mihomo's own "at least one nameserver" rule
	// (config/config.go:1453-1454). The pass-through is deliberately silent:
	// repairApplePacketTunnelDNS follows on every Apple packet tunnel, removes
	// those entries itself and reports what it substituted.
	filterBootstrap := func(field string, list []string) []string {
		kept := make([]string, 0, len(list))
		var pending []string
		usable := false
		for _, ns := range list {
			if isNEIncompatibleNameserver(ns) {
				pending = append(pending, field+" "+ns)
				continue
			}
			kept = append(kept, ns)
			if isUsableBootstrapNameserver(ns) {
				usable = true
			}
		}
		if !usable {
			return list
		}
		stripped = append(stripped, pending...)
		return kept
	}
	raw.DNS.NameServer = filter("nameserver", raw.DNS.NameServer)
	raw.DNS.Fallback = filter("fallback", raw.DNS.Fallback)
	raw.DNS.ProxyServerNameserver = filter("proxy-server-nameserver", raw.DNS.ProxyServerNameserver)
	raw.DNS.DirectNameServer = filter("direct-nameserver", raw.DNS.DirectNameServer)
	raw.DNS.DefaultNameserver = filterBootstrap("default-nameserver", raw.DNS.DefaultNameserver)
	// nameserver policies (split-DNS) get the same treatment: system/dhcp
	// entries are stripped from each policy value; a policy whose resolvers all
	// strip is removed, so its domains fall through to the main nameserver.
	stripped = append(stripped, filterPolicyNameservers("nameserver-policy", raw.DNS.NameServerPolicy)...)
	stripped = append(stripped, filterPolicyNameservers("proxy-server-nameserver-policy", raw.DNS.ProxyServerNameserverPolicy)...)
	return stripped
}

func isDHCPNameserver(server string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(server)), "dhcp:")
}

// repairApplePacketTunnelDNS converts an ordinary upstream mihomo config into
// a self-contained Packet Tunnel DNS configuration: configs that relied on
// system DNS, or on mihomo's default of not enabling DNS at all, start by
// substituting mihomo's own explicit defaults. The substitutions are visible
// warnings and never reintroduce system:// or dhcp:// into the tunnel.
//
// Both Apple packet tunnels run this. It was macOS-only for two weeks, which is
// how the same subscription could start on a Mac and refuse on an iPhone.
func repairApplePacketTunnelDNS(raw *config.RawConfig) []string {
	repairs := []string{}
	defaults := config.DefaultRawConfig().DNS

	bootstrap := make([]string, 0, len(raw.DNS.DefaultNameserver))
	for _, server := range raw.DNS.DefaultNameserver {
		if isNEIncompatibleNameserver(server) {
			repairs = append(repairs, "default-nameserver system/dhcp bootstrap was replaced with explicit core bootstrap resolvers")
			continue
		}
		bootstrap = append(bootstrap, server)
	}
	if len(bootstrap) == 0 {
		bootstrap = append([]string(nil), defaults.DefaultNameserver...)
		if len(raw.DNS.DefaultNameserver) == 0 {
			repairs = append(repairs, "default-nameserver was empty and received explicit core bootstrap resolvers")
		}
	}
	raw.DNS.DefaultNameserver = bootstrap

	// dns.enable is the ONE field this product requires. Everything downstream of it --
	// every other key, every resolution behaviour -- stays byte-identical to mihomo
	// . This is a product decision about which configurations can run on an Apple
	// packet tunnel, not this core deciding it knows better than upstream, which is the
	// class rejected.
	//
	// Traced end to end in v1.19.29, because "the NE needs DNS" was asserted here for
	// months without one:
	//
	//	dns.enable false -> updateDNS sets DefaultService = nil    (executor.go:238-247)
	//	                 -> ServeMsg returns ErrIPNotFound         (resolver/service.go:16-22)
	//	                 -> relayDnsPacket answers SERVFAIL        (resolver/relay.go:79-90)
	//
	// and the hijack feeding it is unconditional: ShouldHijackDns matches any port 53
	// target against 0.0.0.0:53 (sing_tun/dns.go:21-27) and never asks whether a resolver
	// exists. So inside a tunnel this is not "DNS falls back to the system" -- it is every
	// query answering SERVFAIL, deterministically.
	//
	// A desktop mihomo user reaches that only by enabling tun and can step back out. An
	// Apple packet tunnel is always a tunnel, so the combination is always reached and
	// there is no step back. Enabling DNS is what makes the product function at all.
	//
	// Minimal on purpose: this sets enable and nothing else, only under a packet tunnel,
	// and says so in the log rather than doing it quietly.
	if !raw.DNS.Enable {
		raw.DNS.Enable = true
		repairs = append(repairs, "was enabled because an Apple packet tunnel always captures "+
			"port 53: with dns.enable false the core serves no DNS and every hijacked query "+
			"answers SERVFAIL, so the tunnel would start and resolve nothing")
	}
	if len(raw.DNS.NameServer) == 0 {
		raw.DNS.NameServer = append([]string(nil), defaults.NameServer...)
		repairs = append(repairs, "nameserver was empty after Apple normalization and received mihomo's explicit core defaults")
	}
	if raw.DNS.RespectRules && len(raw.DNS.ProxyServerNameserver) == 0 {
		raw.DNS.ProxyServerNameserver = append([]string(nil), bootstrap...)
		repairs = append(repairs, "proxy-server-nameserver was empty with respect-rules and received explicit bootstrap resolvers")
	}
	if raw.DNS.ProxyServerNameserverPolicy != nil && raw.DNS.ProxyServerNameserverPolicy.Oldest() != nil && len(raw.DNS.ProxyServerNameserver) == 0 {
		raw.DNS.ProxyServerNameserver = append([]string(nil), bootstrap...)
		repairs = append(repairs, "proxy-server-nameserver was empty with a policy and received explicit bootstrap resolvers")
	}
	return repairs
}

func filterPolicyNameservers(field string, policy *orderedmap.OrderedMap[string, any]) []string {
	if policy == nil {
		return nil
	}
	stripped := []string{}
	type policyEdit struct {
		key    string
		value  any
		remove bool
	}
	edits := []policyEdit{}
	for pair := policy.Oldest(); pair != nil; pair = pair.Next() {
		servers := dnsServerStrings(pair.Value)
		if len(servers) == 0 {
			continue
		}
		kept := make([]any, 0, len(servers))
		removed := false
		for _, ns := range servers {
			if isNEIncompatibleNameserver(ns) {
				stripped = append(stripped, field+" "+pair.Key+" "+ns)
				removed = true
				continue
			}
			kept = append(kept, ns)
		}
		if !removed {
			continue
		}
		if len(kept) == 0 {
			// Deleting the key would leak these domains to the main (public)
			// resolver — the opposite of the split-DNS intent. Fail closed
			// instead: the domain resolves NXDOMAIN until the user supplies an
			// iOS-usable resolver.
			edits = append(edits, policyEdit{key: pair.Key, value: []any{"rcode://name_error"}})
		} else {
			edits = append(edits, policyEdit{key: pair.Key, value: kept})
		}
	}
	for _, edit := range edits {
		if edit.remove {
			policy.Delete(edit.key)
		} else {
			policy.Set(edit.key, edit.value)
		}
	}
	return stripped
}

// knownDNSFragmentProxies lists the names a DNS nameserver fragment may validly
// select on iOS: built-in policies plus statically configured proxies/groups.
func knownDNSFragmentProxies(raw *config.RawConfig) map[string]struct{} {
	known := map[string]struct{}{
		"DIRECT": {}, "REJECT": {}, "REJECT-DROP": {}, "COMPATIBLE": {},
		"PASS": {}, "PASS-RULE": {}, "GLOBAL": {}, dns.RespectRules: {},
	}
	for _, proxy := range raw.Proxy {
		if name, _ := proxy["name"].(string); name != "" {
			known[name] = struct{}{}
		}
	}
	for _, group := range raw.ProxyGroup {
		if name, _ := group["name"].(string); name != "" {
			known[name] = struct{}{}
		}
	}
	return known
}

// stripDNSFragmentName removes the proxy/interface NAME segment from a DNS
// nameserver fragment while preserving key=value params (e.g. h3=true), so
// "https://1.1.1.1/dns-query#en0&h3=true" → "https://1.1.1.1/dns-query#h3=true".
func stripDNSFragmentName(server string) string {
	base, fragment, found := strings.Cut(server, "#")
	if !found {
		return server
	}
	kept := []string{}
	for _, component := range strings.Split(fragment, "&") {
		if strings.Contains(component, "=") {
			kept = append(kept, component)
		}
	}
	if len(kept) == 0 {
		return base
	}
	return base + "#" + strings.Join(kept, "&")
}

// detectUnroutableDNSFragments lists fragments that name something iOS cannot
// statically route — a physical interface (en0) or a proxy the static config
// does not define. Detection only, NEVER mutation: stripping the name could
// silently reroute DNS to a different proxy or DIRECT (a privacy change), so
// the fragment is kept and the resolver fails closed at runtime unless the
// name materializes (e.g. a provider-supplied proxy).
func detectUnroutableDNSFragments(raw *config.RawConfig) []string {
	known := knownDNSFragmentProxies(raw)
	stripped := []string{}
	rewrite := func(field string, list []string) {
		for index, server := range list {
			name := dnsFragmentProxyName(server)
			if name == "" {
				continue
			}
			if _, ok := known[name]; ok {
				continue
			}
			stripped = append(stripped, field+" "+server)
			_ = index
		}
	}
	rewrite("nameserver", raw.DNS.NameServer)
	rewrite("fallback", raw.DNS.Fallback)
	rewrite("default-nameserver", raw.DNS.DefaultNameserver)
	rewrite("proxy-server-nameserver", raw.DNS.ProxyServerNameserver)
	rewrite("direct-nameserver", raw.DNS.DirectNameServer)
	for field, policy := range map[string]*orderedmap.OrderedMap[string, any]{
		"nameserver-policy":              raw.DNS.NameServerPolicy,
		"proxy-server-nameserver-policy": raw.DNS.ProxyServerNameserverPolicy,
	} {
		if policy == nil {
			continue
		}
		// Detection only, like the rest of this function. A leftover rewrite
		// skeleton used to sit here (an edits list applied via policy.Set,
		// guarded by a `changed` flag nothing ever raised). It was dead -- and
		// armed: the plan now reads a ConfigDocument's shared views, so the
		// day someone revived that flag, concurrent plan/projection calls
		// would become lock-free writes to a shared ordered map. Removed
		// rather than left as a landmine.
		for pair := policy.Oldest(); pair != nil; pair = pair.Next() {
			for _, server := range dnsServerStrings(pair.Value) {
				name := dnsFragmentProxyName(server)
				if name == "" {
					continue
				}
				if _, ok := known[name]; ok {
					continue
				}
				stripped = append(stripped, field+" "+pair.Key+" "+server)
			}
		}
	}
	return stripped
}

// stripOutboundEgressOverrides deletes per-proxy interface-name / routing-mark
// egress overrides from every outbound map (proxies, proxy-groups, and each
// proxy-provider override + inline payload item). Like the top-level
// interface/mark, the NE selects its physical egress via NWPathMonitor, so these
// never take effect and never change which proxy handles a flow — strip them
// (tolerate + strip) rather than reject the config. Returns the stripped field
// locations for a per-entry warning.
func stripOutboundEgressOverrides(raw *config.RawConfig) []string {
	stripped := []string{}
	forEachOutboundMapping(raw, func(location string, mapping map[string]any) {
		for _, key := range []string{"interface-name", "routing-mark"} {
			if value, exists := mapping[key]; exists && !isZeroish(value) {
				delete(mapping, key)
				stripped = append(stripped, location+"."+key)
			}
		}
	})
	return stripped
}

func validateRawConfigForIOS(raw *config.RawConfig) error {
	// Global and per-group duration ranges are no longer judged:
	// keep-alive-idle, keep-alive-interval, dns.cache-max-size and a group's
	// interval are bare ints in upstream's RawConfig, read as given.
	// The transport-option value checks that used to run here are gone,
	// and the sentence that stood here to justify it was wrong. It said "not one
	// of them was a check upstream makes". Seven of the seventeen were mixed,
	// and the reasoning that missed them is worth keeping visible: the evidence
	// offered was utils.StringToBps returning 0 without an error -- true, and
	// the next function down is HysteriaOption.Speed (hysteria.go:131-143),
	// which turns that 0 into "invaild upload speed" and refuses the
	// configuration. One function short of the answer.
	//
	// The line upstream actually draws is between parsing and range: it REFUSES
	// what it cannot parse and CLAMPS what parses but sits out of range.
	// hysteria2.go:280-291 does both in six lines. Deleting the clamped half was
	// 's point and stands. The refused half now lives in the plan, as
	// upstreamRefusedOutboundOption -- which calls upstream's own parsers and
	// reports upstream's own error text, so it cannot become stricter than
	// upstream on its own.
	//
	// Nothing is re-added HERE, on purpose. mihomo's parse runs a few lines
	// below and produces the same verdict with the same words; a second copy
	// would only be a second thing to drift. What was actually broken was the
	// plan telling a user their configuration was fine when it was not, and
	// that is where the fix belongs. Found by Codex 2026-08-27.
	if err := validateRawProxyGroupRegexForIOS(raw.ProxyGroup); err != nil {
		return err
	}
	if err := validateRawProvidersForIOS("proxy-provider", raw.ProxyProvider); err != nil {
		return err
	}
	if err := validateRawProvidersForIOS("rule-provider", raw.RuleProvider); err != nil {
		return err
	}
	return validateGeodataFilesForIOS(raw)
}

func validateRawProxyGroupRegexForIOS(groups []map[string]any) error {
	for index, group := range groups {
		for _, field := range []string{"filter", "exclude-filter"} {
			value, ok := group[field].(string)
			if !ok || value == "" {
				continue
			}
			for _, expression := range strings.Split(value, "`") {
				if _, err := regexp2.Compile(expression, regexp2.None); err != nil {
					// Do not echo the user-controlled expression into logs. The
					// indexed field path is sufficient for an editor to locate it.
					// refusal-id: ConfigPipeline.proxyGroupFilterRegex
					return fmt.Errorf("hako: proxy-groups[%d].%s is not a valid regular expression", index, field)
				}
			}
		}
	}
	return nil
}

func validateRawProvidersForIOS(kind string, providers map[string]map[string]any) error {
	names := make([]string, 0, len(providers))
	for name := range providers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		provider := providers[name]
		if kind == "proxy-provider" {
			if err := validateProxyProviderHealthCheck(name, provider); err != nil {
				return err
			}
		}
		typeName, _ := provider["type"].(string)
		if strings.EqualFold(typeName, "http") {
			// refuses a provider that would fetch during parse, and the
			// reason is measured: parse-time network I/O blocks or blows the
			// ~50 MiB extension ceiling. That reason cannot reach a url this
			// build could never issue a request for. url.Parse fails, the
			// vehicle errors before any socket, and upstream logs it and rides
			// empty (hub/executor/executor.go:400-411).
			//
			// So this asks the SAME question the finalize layer asks, with the
			// same predicate. config_finalize.go:228-232 already skips a
			// provider whose url normalizeResourceURL rejects, and its comment
			// says the definition "reaches the kernel, which fails its download
			// and rides empty, exactly as upstream does" -- while this line
			// refused the whole configuration two steps later and made that
			// sentence false. aligned the plan and left this half
			// standing; Codex found it on 2026-08-27.
			//
			// A provider with a usable url is still refused, and must be: that
			// one really would open a socket during parse, and the app was
			// asked to download it precisely so it does not have to.
			// No `rawURL != ""` guard here either: an absent url is the
			// clearest case of a url no request can be made from, and skipping
			// the question for it left this layer refusing a provider the other
			// two had already decided to tolerate.
			rawURL, _ := provider["url"].(string)
			_, urlErr := normalizeResourceURL(rawURL, "provider")
			usableURL := urlErr == nil
			if !usableURL {
				continue
			}
			// refusal-id: ConfigPipeline.remoteProviderNotPreDownloaded
			return fmt.Errorf("hako: %s %q is remote (HTTP) — pre-download it app-side and use a file provider", kind, name)
		}
	}
	return nil
}

func validateProxyProviderHealthCheck(name string, provider map[string]any) error {
	raw, exists := provider["health-check"]
	if !exists {
		return nil
	}
	healthCheck, ok := raw.(map[string]any)
	if !ok {
		// The upstream typed decoder owns shape diagnostics. Duration checks are
		// only needed before its signed-to-unsigned conversions.
		return nil
	}
	// timeout is no longer judged. Upstream accepts a negative one -- measured
	// against config.ParseRawConfig, not read -- and adapter/provider/parser.go:71
	// hands it to NewHealthCheck as uint(schema.HealthCheck.TestTimeout), where
	// it becomes a very large timeout rather than anything that fails. A check
	// that never times out costs that provider's health results; it does not
	// cost the user every other line of their configuration, and upstream lets
	// them have it. Found by Codex 2026-08-27.
	//
	// interval stays, and the reason is NOT that upstream refuses it -- upstream
	// accepts that too. It is that nobody has established what upstream DOES
	// with it. adapter/provider/parser.go:69 converts it the same way, and the
	// result reaches time.NewTicker (healthcheck.go:47) and pause.RegisterTicker
	// (:71); a huge duration and a negative one behave very differently there,
	// and "upstream accepts it at parse" says nothing about which this becomes.
	// Refusing something unmeasured is not the same as refusing something
	// upstream tolerates, so it stays until someone measures it. Registered as
	// unverified rather than left looking settled.
	fields := []struct {
		name      string
		unit      time.Duration
		unitLabel string
	}{
		{name: "interval", unit: time.Second, unitLabel: "second"},
	}
	for _, field := range fields {
		if _, err := providerDurationUnits(healthCheck[field.name], field.unit, "health-check "+field.name, field.unitLabel); err != nil {
			// refusal-id: ConfigPipeline.providerHealthCheckInterval
			return fmt.Errorf("hako: proxy-provider %q health-check.%s: %w", name, field.name, err)
		}
	}
	return nil
}

type geodataRequirements struct {
	geoIP   bool
	geoSite bool
	asn     bool
}

var geodataRuleToken = regexp.MustCompile(`(?i)(?:^|\()\s*(GEOIP|SRC-GEOIP|GEOSITE|IP-ASN|SRC-IP-ASN)\s*,\s*([^,()]*)`)

func validateGeodataFilesForIOS(raw *config.RawConfig) error {
	required := requiredGeodata(raw)
	if required.geoIP {
		path := C.Path.MMDB()
		if raw.GeodataMode {
			path = C.Path.GeoIP()
		}
		if err := requirePrestagedFile("GeoIP", path); err != nil {
			return err
		}
	}
	if required.geoSite {
		if err := requirePrestagedFile("GeoSite", C.Path.GeoSite()); err != nil {
			return err
		}
		// The App validated this file before publishing it (immutable
		// revisions, ValidateGeodataForIOS), so mihomo's own health check is
		// redundant here — and it is the single most expensive allocation a
		// geosite config makes: Verify builds the whole CN matcher (~90k
		// domains, ~14 MiB retained) whether or not any rule names CN. Both
		// 2026-08-01 TestFlight subscriptions ask for `gfw` alone, and the
		// extension died at jetsam's per-process limit with that matcher
		// aboard. Marking it verified makes mihomo load exactly the codes the
		// configuration names; a corrupt file still fails those loads and the
		// config still refuses to start.
		geodata.MarkGeoSiteVerified()
	}
	if required.asn {
		if err := requirePrestagedFile("ASN", C.Path.ASN()); err != nil {
			return err
		}
	}
	return nil
}

func requirePrestagedFile(kind, path string) error {
	if path == "" {
		return fmt.Errorf("hako: %s geodata path is unavailable; call Setup before Start", kind)
	}
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("hako: required %s geodata is not pre-staged at %s (NE downloads are disabled)", kind, path)
		}
		return fmt.Errorf("hako: stat %s geodata at %s: %w", kind, path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("hako: required %s geodata at %s is not a regular file", kind, path)
	}
	return nil
}

func requiredGeodata(raw *config.RawConfig) geodataRequirements {
	var required geodataRequirements
	for _, line := range raw.Rule {
		markRuleGeodata(line, &required)
	}
	for _, rules := range raw.SubRules {
		for _, line := range rules {
			markRuleGeodata(line, &required)
		}
	}
	for _, line := range raw.DNS.FakeIPFilter {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "geosite:") {
			required.geoSite = true
		} else {
			markRuleGeodata(line, &required)
		}
	}
	if len(raw.DNS.Fallback) > 0 {
		required.geoIP = required.geoIP || raw.DNS.FallbackFilter.GeoIP
		required.geoSite = required.geoSite || len(raw.DNS.FallbackFilter.GeoSite) > 0
	}
	markPolicyGeosite(raw.DNS.NameServerPolicy, &required)
	markPolicyGeosite(raw.DNS.ProxyServerNameserverPolicy, &required)
	return required
}

func markRuleGeodata(line string, required *geodataRequirements) {
	for _, match := range geodataRuleToken.FindAllStringSubmatch(line, -1) {
		switch strings.ToUpper(match[1]) {
		case "GEOIP", "SRC-GEOIP":
			// Upstream NewGEOIP lower-cases the country and returns before any
			// geodata file access when it is "lan" (Match evaluates lan via a pure
			// netip predicate), so GEOIP/SRC-GEOIP,lan needs no pre-staged database.
			if strings.ToLower(strings.TrimSpace(match[2])) != "lan" {
				required.geoIP = true
			}
		case "GEOSITE":
			required.geoSite = true
		case "IP-ASN", "SRC-IP-ASN":
			required.asn = true
		}
	}
}

func markPolicyGeosite(policy *orderedmap.OrderedMap[string, any], required *geodataRequirements) {
	if policy == nil {
		return
	}
	for pair := policy.Oldest(); pair != nil; pair = pair.Next() {
		if strings.HasPrefix(strings.ToLower(pair.Key), "geosite:") {
			required.geoSite = true
		}
	}
}
