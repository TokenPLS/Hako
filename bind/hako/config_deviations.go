package hako

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/TokenPLS/Hako/log"
	"gopkg.in/yaml.v3"
)

// A deviation is this core doing something other than what the configuration asked for.
// mihomo is the yardstick: if upstream would honour a field and this core does not,
// that is a deviation and it is owed an explanation, whether or not the outcome is better.
//
// The three categories are the three shapes one can take, and they are not interchangeable:
//
//	stripped    -- the field parsed and this core removed it. A decision. Arguable, revisable.
//	forced      -- the field parsed and this core overwrote it with a different value.
//	unavailable -- no facility exists on this platform; nothing could have honoured it.
//
// Writing a decision down as a wall is the specific failure this batch was opened to fix:
// 43 of 48 stripped fields carried "a Network Extension cannot open a listening socket",
// which this core's own proxy_share.go disproves inside the extension process. A wall is not
// debatable and never gets revisited; a decision is, and does.
const (
	deviationStripped    = "stripped"
	deviationForced      = "forced"
	deviationUnavailable = "unavailable"
)

// configDeviationSchemaVersion lets a client tell "this core reported nothing" from "this
// core is older than the report".
const configDeviationSchemaVersion = 1

type configDeviation struct {
	// Field is the dotted YAML path exactly as a reader would find it in their own file.
	Field string `json:"field"`
	// Given is what they wrote, rendered back. Without it the report is not addressable.
	Given string `json:"given"`
	// Effective is what the core does instead, in the reader's terms rather than the code's.
	Effective string `json:"effective"`
	// Category is one of the three constants above.
	Category string `json:"category"`
	// Reason is why, in one sentence.
	Reason string `json:"reason"`
	// Source is the citation: an Apple document, SDK header, man page or sandbox profile;
	// an upstream mihomo source line; or a file in this repository. Every deviation owes
	// one -- an unciteable reason is how "the platform forbids it" survives unchallenged.
	Source string `json:"source"`
	// Recoverable says whether editing the configuration ALONE can get the behaviour back --
	// a clamped value the reader could have written inside the accepted range, say. It is
	// false for everything this core currently reports, and saying so is the point: the
	// first definition written here was "we chose this vs nothing could do that", which is
	// what Category already answers, and a field that quietly means something else than its
	// name is how a client ends up phrasing a wall as a fixable mistake.
	Recoverable bool `json:"recoverable"`
	// Alternative names another way to get the behaviour on this platform, or is empty when
	// there is none. This is the distinction a reader actually acts on: "you cannot write
	// this in your configuration, but the app offers it here" is a different sentence from
	// "nothing on this platform does this".
	Alternative string `json:"alternative,omitempty"`
	// Effect is what the entry does to the user's traffic, as opposed to what this core did to
	// it. The two come apart for owner-metadata rules: PROCESS-NAME,curl never fires here while
	// PROCESS-NAME-REGEX,.* fires on every connection, and both are "kept".
	//
	// It is a separate field rather than a new Category value on the consuming lane's advice,
	// and their reason is better than the one this side had: their decoder treats Category as a
	// strict enum and DROPS a row carrying an unknown value. A new category would therefore
	// have made "this rule matches every connection" -- the single row most worth seeing --
	// disappear from already-shipped clients with no sign that anything was missing. An unknown
	// FIELD is ignored and the row still renders.
	Effect string `json:"effect,omitempty"`
	// Mechanism is the developer-register half of Reason. Diagnostics export only; never on screen.
	Mechanism string `json:"mechanism,omitempty"`
	// Written says whether the field is present in the reader's file. When it is not, Given
	// still carries the "not set (core default: …)" text this lock's clients render verbatim;
	// the client that renders from Written and UpstreamDefault instead no longer needs that
	// text, and a later lock drops it.
	Written bool `json:"written"`
	// UpstreamDefault is the core's own default for the field, for rows the reader did not
	// write. Empty for written fields and for rules that have no registered default.
	UpstreamDefault string `json:"upstreamDefault,omitempty"`
	// RuleKind names the rule kind a rules row is about ("PROCESS-NAME", "UID", …), as data,
	// so a client can place and word the row without parsing Field or Given. Empty on rows
	// about a setting.
	RuleKind string `json:"ruleKind,omitempty"`
	// Honoured is true when the core ignores the field but this build carries the intent out
	// another way (tun.route-address-set is expanded into addresses before the core starts),
	// so the reader's setting takes effect. A client that words every unavailable row as
	// "does nothing -- remove it" would tell this reader to throw their routes away; the
	// registry has known this (honouredBy) since and the row now says it too.
	Honoured bool `json:"honoured,omitempty"`
}

// deviationRule declares one field's deviation. The table is the record: a field that
// deviates without an entry here is silent, and a field whose entry has no Source cannot be
// added, because the struct literal would not compile past review.
type deviationRule struct {
	field       string
	category    string
	effective   string
	reason      string
	source      string
	recoverable bool
	alternative string
	// withheld marks a field whose value is credential material. The report goes to an HTTP
	// response AND to a log line that lands on disk at any level in any build, so rendering
	// one here breaks the credential red line twice through a single struct field.
	//
	// This is an outlet constraint, not an internal invariant: the parsed configuration keeps
	// the user's value byte for byte, exactly as supplied. Only what leaves the process is
	// withheld. It is set on every credential-bearing field rather than only the ones that
	// happen to render as a scalar today -- authentication and tuic-server currently render as
	// "N entries" and leak nothing, which is luck, not design, and luck changes when a schema
	// admits a single-value spelling.
	withheld bool
	// ruleScan marks a registration issued by scanning the rules list rather than by a YAML
	// path: field is "rules" with ruleKind "UID", and the rules list, not a leaf, is what decides, so lookupYAMLPath can never
	// find it written. The main loop skips these; ownerMetadataRuleDeviations issues them from
	// the same registration, so the sentences have one home. Without this flag the entry was
	// registered and unreachable -- listed in the golden, never in a report.
	ruleScan bool
	// ruleKind is the kind a ruleScan registration is about; it rides out on the row.
	ruleKind string
	// applies answers whether this profile deviates at all. macOS resolves process
	// metadata that iOS cannot, so the same field is a deviation on one and not the other.
	applies func(policy appleRuntimePolicy) bool
	// upstreamDefault is set only for fields this core overwrites whether or not the user
	// wrote them. Those are the deviations a report keyed on "did they write it" cannot
	// see, and they are the worst kind: the reader who wrote nothing has no reason to
	// suspect anything changed. The string is the value mihomo's DefaultRawConfig uses,
	// so the report can name a baseline instead of an absence.
	//
	// Leave it empty when this core forces the value upstream already defaults to. That
	// changes nothing for a silent reader, and listing it would be noise -- which is how
	// a report stops being read, and silence comes back by another route.
	upstreamDefault string
	// honouredBy names how the INTENT behind a field is carried out when the field itself
	// is not. It is set on an unavailable field whose value this core reads and rewrites
	// into something the platform does act on -- route-address-set is expanded into
	// route-address before the core ever sees the configuration. The field reaches the
	// core, is ignored there exactly as upstream ignores it on darwin, and the routes are
	// installed anyway.
	//
	// A client drawing the registry needs this as a bit, not a sentence. The macOS lane's
	// first gate over this file correctly flagged both route-set keys as "unavailable yet
	// editable", made the rows read-only, and told the reader the value does not take
	// effect -- which is false, and a sadder sentence than the truth. Their interim repair
	// read the `effective` prose out of this Go source to find the word "resolved", which
	// means rewording a sentence here reds a gate over there. This field is the structured
	// version of that sentence, and TestEveryHonouredByIsARealWrite refuses to let it
	// become a sentence again: every rule carrying it has to produce the write it claims.
	//
	// Values: "" (nothing honours it -- the common case) or "expansion".
	honouredBy string
	// defaultOnly marks a rule whose enforcement fires ONLY when the reader did not write the
	// field: this core changes the default and leaves an explicit value alone. For such a rule a
	// configuration that writes the field has no deviation -- nothing happened to it -- and
	// reporting "given false -> effective true" there states an event that did not occur.
	// Found on a Mac whose profile wrote store-fake-ip: false and whose page then showed
	// "off, from configuration" one line above "false -> true" (the guard had returned early;
	// the report had not looked). The row is emitted only for an unwritten field, where
	// given reads "not set (core default: X)" -- "core default" is the client's own word for it.
	defaultOnly bool
	// forcedValue is the scalar a forced rule writes, rendered the way lookupYAMLPath renders
	// a read value ("true", "false", "off", "0", "memconservative"). A configuration that wrote
	// exactly that value has no deviation -- the core changed X to X -- and gets no row, which
	// is the same standard as defaultOnly from the other side: a row in "what the running core
	// did" has to name something that happened. Empty for a forced rule whose value is not a
	// constant (tun.mtu is chosen at startup) or not a scalar (tun.dns-hijack is a list and is
	// compared raw); TestEveryForcedRuleNamesItsValueOrIsExempt lists the exemptions.
	forcedValue string
	// mechanism is the developer's half of the reason: the file, function, API type, kernel
	// constant or tool that makes the sentence true. It exists so that reason can be written
	// for the person changing a setting -- what happened to them, what they can do -- while the
	// material that proves it lives here. Clients keep mechanism and source for the diagnostics
	// export and never put them on screen. The user's words on seeing
	// "bind/hako/config_pipeline.go:119-124 (the StoreFakeIPSet guard)" under a setting: that is
	// Go's decision-making shown to someone who came to change a setting.
	mechanism string
}

// The tun families. Each is one sentence shared by fields that deviate for the SAME reason, and
// they are named here rather than repeated so that a new sharer is a deliberate act --
// TestSharedDeviationReasonsAreDeclaredFamilies refuses an undeclared one, because a borrowed
// sentence is how dns.listen once shipped carrying the RESTful API's explanation.
const (
	tunPacketTunnelShape = "on Apple the tunnel is the only shape this extension can take, so there is no setting that turns it off"
	tunRoutingIsApples   = "on Apple the routes are installed by the app, not by the core, so the core-side routing switches have nothing to act on"
	// Two families ride the same SOCK_DGRAM bridge fact but select different utun-fd features,
	// so each gets a sentence that is true of ITS fields. The batch-I/O one was once shared by
	// all four; a rewrite made it precise for recvmsgx/sendmsgx and thereby wrong for gso,
	// which selects segmentation offload, not a read/write path.
	tunOffloadBridge   = "on Apple the tunnel has no network driver to negotiate offload with, so offload cannot be turned on"
	tunBatchIOBridge   = "on Apple the tunnel does not expose the batched read/write path these fields select, so the ordinary path is used instead; nothing is lost but the batching"
	tunAutoRouteFilter = "this filters a kind of routing the core never installs on Apple -- the app installs the routes -- so there is nothing for the filter to act on"

	// The developer-register twins of the family sentences: the machinery that makes each true.
	// They ride in mechanism, never in reason.
	tunPacketTunnelShapeMechanism = "a packet tunnel provider is a tun by construction: there is no no-tun shape for the extension to take"
	tunRoutingIsApplesMechanism   = "routes belong to NEPacketTunnelNetworkSettings and are installed by the extension's Swift side; the core does not own a host routing table here"
	tunOffloadBridgeMechanism     = "the data plane is NEPacketTunnelFlow bridged through a SOCK_DGRAM descriptor rather than a utun fd; segmentation offload is negotiated with a tun driver, and the bridge descriptor has no such driver to negotiate with"
	tunBatchIOBridgeMechanism     = "the data plane is NEPacketTunnelFlow bridged through a SOCK_DGRAM descriptor rather than a utun fd, so the batched utun-fd read/write path these fields select uses ordinary readv/writev instead (this is about the fd, not about socket options -- IP_BOUND_IF is a socket option and works fine over the bridge)"
	tunAutoRouteFilterMechanism   = "this filters sing-tun's auto-route host routing, which the extension never installs -- NEPacketTunnelNetworkSettings does"

	tunIncludeAllNetworks          = "with Include All Networks on, the system and mixed stacks send nothing; only the gvisor stack carries the tunnel's traffic"
	tunIncludeAllNetworksMechanism = "Include All Networks makes the kernel drop, at ip_output, every packet that does not leave through the tunnel; the system and mixed stacks re-inject the tunnel's TCP through the kernel and lose it there, which is why sing-tun refuses both under includeAllNetworks (third_party/sing-tun/stack.go)"
)

func underNetworkExtension(policy appleRuntimePolicy) bool { return policy.networkExtension }

// underPacketTunnel is where overrideTunForIOS runs, and tun is always enabled there because
// ensureTunEnabled turns it on before the override. Outside a packet tunnel nothing rewrites
// these fields, so reporting them would describe a change that did not happen.
func underPacketTunnel(policy appleRuntimePolicy) bool {
	return policy.networkExtension && policy.packetTunnel
}

var deviationRules = []deviationRule{
	// -- unavailable: upstream itself cannot do this here ------------------------------
	{
		field:       "tproxy-port",
		category:    deviationUnavailable,
		effective:   "no transparent-proxy listener is opened",
		reason:      "transparent proxying is a Linux-only facility; the core itself reports it as unsupported on this platform",
		source:      "upstream listener/tproxy/setsockopt_other.go; iPhoneOS SDK netinet/in.h has no IP_TRANSPARENT",
		recoverable: false,
		mechanism:   "transparent proxying needs Linux netfilter; upstream's own non-Linux build answers \"not supported on current platform\"",
	},
	{
		field:       "redir-port",
		category:    deviationUnavailable,
		effective:   "no redirect listener is opened",
		reason:      "the redirect listener needs a system facility that an app on Apple is not allowed to open, and a firewall rule the app is not allowed to install",
		source:      "upstream listener/redir/tcp_darwin.go; /System/Library/Sandbox/Profiles/application.sb",
		recoverable: false,
		mechanism:   "upstream's darwin implementation reads the original destination from /dev/pf with a DIOCNATLOOK ioctl, which an App Sandbox cannot open, and installing the pf redirect rule it depends on needs root",
	},
	{
		field:       "dns.listen-routing-mark",
		category:    deviationUnavailable,
		effective:   "the mark is not applied",
		reason:      "socket marks are a Linux facility and do not exist on Apple",
		source:      "iPhoneOS SDK sys/socket.h defines no SO_MARK",
		recoverable: false,
		mechanism:   "SO_MARK is a Linux socket option and does not exist on Darwin",
	},
	{
		field:       "external-controller-routing-mark",
		category:    deviationUnavailable,
		effective:   "the mark is not applied",
		reason:      "socket marks are a Linux facility and do not exist on Apple",
		source:      "iPhoneOS SDK sys/socket.h defines no SO_MARK",
		recoverable: false,
		mechanism:   "SO_MARK is a Linux socket option and does not exist on Darwin",
	},
	{
		field:     "external-controller-pipe",
		category:  deviationUnavailable,
		effective: "no pipe is opened",
		reason: "a named pipe is a Windows facility; upstream requires the address to start " +
			"with \\\\.\\pipe\\ and has no Darwin implementation",
		source:      "upstream hub/route/server.go:308",
		recoverable: false,
	},
	{
		field:     "allow-lan",
		category:  deviationStripped,
		effective: "the configured listener stays on 127.0.0.1 instead of every interface",
		reason: "exposing the device to the local network is a decision the person holding it " +
			"makes, not one an imported subscription makes for them; the app has not recorded " +
			"that agreement yet",
		source: "listener/listener.go:709-718 genAddr binds \":port\" when allow-lan is true and " +
			"127.0.0.1 when it is not; bind/hako/allow_lan_gate.go holds the permission",
		recoverable: false,
		alternative: "turn on local-network sharing in the app; the configured value is honoured from the next reload",
		applies: func(policy appleRuntimePolicy) bool {
			return policy.networkExtension && !allowLanPermitted.Load()
		},
	},
	{
		field:     "rules",
		ruleScan:  true,
		ruleKind:  "UID",
		category:  deviationUnavailable,
		effective: "UID rules are removed; a logic rule carrying a UID branch is removed whole",
		reason: "UID names a socket owner this platform does not expose, and the core's own rule " +
			"constructor refuses to build it here, so keeping the rule would fail the entire " +
			"configuration rather than simply never matching",
		source: "upstream rules/common/uid.go gates NewUid on GOOS linux/android/darwin; " +
			"rules/logic/logic.go parsePayload returns on the first branch that fails to construct",
		recoverable: false,
		applies: func(policy appleRuntimePolicy) bool {
			return policy.networkExtension && !policy.processMetadata().resolves("UID")
		},
	},
	{
		field:     "tun.route-address-set",
		category:  deviationUnavailable,
		effective: "the routes take effect: the named rule set is read and its addresses are written into route-address before the core starts; the set name itself is accepted and ignored, the same as on any other platform",
		reason:    "the named rule set is turned into plain addresses before the core starts, so the routes you meant do take effect; the set itself is a Linux firewall facility that Apple does not have",
		source: "bind/hako/config_finalize.go FinalizeForIOS expandRouteSet; sing-tun consumes the " +
			"field itself only in redirect_linux.go and redirect_nftables*.go, always through " +
			"autoRedirect, and upstream documentation says Linux only and requires nftables",
		recoverable: false,
		honouredBy:  "expansion",
		mechanism:   "the FIELD is a Linux forwarding-plane switch -- it adds prefixes to an nftables set so the host firewall can bypass the redirect -- but the INTENT behind it, which prefixes enter the tunnel, is expressible here and is honoured by expanding it",
	},
	{
		field:     "tun.route-exclude-address-set",
		category:  deviationUnavailable,
		effective: "the exclusions take effect: the named rule set is read and its addresses are written into route-exclude-address before the core starts; the set name itself is accepted and ignored, the same as on any other platform",
		reason:    "the named rule set is turned into plain addresses before the core starts, so the routes you meant do take effect; the set itself is a Linux firewall facility that Apple does not have",
		source: "bind/hako/config_finalize.go FinalizeForIOS expandRouteSet; sing-tun consumes the " +
			"field itself only in redirect_linux.go and redirect_nftables*.go, always through " +
			"autoRedirect, and upstream documentation says Linux only and requires nftables",
		recoverable: false,
		honouredBy:  "expansion",
		mechanism:   "the FIELD is a Linux forwarding-plane switch -- it adds prefixes to an nftables set so the host firewall can bypass the redirect -- but the INTENT behind it, which prefixes enter the tunnel, is expressible here and is honoured by expanding it",
	},
	{
		field:       "ntp.write-to-system",
		category:    deviationForced,
		effective:   "false: the core keeps its own NTP offset and never sets the device clock",
		reason:      "only the system itself may set the device clock; an app or its extension cannot",
		source:      "man 2 settimeofday: \"Only the super-user may set the time of day\" (EPERM otherwise)",
		recoverable: false,
		forcedValue: "false",
		// Cleared only inside the extension (overrideForNetworkExtension / the raw NE normaliser);
		// the containing-app preflight leaves it as written.
		applies:   underNetworkExtension,
		mechanism: "setting the system clock goes through settimeofday, which only the super-user may call; an app extension is not",
	},

	{
		field:       "routing-mark",
		category:    deviationUnavailable,
		effective:   "no mark is set on outbound sockets",
		reason:      "socket marks are a Linux facility and do not exist on Apple; the core itself reports it as unsupported here",
		source:      "upstream component/dialer/mark_nonlinux.go printMarkWarn; Darwin has no SO_MARK",
		recoverable: false,
		mechanism:   "SO_MARK is a Linux socket option; upstream's own non-Linux build warns \"Routing mark on socket is not supported on current platform\" and sets nothing",
	},

	// -- stripped: this core removed something the platform could have done ------------
	//
	// The capability is not in question: proxy_share.go opens an authenticated mixed
	// HTTP/SOCKS5 listener bound to 0.0.0.0 and :: inside this very extension process,
	// shipping, and the SDK puts no availability limit on accept/bind/listen.
	//
	// Apple's guidance is a separate question from capability, and it is not silent. TN3120:
	// "Do not use a packet tunnel provider to host a network listener or proxy server. There
	// is no reasonable alternative here other than using one of the app proxy provider APIs.
	// This path is simply not a recommended use case for a packet tunnel provider or any
	// other Network Extension." That is an imperative, and it is cited on every entry below.
	//
	// So "a Network Extension cannot open a listening socket" was still false -- Apple says
	// do not, not cannot, and this core does it anyway. But the strip is not a bare
	// preference either: it follows a specific Apple instruction. Both halves belong in the
	// record, because the first one is what makes 43 fields debatable and the second is what
	// they will be debated against.

	{
		field:     "interface-name",
		category:  deviationStripped,
		effective: "removed: outbound sockets are bound by the extension, not by this name",
		reason:    "on Apple every outgoing connection is already bound to the physical network by the app, so a name here has nothing left to decide; this is a choice of this product, not a platform limit",
		source: "bind/hako/override.go overrideForNetworkExtension; upstream " +
			"component/dialer/dialer.go \"ignore interfaceName, routingMark when " +
			"DefaultSocketHook not null\"; component/dialer/bind_darwin.go exists",
		recoverable: false,
		applies:     underNetworkExtension,
		mechanism:   "the extension installs a socket hook so every outbound socket is bound to the physical interface with IP_BOUND_IF, and upstream's dialer ignores interface-name whenever a socket hook is installed -- unlike routing-mark this one is a decision, because binding by name does work on Darwin without the hook",
	},

	// -- forced: this core overwrote a value the user set -------------------------------
	{
		field:     "dns.enable",
		category:  deviationForced,
		effective: "true: the core serves DNS for the queries the tunnel captures",
		reason: "an Apple packet tunnel always captures port 53; with dns.enable false the core " +
			"serves nothing and every captured query answers SERVFAIL, so the tunnel would " +
			"start and resolve nothing",
		source:          "upstream config/config.go DefaultRawConfig has DNS.Enable false",
		recoverable:     false,
		applies:         underNetworkExtension,
		upstreamDefault: "false",
		forcedValue:     "true",
	},
	{
		field:     "profile.store-fake-ip",
		category:  deviationForced,
		effective: "true: fake-ip mappings are written to disk so they survive an extension restart",
		reason: "an Apple packet tunnel is restarted by the system far more often than a desktop " +
			"process is, and a fresh in-memory pool hands the same domain a different fake " +
			"address each time; an explicit true or false is always honoured",
		source:          "bind/hako/config_pipeline.go:119-124 (the StoreFakeIPSet guard); upstream config/config.go DefaultRawConfig has StoreFakeIP false",
		recoverable:     true,
		alternative:     "write profile.store-fake-ip explicitly -- any value you set is kept",
		upstreamDefault: "false",
		defaultOnly:     true,
		forcedValue:     "true",
	},
	{
		field:     "unified-delay",
		category:  deviationForced,
		effective: "true: a probe reports the second, comparable round trip instead of billing the whole cold start to whichever proxy was measured first",
		reason: "upstream defaults unified-delay off, so the first probe of a proxy pays " +
			"TCP, TLS and the protocol handshake while the next one does not, and numbers " +
			"cannot be compared across proxies or protocols; an explicit true or false is " +
			"always honoured",
		source:          "bind/hako/config_pipeline.go applyUnifiedDelayDefault (the typed-probe guard); upstream config/config.go DefaultRawConfig has UnifiedDelay false",
		recoverable:     true,
		alternative:     "write unified-delay explicitly -- any value you set is kept",
		upstreamDefault: "false",
		defaultOnly:     true,
		forcedValue:     "true",
	},
	{
		field:     "find-process-mode",
		category:  deviationForced,
		effective: "off: no rule is matched against the owning process, and PROCESS-*/UID rules evaluate against empty metadata",
		reason: "an app extension cannot enumerate other processes, so a lookup would fail on " +
			"every connection rather than some; the rules themselves are kept and behave " +
			"exactly as they do with find-process-mode off",
		source:          "upstream config/config.go DefaultRawConfig has FindProcessMode strict; bind/hako/config_pipeline.go normalizeRawNetworkExtensionSurfaces",
		recoverable:     false,
		applies:         func(policy appleRuntimePolicy) bool { return !policy.processMetadata().processPath },
		upstreamDefault: "strict",
		forcedValue:     "off",
	},
	// -- tun: the 23 fields a packet tunnel intervenes on -------------------------------
	//
	// Every one of these was labelled "apple" until 2026-08-10, and apple is the only
	// disposition exempt from BOTH the code-anchoring check and this report. So a user who wrote
	// include-interface, or auto-route, or dns-hijack got it removed or overwritten and was told
	// nothing. The audit that produced these entries measured all 36 rather than reading the
	// family note: 12 turned out to be honoured verbatim, 12 cleared, 11 forced.
	{
		field:       "tun.stack",
		category:    deviationForced,
		effective:   "gvisor: the only stack that carries traffic while Include All Networks is on",
		reason:      tunIncludeAllNetworks,
		source:      "bind/hako/override.go overrideTunForIOS; third_party/sing-tun/stack.go ErrIncludeAllNetworks; NETunnelProviderProtocol.includeAllNetworks",
		recoverable: true,
		alternative: "turn Include All Networks off in the tunnel settings, or write tun.stack: gvisor",
		applies: func(policy appleRuntimePolicy) bool {
			return underPacketTunnel(policy) && includeAllNetworksActive()
		},
		forcedValue: "gvisor",
		mechanism:   tunIncludeAllNetworksMechanism,
	},
	{
		field:       "tun.enable",
		category:    deviationForced,
		effective:   "true: the extension is a packet tunnel, so it always carries a tun",
		reason:      tunPacketTunnelShape,
		source:      "bind/hako/service.go ensureTunEnabled",
		recoverable: false,
		applies:     underPacketTunnel,
		forcedValue: "true",
		mechanism:   tunPacketTunnelShapeMechanism,
	},
	{
		field:       "tun.device",
		category:    deviationForced,
		effective:   "hako-packet-flow, this product's bridge",
		reason:      "on Apple the tunnel is handed to the core by the system, not opened by name, so there is no device to name",
		source:      "bind/hako/override.go overrideTunForIOS; Apple NEPacketTunnelProvider.packetFlow",
		recoverable: false,
		applies:     underPacketTunnel,
		forcedValue: "hako-packet-flow",
		mechanism:   "the extension is handed an NEPacketTunnelFlow rather than a utun descriptor, so a device name has nothing to name",
	},
	{
		field:       "tun.auto-route",
		category:    deviationForced,
		effective:   "false: Swift installs the routes",
		reason:      tunRoutingIsApples,
		source:      "bind/hako/override.go overrideTunForIOS; Apple NEPacketTunnelNetworkSettings",
		recoverable: false,
		alternative: "tun.route-address and tun.route-exclude-address ARE honoured, and become the routes the extension installs",
		applies:     underPacketTunnel,
		forcedValue: "false",
		mechanism:   tunRoutingIsApplesMechanism,
	},
	{
		field:       "tun.auto-detect-interface",
		category:    deviationForced,
		effective:   "false: the extension decides its own egress interface",
		reason:      tunRoutingIsApples,
		source:      "bind/hako/override.go overrideTunForIOS; Apple NEPacketTunnelNetworkSettings",
		recoverable: false,
		applies:     underPacketTunnel,
		forcedValue: "false",
		mechanism:   tunRoutingIsApplesMechanism,
	},
	{
		field:       "tun.gso",
		category:    deviationForced,
		effective:   "false",
		reason:      tunOffloadBridge,
		source:      "bind/hako/override.go overrideTunForIOS",
		recoverable: false,
		applies:     underPacketTunnel,
		forcedValue: "false",
		mechanism:   tunOffloadBridgeMechanism,
	},
	{
		field:       "tun.gso-max-size",
		category:    deviationForced,
		effective:   "0, following gso",
		reason:      tunOffloadBridge,
		source:      "bind/hako/override.go overrideTunForIOS",
		recoverable: false,
		applies:     underPacketTunnel,
		forcedValue: "0",
		mechanism:   tunOffloadBridgeMechanism,
	},
	{
		field:       "tun.recvmsgx",
		category:    deviationForced,
		effective:   "false: the tunnel uses its normal data path",
		reason:      tunBatchIOBridge,
		source:      "bind/hako/override.go overrideTunForIOS; upstream sing-tun recvmsg_x is the batched utun-fd read path, not a socket option",
		recoverable: false,
		applies:     underPacketTunnel,
		forcedValue: "false",
		mechanism:   tunBatchIOBridgeMechanism,
	},
	{
		field:       "tun.sendmsgx",
		category:    deviationForced,
		effective:   "false: the tunnel uses its normal data path",
		reason:      tunBatchIOBridge,
		source:      "bind/hako/override.go overrideTunForIOS; upstream sing-tun sendmsg_x is the batched utun-fd write path, not a socket option",
		recoverable: false,
		applies:     underPacketTunnel,
		forcedValue: "false",
		mechanism:   tunBatchIOBridgeMechanism,
	},
	{
		field:     "tun.disable-icmp-forwarding",
		category:  deviationForced,
		effective: "true: the core answers pings itself instead of forwarding them",
		reason: "forwarding ICMP needs a raw socket, which no unprivileged Apple process can " +
			"open; ping still answers, but the latency it shows is this device's, not the route's",
		source:      "bind/hako/override.go overrideTunForIOS; listener/sing_tun/prepare.go",
		recoverable: false,
		applies:     underPacketTunnel,
		forcedValue: "true",
	},
	{
		field:       "tun.dns-hijack",
		category:    deviationForced,
		effective:   "0.0.0.0:53, every DNS query in the tunnel",
		reason:      "this is a choice of this product, not an Apple rule: the system advertises one DNS address to apps, and capturing every DNS query is what keeps a query from slipping out of the tunnel unresolved",
		source:      "bind/hako/override.go overrideTunForIOS",
		recoverable: false,
		applies:     underPacketTunnel,
		mechanism:   "this is a product decision rather than an Apple rule: NEDNSSettings advertises one address, the tun gateway +1, and hijacking all of port 53 is what keeps a query from leaving the tunnel unresolved by this core",
	},
	{
		field:       "tun.include-interface",
		category:    deviationStripped,
		effective:   "removed: nothing filters the tunnel by this",
		reason:      tunAutoRouteFilter,
		source:      "bind/hako/config_pipeline.go normalizeRawNetworkExtensionSurfaces; Apple NEPacketTunnelNetworkSettings owns the routes",
		recoverable: false,
		applies:     underPacketTunnel,
		mechanism:   tunAutoRouteFilterMechanism,
	},
	{
		field:       "tun.exclude-interface",
		category:    deviationStripped,
		effective:   "removed: nothing filters the tunnel by this",
		reason:      tunAutoRouteFilter,
		source:      "bind/hako/config_pipeline.go normalizeRawNetworkExtensionSurfaces; Apple NEPacketTunnelNetworkSettings owns the routes",
		recoverable: false,
		applies:     underPacketTunnel,
		mechanism:   tunAutoRouteFilterMechanism,
	},
	{
		field:       "tun.include-uid",
		category:    deviationStripped,
		effective:   "removed: nothing filters the tunnel by this",
		reason:      tunAutoRouteFilter,
		source:      "bind/hako/config_pipeline.go normalizeRawNetworkExtensionSurfaces; Apple NEPacketTunnelNetworkSettings owns the routes",
		recoverable: false,
		applies:     underPacketTunnel,
		mechanism:   tunAutoRouteFilterMechanism,
	},
	{
		field:       "tun.include-uid-range",
		category:    deviationStripped,
		effective:   "removed: nothing filters the tunnel by this",
		reason:      tunAutoRouteFilter,
		source:      "bind/hako/config_pipeline.go normalizeRawNetworkExtensionSurfaces; Apple NEPacketTunnelNetworkSettings owns the routes",
		recoverable: false,
		applies:     underPacketTunnel,
		mechanism:   tunAutoRouteFilterMechanism,
	},
	{
		field:       "tun.exclude-uid",
		category:    deviationStripped,
		effective:   "removed: nothing filters the tunnel by this",
		reason:      tunAutoRouteFilter,
		source:      "bind/hako/config_pipeline.go normalizeRawNetworkExtensionSurfaces; Apple NEPacketTunnelNetworkSettings owns the routes",
		recoverable: false,
		applies:     underPacketTunnel,
		mechanism:   tunAutoRouteFilterMechanism,
	},
	{
		field:       "tun.exclude-uid-range",
		category:    deviationStripped,
		effective:   "removed: nothing filters the tunnel by this",
		reason:      tunAutoRouteFilter,
		source:      "bind/hako/config_pipeline.go normalizeRawNetworkExtensionSurfaces; Apple NEPacketTunnelNetworkSettings owns the routes",
		recoverable: false,
		applies:     underPacketTunnel,
		mechanism:   tunAutoRouteFilterMechanism,
	},
	{
		field:       "tun.exclude-src-port",
		category:    deviationStripped,
		effective:   "removed: nothing filters the tunnel by this",
		reason:      tunAutoRouteFilter,
		source:      "bind/hako/config_pipeline.go normalizeRawNetworkExtensionSurfaces; Apple NEPacketTunnelNetworkSettings owns the routes",
		recoverable: false,
		applies:     underPacketTunnel,
		mechanism:   tunAutoRouteFilterMechanism,
	},
	{
		field:       "tun.exclude-src-port-range",
		category:    deviationStripped,
		effective:   "removed: nothing filters the tunnel by this",
		reason:      tunAutoRouteFilter,
		source:      "bind/hako/config_pipeline.go normalizeRawNetworkExtensionSurfaces; Apple NEPacketTunnelNetworkSettings owns the routes",
		recoverable: false,
		applies:     underPacketTunnel,
		mechanism:   tunAutoRouteFilterMechanism,
	},
	{
		field:       "tun.exclude-dst-port",
		category:    deviationStripped,
		effective:   "removed: nothing filters the tunnel by this",
		reason:      tunAutoRouteFilter,
		source:      "bind/hako/config_pipeline.go normalizeRawNetworkExtensionSurfaces; Apple NEPacketTunnelNetworkSettings owns the routes",
		recoverable: false,
		applies:     underPacketTunnel,
		mechanism:   tunAutoRouteFilterMechanism,
	},
	{
		field:       "tun.exclude-dst-port-range",
		category:    deviationStripped,
		effective:   "removed: nothing filters the tunnel by this",
		reason:      tunAutoRouteFilter,
		source:      "bind/hako/config_pipeline.go normalizeRawNetworkExtensionSurfaces; Apple NEPacketTunnelNetworkSettings owns the routes",
		recoverable: false,
		applies:     underPacketTunnel,
		mechanism:   tunAutoRouteFilterMechanism,
	},
	{
		field:       "tun.include-mac-address",
		category:    deviationStripped,
		effective:   "removed: nothing filters the tunnel by this",
		reason:      tunAutoRouteFilter,
		source:      "bind/hako/config_pipeline.go normalizeRawNetworkExtensionSurfaces; Apple NEPacketTunnelNetworkSettings owns the routes",
		recoverable: false,
		applies:     underPacketTunnel,
		mechanism:   tunAutoRouteFilterMechanism,
	},
	{
		field:       "tun.exclude-mac-address",
		category:    deviationStripped,
		effective:   "removed: nothing filters the tunnel by this",
		reason:      tunAutoRouteFilter,
		source:      "bind/hako/config_pipeline.go normalizeRawNetworkExtensionSurfaces; Apple NEPacketTunnelNetworkSettings owns the routes",
		recoverable: false,
		applies:     underPacketTunnel,
		mechanism:   tunAutoRouteFilterMechanism,
	},
	{
		field:       "tun.mtu",
		category:    deviationForced,
		effective:   "the MTU the extension selected at startup",
		reason:      "the tunnel can only use one packet size, and the app and the core have to agree on it, so it is chosen once at startup; a value written here is not used, and the size that is used is the one both sides agreed on, so nothing is missing",
		source:      "bind/hako/override.go overrideTunForIOS; TunOptions.GetMTU",
		recoverable: false,
		applies:     underPacketTunnel,
		mechanism:   "the core and the Network Extension have to agree on one number -- Swift reads it back through TunOptions.GetMTU and installs it on NEPacketTunnelNetworkSettings -- so a value that reached only one of the two would describe a link neither side is running",
	},
	{
		field:       "geo-auto-update",
		category:    deviationForced,
		effective:   "false: geo data is pre-downloaded by the containing app and handed to the core",
		reason:      "this is how this product is built, not an Apple rule: the app downloads geo data itself and hands it to the core",
		source:      "bind/hako/override.go",
		recoverable: false,
		forcedValue: "false",
		mechanism:   "this is this product's architecture, not an Apple rule -- an extension is allowed to make outbound requests",
	},
	{
		field:       "geodata-loader",
		category:    deviationForced,
		effective:   "memconservative: geo data is streamed rather than held decoded",
		reason:      "this core measured a 72.7 MiB peak compiling geosite, which a packet tunnel cannot afford; note that no Apple document states a memory ceiling",
		source:      "bind/hako/override.go; measured in this repository, not an Apple source",
		recoverable: false,
		forcedValue: "memconservative",
		// Forced only where the memory model demands it; a macOS profile keeps the loader as written.
		applies: func(policy appleRuntimePolicy) bool { return policy.memoryConservativeGeodata },
		// Forced only where the memory model demands it; a macOS profile keeps the loader as written.
	},
	{
		field:       "geo-update-interval",
		category:    deviationUnavailable,
		effective:   "unused: no periodic downloader runs in this core",
		reason:      "it only schedules geo-auto-update, which is off",
		source:      "bind/hako/override.go; see geo-auto-update",
		recoverable: false,
	},
	{
		field:       "tun.auto-redirect",
		category:    deviationUnavailable,
		effective:   "accepted and ignored, the same as on any other platform",
		reason:      "this configures a Linux-only part of the system that Apple does not have; the core accepts it and does nothing with it, exactly as it does on any non-Linux platform",
		source:      "sing-tun consumes it only in tun_linux.go and the redirect_nftables/iptables files, all Linux forwarding plane",
		recoverable: false,
		mechanism:   "this configures the Linux forwarding plane (nftables/iptables/iproute2), which no Apple platform has",
	},
	{
		field:       "tun.auto-redirect-input-mark",
		category:    deviationUnavailable,
		effective:   "accepted and ignored, the same as on any other platform",
		reason:      "this configures a Linux-only part of the system that Apple does not have; the core accepts it and does nothing with it, exactly as it does on any non-Linux platform",
		source:      "sing-tun consumes it only in tun_linux.go and the redirect_nftables/iptables files, all Linux forwarding plane",
		recoverable: false,
		mechanism:   "this configures the Linux forwarding plane (nftables/iptables/iproute2), which no Apple platform has",
	},
	{
		field:       "tun.auto-redirect-output-mark",
		category:    deviationUnavailable,
		effective:   "accepted and ignored, the same as on any other platform",
		reason:      "this configures a Linux-only part of the system that Apple does not have; the core accepts it and does nothing with it, exactly as it does on any non-Linux platform",
		source:      "sing-tun consumes it only in tun_linux.go and the redirect_nftables/iptables files, all Linux forwarding plane",
		recoverable: false,
		mechanism:   "this configures the Linux forwarding plane (nftables/iptables/iproute2), which no Apple platform has",
	},
	{
		field:       "tun.auto-redirect-iproute2-fallback-rule-index",
		category:    deviationUnavailable,
		effective:   "accepted and ignored, the same as on any other platform",
		reason:      "this configures a Linux-only part of the system that Apple does not have; the core accepts it and does nothing with it, exactly as it does on any non-Linux platform",
		source:      "sing-tun consumes it only in tun_linux.go and the redirect_nftables/iptables files, all Linux forwarding plane",
		recoverable: false,
		mechanism:   "this configures the Linux forwarding plane (nftables/iptables/iproute2), which no Apple platform has",
	},
	{
		field:       "tun.iproute2-table-index",
		category:    deviationUnavailable,
		effective:   "accepted and ignored, the same as on any other platform",
		reason:      "this configures a Linux-only part of the system that Apple does not have; the core accepts it and does nothing with it, exactly as it does on any non-Linux platform",
		source:      "sing-tun consumes it only in tun_linux.go and the redirect_nftables/iptables files, all Linux forwarding plane",
		recoverable: false,
		mechanism:   "this configures the Linux forwarding plane (nftables/iptables/iproute2), which no Apple platform has",
	},
	{
		field:       "tun.iproute2-rule-index",
		category:    deviationUnavailable,
		effective:   "accepted and ignored, the same as on any other platform",
		reason:      "this configures a Linux-only part of the system that Apple does not have; the core accepts it and does nothing with it, exactly as it does on any non-Linux platform",
		source:      "sing-tun consumes it only in tun_linux.go and the redirect_nftables/iptables files, all Linux forwarding plane",
		recoverable: false,
		mechanism:   "this configures the Linux forwarding plane (nftables/iptables/iproute2), which no Apple platform has",
	},
	{
		field:       "iptables",
		category:    deviationUnavailable,
		effective:   "accepted and ignored, the same as on any other platform",
		reason:      "this configures a Linux-only part of the system that Apple does not have; the core accepts it and does nothing with it, exactly as it does on any non-Linux platform",
		source:      "sing-tun consumes it only in tun_linux.go and the redirect_nftables/iptables files, all Linux forwarding plane",
		recoverable: false,
		mechanism:   "this configures the Linux forwarding plane (nftables/iptables/iproute2), which no Apple platform has",
	},
	{
		field:       "tun.include-package",
		category:    deviationUnavailable,
		effective:   "accepted and ignored, the same as on any other platform",
		reason:      "this names Android packages or users, which no Apple platform can resolve",
		source:      "resolving a package name to a UID exists only in sing-tun's packages_android.go; every other platform gets the packages_stub.go stub",
		recoverable: false,
	},
	{
		field:       "tun.exclude-package",
		category:    deviationUnavailable,
		effective:   "accepted and ignored, the same as on any other platform",
		reason:      "this names Android packages or users, which no Apple platform can resolve",
		source:      "resolving a package name to a UID exists only in sing-tun's packages_android.go; every other platform gets the packages_stub.go stub",
		recoverable: false,
	},
	{
		field:       "tun.include-android-user",
		category:    deviationUnavailable,
		effective:   "accepted and ignored, the same as on any other platform",
		reason:      "this names Android packages or users, which no Apple platform can resolve",
		source:      "resolving a package name to a UID exists only in sing-tun's packages_android.go; every other platform gets the packages_stub.go stub",
		recoverable: false,
	},
	{
		field:       "clash-for-android",
		category:    deviationUnavailable,
		effective:   "accepted and ignored, the same as on any other platform",
		reason:      "this names Android packages or users, which no Apple platform can resolve",
		source:      "resolving a package name to a UID exists only in sing-tun's packages_android.go; every other platform gets the packages_stub.go stub",
		recoverable: false,
	},
}

// collectConfigDeviations reads the merged YAML the user actually supplied and reports only
// fields they wrote. Reading the parsed RawConfig instead would be unable to tell a value the
// user chose from a zero value the parser filled in, and a report that cannot tell those
// apart lists the whole schema.
func collectConfigDeviations(mergedYAML string, policy appleRuntimePolicy) ([]configDeviation, error) {
	var root map[string]any
	if err := yaml.Unmarshal([]byte(mergedYAML), &root); err != nil {
		return nil, err
	}
	deviations := make([]configDeviation, 0)
	for _, rule := range deviationRules {
		if rule.applies != nil && !rule.applies(policy) {
			continue
		}
		if rule.ruleScan {
			continue // issued by ownerMetadataRuleDeviations from this same registration
		}
		given, written := lookupYAMLPath(root, rule.field)
		if rule.defaultOnly && written {
			// The reader wrote it, so the default-changing guard did not fire and there is no
			// deviation to report. See the field's comment on deviationRule.
			continue
		}
		if written && rule.forcedValue != "" && given == rule.forcedValue {
			// The reader wrote exactly what the core forces. Nothing changed, so no row.
			continue
		}
		if written && rule.field == "tun.dns-hijack" && dnsHijackAlreadyHijacksAll(root) {
			continue
		}
		if written && rule.withheld {
			given = deviationValueWithheld
		}
		upstreamDefault := ""
		if !written {
			if rule.upstreamDefault == "" {
				continue
			}
			given = "not set (core default: " + rule.upstreamDefault + ")"
			upstreamDefault = rule.upstreamDefault
		}
		deviations = append(deviations, configDeviation{
			Field:           rule.field,
			Given:           given,
			Effective:       rule.effective,
			Category:        rule.category,
			Reason:          rule.reason,
			Source:          rule.source,
			Recoverable:     rule.recoverable,
			Alternative:     rule.alternative,
			Mechanism:       rule.mechanism,
			Written:         written,
			UpstreamDefault: upstreamDefault,
			Honoured:        rule.honouredBy != "",
		})
	}
	deviations = append(deviations, ownerMetadataRuleDeviations(root, policy)...)
	return deviations, nil
}

// ownerMetadataRuleDeviations reports the rules whose owner metadata this platform cannot
// supply, by what they do to traffic rather than by what was done to them.
//
// The two effects are reported differently on purpose, and the asymmetry is the point:
//
//   - never-matches is common and inert, so it is summarised per kind. One line per rule would
//     bury the other one in a file with three hundred PROCESS-NAME rules.
//   - matches-everything is rare and dangerous, so every such rule is named individually with
//     its own text. A rule written to single out one process has become the broadest rule in
//     the file and kept its action: DIRECT bypasses everything, REJECT rejects everything.
//     Summarising that by kind would hide which rule it is.
func ownerMetadataRuleDeviations(root map[string]any, policy appleRuntimePolicy) []configDeviation {
	if !policy.networkExtension {
		return nil
	}
	rules, _ := root["rules"].([]any)
	capability := policy.processMetadata()

	reported := make([]configDeviation, 0)
	inertKinds := make(map[string]int)
	firstInert := make(map[string]string)
	for index, entry := range rules {
		text, isString := entry.(string)
		if !isString {
			continue
		}
		kind, _ := splitRuleKindAndPattern(text)
		if matchesMetadataRuleKindName(kind) == "" || capability.resolves(kind) {
			continue
		}
		switch ownerMetadataRuleEffect(text) {
		case RuleEffectMatchesEverything:
			reported = append(reported, configDeviation{
				Field:     fmt.Sprintf("rules[%d]", index),
				Given:     text,
				Effective: "this rule matches every connection on this platform, with its action unchanged",
				Category:  deviationUnavailable,
				Effect:    RuleEffectMatchesEverything,
				Reason: "the pattern matches an empty process name, and this platform supplies " +
					"none, so a rule written to single out one process is now the broadest rule " +
					"in the file",
				Source:      "upstream rules/common/process.go Match compares the pattern against metadata.Process, which no Apple packet tunnel populates",
				Recoverable: true,
				Written:     true,
				RuleKind:    kind,
				Alternative: "anchor the pattern so it cannot match an empty name, or remove the rule",
			})
		case RuleEffectNeverMatches:
			if _, seen := inertKinds[kind]; !seen {
				firstInert[kind] = fmt.Sprintf("rules[%d]", index)
			}
			inertKinds[kind]++
		}
	}
	for kind, count := range inertKinds {
		// The field is the address in the file -- "rules" -- and the kind rides in RuleKind.
		// It used to be "<KIND> rules", a phrase: the clients' page filters match on the key or
		// a dotted prefix, so every one of these rows matched no page and was shown nowhere.
		field := "rules"
		given := fmt.Sprintf("%d rule(s), first at %s", count, firstInert[kind])
		if count == 1 {
			given = firstInert[kind]
		}
		reported = append(reported, configDeviation{
			Field:       field,
			Given:       given,
			Effective:   "these rules never match on this platform; traffic falls through to the next rule",
			Category:    deviationUnavailable,
			Effect:      RuleEffectNeverMatches,
			Reason:      "the metadata they test is not available to an Apple packet tunnel, so the comparison never succeeds",
			Source:      "upstream rules/common Match reads metadata this platform does not populate; the rules are kept rather than removed so logic rules keep their executable branches",
			Recoverable: false,
			Written:     true,
			RuleKind:    kind,
		})
	}
	// UID is the tenth kind and the one that is REMOVED rather than kept: upstream refuses to
	// construct it here, and a logic rule carrying a UID branch goes whole. The other nine are
	// harmless; this is the one removal that changes what matches, so it is the row a reader
	// most needs -- and it was the row the report never issued.
	if !capability.resolves("UID") {
		if registration := deviationRuleByKind("UID"); registration != nil &&
			(registration.applies == nil || registration.applies(policy)) {
			count, first := uidRuleOccurrences(root)
			if count > 0 {
				given := fmt.Sprintf("%d rule(s), first at %s", count, first)
				if count == 1 {
					given = first
				}
				reported = append(reported, configDeviation{
					Field:       registration.field,
					Given:       given,
					Effective:   registration.effective,
					Category:    registration.category,
					Reason:      registration.reason,
					Source:      registration.source,
					Recoverable: registration.recoverable,
					Alternative: registration.alternative,
					Mechanism:   registration.mechanism,
					Written:     true,
					RuleKind:    registration.ruleKind,
				})
			}
		}
	}
	sort.Slice(reported, func(i, j int) bool {
		if reported[i].Field != reported[j].Field {
			return reported[i].Field < reported[j].Field
		}
		return reported[i].RuleKind < reported[j].RuleKind
	})
	return reported
}

// deviationRuleByKind is the rule-scan registration for a rule kind, or nil.
func deviationRuleByKind(kind string) *deviationRule {
	for i := range deviationRules {
		if deviationRules[i].ruleScan && deviationRules[i].ruleKind == kind {
			return &deviationRules[i]
		}
	}
	return nil
}

// deviationRuleByField is the registration for a field, or nil.
func deviationRuleByField(field string) *deviationRule {
	for i := range deviationRules {
		if deviationRules[i].field == field {
			return &deviationRules[i]
		}
	}
	return nil
}

// uidRuleOccurrences counts the rules stripUnconstructibleUIDRules would remove -- plain UID
// rules and logic rules carrying a UID branch -- in rules and in every sub-rules list, by the
// same test (ruleCarriesUID), so the report and the removal cannot disagree about which
// rules are meant. first is the location of the first one, rules[i] or sub-rules.<name>[i].
func uidRuleOccurrences(root map[string]any) (count int, first string) {
	scan := func(entries []any, location func(int) string) {
		for index, entry := range entries {
			text, isString := entry.(string)
			if !isString || !ruleCarriesUID(text) {
				continue
			}
			if count == 0 {
				first = location(index)
			}
			count++
		}
	}
	rules, _ := root["rules"].([]any)
	scan(rules, func(i int) string { return fmt.Sprintf("rules[%d]", i) })
	if subRules, ok := root["sub-rules"].(map[string]any); ok {
		names := make([]string, 0, len(subRules))
		for name := range subRules {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			list, _ := subRules[name].([]any)
			scan(list, func(i int) string { return fmt.Sprintf("sub-rules.%s[%d]", name, i) })
		}
	}
	return count, first
}

// lookupYAMLPath walks a dotted path and renders the leaf. It reports absence rather than a
// zero value, because "the user did not write this" and "the user wrote the default" are
// different facts and only the second is worth a line in the report.
func lookupYAMLPath(root map[string]any, path string) (string, bool) {
	current := any(root)
	for _, segment := range strings.Split(path, ".") {
		node, isMap := current.(map[string]any)
		if !isMap {
			return "", false
		}
		value, present := node[segment]
		if !present {
			return "", false
		}
		current = value
	}
	if current == nil {
		return "", false
	}
	return renderDeviationValue(current), true
}

// deviationValueWithheld is what a credential-bearing field renders as. It still answers the
// reader's first question -- did this core see my value at all -- without answering it to
// whoever else can read the log.
const deviationValueWithheld = "set (value withheld)"

func renderDeviationValue(value any) string {
	switch typed := value.(type) {
	case string:
		if typed == "" {
			return `""`
		}
		return typed
	case []any:
		return fmt.Sprintf("%d entries", len(typed))
	case map[string]any:
		return fmt.Sprintf("%d keys", len(typed))
	default:
		return fmt.Sprintf("%v", typed)
	}
}

// publishedDeviations holds what the running core decided, so a client can ask after Start
// rather than only before it. The plan is computed against a candidate configuration; this is
// the one that is actually running.
var publishedDeviations atomic.Pointer[publishedDeviationReport]

// The two runtime entry points that publish. CheckConfig is deliberately not one of them.
const (
	deviationEntryStart  = "start"
	deviationEntryReload = "reload"
)

// deviationDocumentIdentity names the document a report describes: its length and SHA-256,
// the same two numbers the client can compute over the text it handed to Start or Reload.
type deviationDocumentIdentity struct {
	Bytes  int    `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// publishedDeviationReport is what one runtime parse published: the rows, and enough
// identity to tell WHICH parse. The identity is the repair for a false all-clear seen on a
// device: Start published four rows for the reader's file, a later parse of a
// document that already carried the forced values published zero, and the endpoint then
// served the zero -- correctly, for that document -- to a client that took it as "every field
// in your file was honoured". Carrying the old rows forward would have lied the other way
// round (a reader who removes tun.mtu and reloads must see the row go). The kernel cannot
// tell the two zero-row cases apart from the document alone; the client can, by comparing
// the SHA-256 here with the SHA-256 of the document it handed over.
type publishedDeviationReport struct {
	// Sequence counts publishes in this process, from 1. A client that sees it go backwards
	// or reset is talking to a different process than before.
	Sequence uint64
	// Entry is deviationEntryStart or deviationEntryReload.
	Entry      string
	Document   deviationDocumentIdentity
	Deviations []configDeviation
}

var deviationPublishSequence atomic.Uint64

// publishDeviations records what one runtime parse of content did and logs it in the
// core's own register: one summary line per publish -- zero rows included, because a publish
// that logs nothing is invisible afterwards, which is how stayed hidden -- and one line
// per row naming the field, the values and the mechanism. These lines are diagnostics; the
// reader-facing sentence lives in the served JSON and is the client's to present.
func publishDeviations(entry, content string, deviations []configDeviation) *publishedDeviationReport {
	sum := sha256.Sum256([]byte(content))
	report := &publishedDeviationReport{
		Sequence:   deviationPublishSequence.Add(1),
		Entry:      entry,
		Document:   deviationDocumentIdentity{Bytes: len(content), SHA256: hex.EncodeToString(sum[:])},
		Deviations: deviations,
	}
	publishedDeviations.Store(report)
	log.Infoln("[Apple] deviations published: entry=%s seq=%d document=%dB sha256=%s rows=%d",
		entry, report.Sequence, report.Document.Bytes, report.Document.SHA256[:16], len(deviations))
	for _, deviation := range deviations {
		log.Warnln("[Apple] deviation %s: given=%q effective=%q category=%s -- %s",
			deviation.Field, deviation.Given, deviation.Effective, deviation.Category, deviationWhy(deviation))
	}
	return report
}

// deviationWhy is the developer-register explanation for the log: the mechanism where a rule
// has one, the reason otherwise. Rules without a mechanism twin are the ones whose reason
// already says which guard did what.
func deviationWhy(deviation configDeviation) string {
	if deviation.Mechanism != "" {
		return deviation.Mechanism
	}
	return deviation.Reason
}

// loadPublishedDeviationReport is the last publish, or nil before the first one.
func loadPublishedDeviationReport() *publishedDeviationReport {
	return publishedDeviations.Load()
}

// loadPublishedDeviations is the rows of the last publish; an empty list, never nil, before
// the first one.
func loadPublishedDeviations() []configDeviation {
	if report := publishedDeviations.Load(); report != nil {
		return report.Deviations
	}
	return []configDeviation{}
}

// dnsHijackAlreadyHijacksAll reports whether tun.dns-hijack, as written, is already the
// hijack-everything set the core forces (0.0.0.0:53 or any:53 alone). Written that way,
// forcing it is not a change.
func dnsHijackAlreadyHijacksAll(root map[string]any) bool {
	tun, _ := root["tun"].(map[string]any)
	list, ok := tun["dns-hijack"].([]any)
	if !ok || len(list) != 1 {
		return false
	}
	v, _ := list[0].(string)
	return v == "0.0.0.0:53" || v == "any:53"
}
