package hako

import (
	"fmt"
	"strings"
	"sync/atomic"
)

// RuntimeProfile values select the Apple execution environment whose
// capabilities configuration normalization and process policy must honor.
// Empty remains an alias for iosPacketTunnel so existing SDK consumers keep
// their exact behavior when they adopt a framework containing this field.
const (
	RuntimeProfileIOSPacketTunnel   = "iosPacketTunnel"
	RuntimeProfileMacOSPacketTunnel = "macosPacketTunnel"
	RuntimeProfileMacOSApplication  = "macosApplication"
	// RuntimeProfileTVOSPacketTunnel began as a seat rather than a measurement,
	// and is now one measurement and a seat.
	//
	// Measured: a third-party process on tvOS cannot bind an AF_UNIX socket
	// anywhere, so bindsUnixControlSocket is false. Everything else is
	// still the iOS value on loan, because nothing else about an Apple TV Network
	// Extension has been measured -- not the memory ceiling
	// (os_proc_available_memory is API_AVAILABLE(tvos(13.0)) and has never been
	// read on the device), not whether the App Group container tvOS hands the
	// core survives a reboot or storage pressure. Inheriting the tighter
	// platform's behavior is the conservative choice while that is unknown; it
	// is NOT a finding that the two platforms are alike.
	//
	// Before this seat existed tvOS arrived here as iOS, because the adapter
	// that declares the profile branched on macOS and let everything else fall
	// through to the iOS one. That worked, and it left every number and every
	// log line unable to say which platform it came from. The seat is what the
	// eventual measurements land in.
	RuntimeProfileTVOSPacketTunnel = "tvosPacketTunnel"
)

type runtimeProfile uint32

const (
	runtimeProfileIOSPacketTunnel runtimeProfile = iota
	runtimeProfileMacOSPacketTunnel
	runtimeProfileMacOSApplication
	// Appended last on purpose: the value is stored in setupRuntimeProfile as
	// a uint32, so inserting above would renumber the macOS profiles under any
	// caller that already committed one.
	runtimeProfileTVOSPacketTunnel
)

// Zero is intentionally the legacy iOS profile. It keeps pre-Profile callers
// and tests on the established fail-closed Network Extension policy.
var setupRuntimeProfile atomic.Uint32

// appleRuntimePolicy is the capability matrix consumed by configuration and
// runtime finalization. Runtime profile and actual process placement remain
// separate: containing-App preflight can apply a Packet Tunnel policy without
// itself running under Network Extension.
type appleRuntimePolicy struct {
	profile                   runtimeProfile
	networkExtension          bool
	packetTunnel              bool
	trustedProcessMetadata    bool
	requirePacketTunnelDNS    bool
	memoryConservativeGeodata bool
	compiledGeoSiteOnly       bool
	compiledGeoIPOnly         bool
	useSystemDNS              bool
	repairPacketTunnelDNS     bool
	// bindsUnixControlSocket is whether this profile opens the binding's own
	// App Group Unix socket for the containing app to reach the
	// controller through.
	//
	// False on tvOS, and that is a platform wall rather than a choice. Measured
	// on an Apple TV 4K running tvOS 26.6: a third-party process cannot bind an
	// AF_UNIX socket anywhere on the filesystem -- nine candidate paths across
	// the App Group container, the app container and their Caches directories,
	// every one EPERM. Upstream sing-box carries the same split and says so in
	// one line (experimental/libbox/command_server.go: `if !sTVOS {
	// listenUNIX() } else { listenTCP() }`).
	//
	// Nothing replaces it here, unlike sing-box's loopback TCP on 127.0.0.1:8964.
	// The tvOS app reaches the core through the provider message IPC, which never
	// touches this socket, so a listener would be an open surface answering
	// nobody -- was the session that learned what an unexamined
	// listening surface costs.
	bindsUnixControlSocket bool
}

func normalizeRuntimeProfile(value string) (runtimeProfile, error) {
	switch value {
	case "", RuntimeProfileIOSPacketTunnel:
		return runtimeProfileIOSPacketTunnel, nil
	case RuntimeProfileMacOSPacketTunnel:
		return runtimeProfileMacOSPacketTunnel, nil
	case RuntimeProfileMacOSApplication:
		return runtimeProfileMacOSApplication, nil
	case RuntimeProfileTVOSPacketTunnel:
		return runtimeProfileTVOSPacketTunnel, nil
	default:
		return runtimeProfileIOSPacketTunnel, fmt.Errorf(
			"hako: invalid SetupOptions.RuntimeProfile %q; expected %q, %q, %q or %q",
			value,
			RuntimeProfileIOSPacketTunnel,
			RuntimeProfileMacOSPacketTunnel,
			RuntimeProfileMacOSApplication,
			RuntimeProfileTVOSPacketTunnel,
		)
	}
}

// inheritsIOSPacketTunnelBehavior reports whether this profile takes the iOS
// packet tunnel's behavior wholesale.
//
// It exists because the policy struct is not where all the behavior lives. Two
// shipping gates decided by comparing the profile against the iOS constant, and
// both would have flipped the day a tvOS seat appeared -- without anyone
// choosing that:
//
//   - the geo updater ran wherever the profile was not iOS, so a tvOS seat
//     would have started a 17 MB GeoIP.dat fetch and unpack inside a Network
//     Extension whose ceiling has never been measured;
//   - the self-expiring pause timer armed only for iOS, so a tvOS seat would
//     have removed it and left a tvOS pause waiting on a wake() that may never
//     arrive.
//
// Asking this instead keeps "tvOS carries the iOS values" one fact in one
// place. When a measurement finally splits the two platforms, it splits here.
func (profile runtimeProfile) inheritsIOSPacketTunnelBehavior() bool {
	return profile == runtimeProfileIOSPacketTunnel || profile == runtimeProfileTVOSPacketTunnel
}

func currentRuntimeProfile() runtimeProfile {
	return runtimeProfile(setupRuntimeProfile.Load())
}

// allRuntimeProfiles enumerates every declared profile, derived from the enum
// rather than written out by hand.
//
// The capability matrix generated from these values documents itself as the
// only per-profile machine truth, and its test as what goes red on drift. With
// a hand-written list that claim had exactly one hole, and it was the one that
// mattered: a profile added to the enum was never asked for its policy, so it
// never appeared in the matrix and nothing went red. Deriving the list closes
// it -- a new profile is now documented by existing.
func allRuntimeProfiles() []runtimeProfile {
	var profiles []runtimeProfile
	for value := runtimeProfile(0); ; value++ {
		if strings.HasPrefix(value.String(), "unknown(") {
			return profiles
		}
		profiles = append(profiles, value)
	}
}

// appleProcessMetadataCapability records WHICH kinds of connection-owner metadata a profile
// can actually resolve. One boolean per source, because the ten rule kinds that need owner
// metadata do NOT share a source and a single flag over-enables:
//
//   - processPath covers PROCESS-NAME/-PATH and their REGEX/WILDCARD variants. On darwin
//     mihomo resolves these itself, in-process, from the socket table
//     (component/process/process_darwin.go reads net.inet.{tcp,udp}.pcblist_n, takes
//     xsocket_n.so_last_pid, then proc_pidpath). It does not ask the Network Extension for
//     anything, which is why "the NE exposes no process metadata" was the wrong reason to
//     disable it on macOS. Measured: the same two sysctls answer with com.apple.security
//     .app-sandbox true -- both macOS shapes carry that entitlement -- with a positive
//     control proving the sandbox was engaged. Surge reads the same two MIB names and ships
//     PROCESS-NAME rules as a headline macOS feature.
//   - socketUser covers UID. The darwin lookup DOES supply it, at xsocket_n.so_uid -- the field
//     immediately before the pid this code already read. It returned a hardcoded 0 until the uid
//     was ported from sing-box (searcher_darwin_shared.go reads it at the same base), which
//     silently broke every UID rule on darwin: uid 0 matched everything, any real uid matched
//     nothing.
//   - inboundUser covers IN-USER, and no Apple profile can ever resolve it. It is the user of an
//     INBOUND listener's authentication, which has nothing to do with a socket's owner. (The
//     older wording added "and every inbound listener is stripped anyway" -- that stopped being
// true when the zero-squeeze ruling restored the inbound surface. The reason above
//     never depended on it: a rule about the connection OWNER cannot be answered by an inbound
//     listener's credentials whether or not that listener exists.)
//   - codeSignature covers SOURCE-APP-SIGNING-ID/-TEAM-ID, which need an audit token. Only a
//     flow-level provider has one; a packet tunnel sees packets, not flows.
type appleProcessMetadataCapability struct {
	processPath   bool
	socketUser    bool
	inboundUser   bool
	codeSignature bool
}

// processMetadata derives the capability from the profile.
//
// trustedProcessMetadata means the platform hands the identity over rather than requiring a
// lookup, which is every source at once. Only the containing-App preflight profile has it now:
// it validates configuration without owning a data plane, so it must accept every rule kind
// the shipping profiles might execute rather than pre-strip on its own behalf.
//
// The macOS Packet Tunnel gets processPath only, by doing the lookup itself. iOS gets
// nothing: it has neither a flow-level token nor a working socket table for other processes,
// and Surge's own manual says process rules are Mac-only and iOS ignores them.
func (p appleRuntimePolicy) processMetadata() appleProcessMetadataCapability {
	if p.trustedProcessMetadata {
		// Containing-App preflight: it owns no data plane and only validates configuration, so it
		// must accept every kind a shipping profile might execute rather than pre-strip on their
		// behalf. inboundUser included, even though nothing can execute it, because rejecting a
		// config here that the extension would merely no-op on would be worse.
		return appleProcessMetadataCapability{
			processPath: true, socketUser: true, inboundUser: true, codeSignature: true,
		}
	}
	if p.profile == runtimeProfileMacOSPacketTunnel {
		// PROCESS-NAME/-PATH and UID all come from the same socket-table read.
		return appleProcessMetadataCapability{processPath: true, socketUser: true}
	}
	return appleProcessMetadataCapability{}
}

// resolves reports whether the source a rule kind needs is available.
func (c appleProcessMetadataCapability) resolves(kind string) bool {
	switch strings.ToUpper(strings.TrimSpace(kind)) {
	case "PROCESS-NAME", "PROCESS-NAME-REGEX", "PROCESS-NAME-WILDCARD",
		"PROCESS-PATH", "PROCESS-PATH-REGEX", "PROCESS-PATH-WILDCARD":
		return c.processPath
	case "UID":
		return c.socketUser
	case "IN-USER":
		return c.inboundUser
	case "SOURCE-APP-SIGNING-ID", "SOURCE-APP-TEAM-ID":
		return c.codeSignature
	default:
		// Not an owner-metadata rule kind; nothing here decides its fate.
		return true
	}
}

func runtimePolicyFor(profile runtimeProfile, underNetworkExtension bool) appleRuntimePolicy {
	policy := appleRuntimePolicy{profile: profile}
	switch profile {
	case runtimeProfileTVOSPacketTunnel:
		// tvOS shared the arm below until 2026-08-16. Sharing was the right shape
		// while the two were identical -- it made "identical to iOS" structural
		// instead of a coincidence the next edit to either half could break --
		// and it stopped being available the moment a device measured them apart.
		// What replaces that guarantee is a test comparing the two structs field
		// by field, so the sharing is now enforced from outside rather than by
		// the arms literally being one.
		//
		// Split deliberately: the seat was
		// created carrying the iOS values on loan until a device said otherwise
		// and an Apple TV said otherwise about exactly one of them.
		// Everything else here is still the iOS answer, and a test compares the
		// two structs field by field so the next divergence is also an edit
		// someone had to make on purpose.
		policy.networkExtension = underNetworkExtension
		policy.packetTunnel = true
		policy.requirePacketTunnelDNS = underNetworkExtension
		policy.repairPacketTunnelDNS = underNetworkExtension
		policy.memoryConservativeGeodata = true
		policy.compiledGeoSiteOnly = underNetworkExtension
		policy.compiledGeoIPOnly = underNetworkExtension
	case runtimeProfileIOSPacketTunnel:
		policy.bindsUnixControlSocket = true
		policy.networkExtension = underNetworkExtension
		policy.packetTunnel = true
		policy.requirePacketTunnelDNS = underNetworkExtension
		// Requiring core DNS without supplying it is a demand the reader cannot
		// meet. mihomo defaults dns.enable to false, so an ordinary upstream
		// config — the majority of what subscriptions publish — simply omits
		// the block; iOS then refused it outright while macOS, one line below,
		// repaired the same config and started. The requirement is real (a
		// packet tunnel's NEDNSSettings points at the core resolver, so DNS has
		// to stay inside the core), but a requirement with a known repair is
		// not a reason to refuse.
		policy.repairPacketTunnelDNS = underNetworkExtension
		policy.memoryConservativeGeodata = true
		// Building a geosite category from source peaks at 72.7 MiB; this
		// process is allowed 50 MiB in total. It is not a budget to be careful
		// with, it is a budget the work does not fit in, so the tunnel reads
		// what the App compiled and never reaches for the source. The App runs
		// the same profile without this flag, which is where compiling happens.
		policy.compiledGeoSiteOnly = underNetworkExtension
		// The same for GeoIP, measured the same way: decoding geoip:us peaks at
		// 130 MiB and every country code the shipped file holds peaks at 164 MiB,
		// against the same 50 MiB. What it produces was never the problem -- all
		// 260 matchers weigh 27.9 MiB resident and read back from artifacts at a
		// 35.7 MiB peak -- so the tunnel reads what the App compiled.
		policy.compiledGeoIPOnly = underNetworkExtension
		// Rule sets are deliberately NOT on this list. Geodata is here because
		// the work cannot fit -- building a geosite category peaks at 72.7 MiB
		// against 50 -- and because the App compiles it, so the reader loses
		// nothing. A refused rule set is a different shape: keeping its source
		// online usually costs almost nothing (a real subscription set is a
		// couple of kilobytes), and staging it empty withheld a capability the
		// core has, on every set, because the largest conceivable one might not
		// fit. Ruling of 2026-08-22: do not withhold the feature to protect a
		// resource the reader can manage. A set that will not fit fails to
		// start and says so, and the reader trims it -- the way a full disk
		// stops an install instead of removing the store.
	case runtimeProfileMacOSPacketTunnel:
		policy.bindsUnixControlSocket = true
		policy.networkExtension = underNetworkExtension
		policy.packetTunnel = true
		policy.requirePacketTunnelDNS = underNetworkExtension
		policy.repairPacketTunnelDNS = underNetworkExtension
	case runtimeProfileMacOSApplication:
		policy.bindsUnixControlSocket = true
		policy.trustedProcessMetadata = true
		policy.useSystemDNS = true
	}
	return policy
}

func currentRuntimePolicy(underNetworkExtension bool) appleRuntimePolicy {
	return runtimePolicyFor(currentRuntimeProfile(), underNetworkExtension)
}

func (profile runtimeProfile) String() string {
	switch profile {
	case runtimeProfileIOSPacketTunnel:
		return RuntimeProfileIOSPacketTunnel
	case runtimeProfileMacOSPacketTunnel:
		return RuntimeProfileMacOSPacketTunnel
	case runtimeProfileMacOSApplication:
		return RuntimeProfileMacOSApplication
	case runtimeProfileTVOSPacketTunnel:
		return RuntimeProfileTVOSPacketTunnel
	default:
		return fmt.Sprintf("unknown(%d)", profile)
	}
}
