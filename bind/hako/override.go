package hako

import (
	"net"

	"github.com/TokenPLS/Hako/component/process"
	"github.com/TokenPLS/Hako/config"
	C "github.com/TokenPLS/Hako/constant"
	LC "github.com/TokenPLS/Hako/listener/config"
)

// overrideForIOS applies post-parse struct-level overrides — never YAML/map
// merging, never re-marshalling. Keeps the core off anything the NE
// model owns. Tun.Enable is intentionally NOT touched here: Start decides
// tun vs no-tun from the parsed config and, when enabled, injects the dup fd
// BEFORE this runs. Forced tun sub-params (stack/mtu/…) land in
// dns/process/geo policy.
func overrideForIOS(cfg *config.Config) {
	overrideForAppleConfig(cfg, runtimePolicyFor(runtimeProfileIOSPacketTunnel, false))
}

func overrideForAppleConfig(cfg *config.Config, policy appleRuntimePolicy) {
	// Geo auto-update spawns a periodic in-core downloader; NE policy is
	// app-side pre-download only.
	cfg.General.GeoAutoUpdate = false

	// find-process-mode is forced off only where the owner of a connection cannot be
	// named at all. The original reason recorded here -- "the NE
	// sandbox denies the sysctl/libproc calls process matching needs" -- is wrong on
	// macOS twice over: mihomo does not ask the Network Extension for anything (it reads
	// net.inet.{tcp,udp}.pcblist_n itself), and the App Sandbox does not deny those reads.
	// That was measured with a binary signed com.apple.security.app-sandbox true, the
	// entitlement both macOS shapes ship, with a positive control proving the sandbox was
	// engaged. Surge reads the identical two MIB names from its own macOS client.
	//
	// So iOS keeps the force -- it has no flow-level token and process rules are Mac-only
	// upstream too -- while a macOS Packet Tunnel keeps whatever was configured. mihomo's
	// default is Strict (config.go:498), which looks up only when a rule needs it.
	if !policy.processMetadata().processPath {
		cfg.General.FindProcessMode = process.FindProcessOff
	}

	// The iOS Packet Tunnel keeps the mmap-backed memconservative loader
	// for the jetsam budget. macOS profiles preserve the
	// parsed loader because they do not share that memory model. Files remain
	// pre-downloaded app-side and GeoAutoUpdate remains off for every profile.
	if policy.memoryConservativeGeodata {
		cfg.General.GeodataLoader = "memconservative"
	}

	// Only the dashboard fields are cleared, and only because they have a live consumer:
	// hub/executor/executor.go:455-456 hands them to updater.NewUiUpdater and AutoDownloadUI,
	// which starts an HTTP download inside the extension.
	//
	// The rest of the Controller object is left as parsed, and that is deliberately NOT the
	// same as honouring it. Nothing in this build dispatches it: executor.go:83 says in so
	// many words that ApplyConfig configures every part "without ExternalController", and
	// route.ReCreateServer is reached only from hub.Parse (a CLI path this binding never
	// takes) and from clash_api.go, which serves one binding-owned App Group unix socket
	// . GetGeneral and hub/route/configs.go do not echo these fields either.
	//
	// So external-controller and friends are carried and inert. Clearing them and keeping them
	// are equally unobservable -- which is exactly why the ledger must not call them "keep":
	// that word means the kernel consumes the field, and no consumer exists.
	if cfg.Controller != nil {
		// Nothing is cleared here any more. external-ui was the last field held back, and by
		// ("downloads happen app-side") rather than by the platform -- Apple does not stop
		// an extension from making an outbound request. Under the stated standard that is a
		// decision of ours, and the ruling is to behave as upstream does.
		//
		// What upstream does (component/updater/update_ui.go:51-77): naming the path or the name
		// arms the auto-download, and AutoDownloadUI fetches ONLY when the directory is empty.
		// In this product's normal flow the app materialises the dashboard first, so nothing is
		// fetched inside the extension; the download is the fallback for a directory nobody
		// filled.'s hold on geo and providers is untouched by this.
		_ = cfg.Controller
	}

	// Every Network Extension profile is a Packet Tunnel now, so there is no
	// !packetTunnel branch to take. It went with the Transparent Proxy profile.
	if policy.packetTunnel && cfg.General.Tun.Enable {
		overrideTunForIOS(&cfg.General.Tun)
	}
}

// overrideForNetworkExtension removes local proxy/server surfaces which have
// no role in a packet-tunnel provider. The App/macOS process keeps its parsed
// inbounds for no-tun runs and integration probes.
func overrideForNetworkExtension(cfg *config.Config) {
	if cfg.General != nil {
		// Field by field, not by replacing the struct. Replacing it wiped the ten local-proxy
		// fields the raw layer deliberately lets through -- port, socks-port, mixed-port,
		// allow-lan, bind-address, skip-auth-prefixes, lan-allowed-ips, lan-disallowed-ips,
		// inbound-tfo, inbound-mptcp -- so the batch that opened them changed the parse output
		// and nothing else. hub/executor's updateListeners reads General.Port/MixedPort/...,
		// and zero is exactly what ReCreateMixed treats as "no listener": the configuration
		// said 7890, this core's own warning said the listener was LAN-reachable, and nothing
		// was listening. Found on a device by the consuming lane, not here.
		//
		// bind-address is not pinned either. genAddr (listener/listener.go:709-718) only
		// produces ":port" -- every interface -- when the host is "*" or empty, so forcing
		// 127.0.0.1 made allow-lan a no-op even with the port alive and the permission
		// granted. Upstream's default is "*"; a user who wants loopback writes it.
		//
		// What is cleared here is only what the raw layer already cleared, kept as defence in
		// depth so a future raw-layer edit cannot open a server surface by omission.
		cfg.General.RedirPort = 0
		cfg.General.TProxyPort = 0
		cfg.General.Interface = ""
		cfg.General.RoutingMark = 0
	}
	if cfg.DNS != nil {
		// Listen is deliberately absent: the configured DNS server is honoured now, and this
		// layer is where the previous opening was left half-done -- the raw layer let the local
		// proxy ports through while this function put them back, so the parse output looked
		// right and nothing listened on the device.
		cfg.DNS.ListenRoutingMark = 0
	}
	if cfg.IPTables != nil {
		cfg.IPTables.Enable = false
	}
	if cfg.NTP != nil {
		cfg.NTP.WriteToSystem = false
	}
}

// ensureTunEnabled makes any config a tun VPN inside the NE: a
// packet-tunnel extension always captures traffic via utun, while the user's
// config typically only supplies proxies/rules/dns (local-proxy shape, e.g.
// mixed-port). Called from Start only when the platform is under the NE, so
// app-process/no-tun paths are untouched.
//
// It deliberately sets nothing but Enable. It used to refill Inet4Address and
// Inet6Address from local defaults, and both were wrong:
//
//   - inet4 was dead. Upstream's parseTun always assigns one, derived from
//     dns.fake-ip-range or its 198.18.0.1/16 fallback, so a parsed config never
//     arrives without it and the local 172.19.0.1/30 could not be reached.
//   - inet6 was a silent override of the user. config/config.go parseIPV6
//     clears Tun.Inet6Address when `ipv6: false`, or when ipv6 is true but
//     verifyIP6() finds no global-unicast v6 address on this host. Refilling it
//     handed the extension a v6 address, which ExtensionProvider turns into
//     NEIPv6Settings and a ::/0 default route -- claiming all v6 traffic for a
//     core running with DisableIPv6, which answers no AAAA and proxies no v6.
//
// A guard on cfg.General.IPv6 alone would not have been enough: upstream's
// condition is two terms, and the second one is about this host, not the config.
func ensureTunEnabled(tun *LC.Tun) {
	tun.Enable = true
}

// overrideTunForIOS pins the tun parameters the NE model requires, regardless
// of what the source config asked for. Runs only when
// tun is enabled and the fd is already injected.
func overrideTunForIOS(tun *LC.Tun) {
	// tun.stack is NOT set here any more, and the deletion is the whole change.
	//
	// It used to be forced to gVisor unconditionally, on a reason that was already known to be
	// wrong about the platform. The comment that stood here since 2026-07-26 recorded the
	// measurement itself: the System stack's start() was read line by line and every capability
	// it needs was exercised under this provider's own entitlements, against a real utun this
	// process does not own, with a positive control proving the sandbox was engaged --
	// fixWindowsFirewall (no-op on darwin), BindToInterface0 for both families, listening on the
	// tun's own address, the wildcard listen branch, NewNat/NewDirectRouteMapping. Nothing in it
	// is denied to a sandboxed Network Extension.
	//
	// What kept the force alive after that was a cost I wrote down without checking: "swapping
	// the stack invalidates the device A/B that fixed ProcessorsPerChannel=1, so it needs
	// re-establishing on hardware." True of changing the DEFAULT. False of honouring an explicit
	// value, because constant/tun.go:15 makes TunGvisor the zero value -- a configuration that
	// never mentions tun.stack already parses to gVisor with nothing here to help it. The
	// measured working point is untouched for everyone who did not ask, and
	// ProcessorsPerChannel lives on the gVisor path anyway
	// (third_party/sing-tun/tun_darwin_gvisor.go).
	//
	// So the default stays exactly where the A/B left it, and someone who writes `stack: system`
	// gets system: upstream allows it, the platform allows it. The consuming lane found the zero
	// value; the cost had been on record here for two weeks without anyone testing it.
	//
	// Upstream's own Apple default being Mixed is still not a reason to move anything: stack.go
	// picks gVisor under IncludeAllNetworks, Mixed when WithGVisor && !GSO, System otherwise, so
	// Mixed is simply where sing-box lands with includeAllNetworks false. Matching a fallback is
	// not a decision. See in
	// The Release data plane is NEPacketTunnelFlow bridged through an internal
	// SOCK_DGRAM fd. It is deliberately not an Apple utun descriptor.
	tun.Device = packetFlowBridgeDevice
	// Include All Networks: the system and mixed stacks re-inject the tunnel's TCP through
	// the kernel, and under the setting the kernel drops exactly those packets, so gVisor is
	// the only stack that carries traffic. The move is reported on tun.stack
	// (config_deviations.go) and sing-tun is told the setting as well, so a stack this line
	// does not catch fails at Start instead of running silently (include_all_networks.go).
	if includeAllNetworksActive() && (tun.Stack == C.TunSystem || tun.Stack == C.TunMixed) {
		tun.Stack = C.TunGvisor
	}
	// Single startup-selected MTU, shared with Swift via TunOptions.GetMTU.
	// Source YAML cannot override the Apple/Core invariant.
	tun.MTU = uint32(effectiveTunMTU())
	// Routing belongs to NEPacketTunnelNetworkSettings, not the core: the
	// utun is owned by the NE. Swift installs the routes.
	tun.AutoRoute = false
	tun.AutoDetectInterface = false
	// NE utun has no GSO.
	tun.GSO = false
	tun.GSOMaxSize = 0
	// recvmsg_x/sendmsg_x contain utun-specific socket options in sing-tun.
	// The public PacketFlow bridge preserves packet boundaries with SOCK_DGRAM
	// and uses the ordinary readv/writev path instead.
	tun.RecvMsgX = false
	tun.SendMsgX = false
	// NE has no raw ICMP socket; the fork answers with a fake ping echo
	// instead of forwarding.
	tun.DisableICMPForwarding = true

	// DNS single-source: the address we advertise to
	// NEDNSSettings is the tun gateway +1 (TunOptions.GetDNSServerAddress).
	// Force hijack-all so that address — and every other DNS query through
	// the tunnel — is caught by the core (no DNS leak past the VPN). The
	// invariant "advertised DNS ∈ hijack set" is asserted by dnsHijackCovers.
	tun.DNSHijack = []string{"0.0.0.0:53"}
}

// dnsHijackCovers reports whether the DNS server address advertised to the NE
// (TunOptions.GetDNSServerAddress) is within the core's DNSHijack set — the
// single-source invariant. "0.0.0.0:53"/"any:53" cover any
// address; otherwise the host must match exactly.
func dnsHijackCovers(tun *LC.Tun) bool {
	// Hijack-all covers any advertised address, independent of the inet4 setup.
	for _, h := range tun.DNSHijack {
		if h == "0.0.0.0:53" || h == "any:53" {
			return true
		}
	}
	dns, err := newTunOptions(tun).GetDNSServerAddress()
	if err != nil {
		return false
	}
	for _, h := range tun.DNSHijack {
		if host, _, splitErr := net.SplitHostPort(h); splitErr == nil && host == dns.Value {
			return true
		}
	}
	return false
}
