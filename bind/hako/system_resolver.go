package hako

import (
	"bufio"
	"io"
	"net/netip"
	"os"
	"strings"
)

// resolvConfPath is the file mihomo's own `system` nameserver reads (dns/system_posix.go:13).
// A variable only so a test can point it at a fixture.
var resolvConfPath = "/etc/resolv.conf"

// tunnelOwnedPrefixes are the ranges this product's packet tunnel occupies by default: the
// fake-ip range mihomo narrows to the tun address (198.18.0.1/16 -> /30, whose +1 is the
// NEDNSSettings address, config.go parseTun) with its RFC 2544 neighbour, and the default tun
// IPv6 address (fdfe:dcba:9876::1/126). A resolver inside them is the tunnel itself -- which
// is what /etc/resolv.conf lists once the tunnel's DNS settings have applied, the very reading
// behind issue #21. A configuration's own ranges are added at substitution time
// (tunnelPrefixesFromRaw); these are the ones known before any configuration is.
var tunnelOwnedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("fdfe:dcba:9876::/48"),
}

// SystemResolverLines returns the resolvers the OS lists right now, one per line in the
// OS's order, from the platform resolver library (res_ninit -- configd's DNS configuration,
// which /etc/resolv.conf mirrors on macOS and which is the only source on iOS, where that file
// does not exist), falling back to the file mihomo's `system` nameserver reads. Link-local, unspecified and
// multicast addresses go, and so does anything inside the tunnel's own ranges, because a
// resolv.conf read AFTER the tunnel's DNS settings applied lists only the tunnel's address
// (the packet-tunnel comment in config_pipeline.go has the measurement).
// A resolver the OS routes through an interface other than the default route's -- another
// VPN's resolver, Tailscale's MagicDNS -- goes too: the tunnel's sockets are bound to the
// physical interface and cannot reach it (reachableFromThePhysicalPath). Call it BEFORE
// applying tunnel network settings and hand the result to SetupOptions.SystemDNSServerLines;
// empty means the file lists nothing usable, or could not be read.
//
// It lives in the core so that no client target needs libresolv or a module map: the App
// reads through the same code path on every platform, and the file is the one the `system`
// nameserver would have consulted, not a second opinion about what "the system resolver" is.
func SystemResolverLines() string {
	return bridgeSafeString(strings.Join(reachableFromThePhysicalPath(systemResolverAddresses()), "\n"))
}

// platformResolvers is libresolvResolvers, as a variable so a test can stand in for the
// platform library.
var platformResolvers = libresolvResolvers

// systemResolverAddresses is the platform resolver library's list, filtered like the file's
// (usableSystemResolver), and the file's list where the library has nothing to say -- the
// two read the same configuration on macOS, and only the library exists on iOS.
func systemResolverAddresses() []string {
	if fromLibrary, err := platformResolvers(); err == nil && len(fromLibrary) != 0 {
		servers := make([]string, 0, len(fromLibrary))
		for _, line := range fromLibrary {
			if addr := substituteAddr(line); addr.IsValid() && usableSystemResolver(addr) {
				servers = append(servers, line)
			}
		}
		if len(servers) != 0 {
			return servers
		}
	}
	file, err := os.Open(resolvConfPath)
	if err != nil {
		return nil
	}
	defer func() { _ = file.Close() }()
	return readResolvConf(file)
}

// readResolvConf mirrors dns/system_posix.go dnsReadConfig -- `nameserver` lines only,
// comments skipped, the second field parsed as an address -- and then drops what no tunnel
// can dial.
func readResolvConf(r io.Reader) []string {
	var servers []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) > 0 && (line[0] == ';' || line[0] == '#') {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != "nameserver" {
			continue
		}
		addr, err := netip.ParseAddr(f[1])
		if err != nil || !usableSystemResolver(addr) {
			continue
		}
		servers = append(servers, addr.String())
	}
	return servers
}

func usableSystemResolver(addr netip.Addr) bool {
	addr = addr.Unmap()
	if addr.Zone() != "" || addr.IsLinkLocalUnicast() || addr.IsUnspecified() || addr.IsMulticast() {
		return false
	}
	return !insideAnyPrefix(addr, tunnelOwnedPrefixes)
}

func insideAnyPrefix(addr netip.Addr, prefixes []netip.Prefix) bool {
	addr = addr.Unmap()
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
