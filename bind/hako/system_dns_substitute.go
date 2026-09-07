package hako

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/TokenPLS/Hako/common/orderedmap"
	"github.com/TokenPLS/Hako/config"
)

// systemDNSSubstitutes is SetupOptions.SystemDNSServerLines, parsed: the resolvers that take
// the place of every `system` / `dhcp://` nameserver entry inside a packet tunnel (issue #21).
// Nil or empty means no substitution -- those entries are stripped, as they were before the
// option existed. Set by Setup, read by the configuration pipeline and by the plan, so the
// two report the same thing for the same process.
var systemDNSSubstitutes atomic.Pointer[[]string]

func systemDNSServerSubstitutes() []string {
	if p := systemDNSSubstitutes.Load(); p != nil {
		return *p
	}
	return nil
}

// parseSystemDNSServerLines accepts one resolver per line -- `ip`, `ip:port` or `[v6]:port` --
// ignores blank lines, and refuses anything else with the line number, so a bad line fails
// Setup instead of reaching mihomo as a nameserver it would parse as udp://hostname.
func parseSystemDNSServerLines(lines string) ([]string, error) {
	var out []string
	for i, line := range strings.Split(lines, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if ap, err := netip.ParseAddrPort(line); err == nil {
			if ap.Port() == 0 {
				return nil, fmt.Errorf("line %d: %q names port 0", i+1, line)
			}
			if ap.Addr().Zone() != "" {
				return nil, fmt.Errorf("line %d: %q carries an interface zone no tunnel can dial", i+1, line)
			}
			out = append(out, net.JoinHostPort(ap.Addr().Unmap().String(), strconv.Itoa(int(ap.Port()))))
			continue
		}
		addr, err := netip.ParseAddr(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %q is neither an IP address nor ip:port", i+1, line)
		}
		if addr.Zone() != "" {
			return nil, fmt.Errorf("line %d: %q carries an interface zone no tunnel can dial", i+1, line)
		}
		out = append(out, addr.Unmap().String())
	}
	return out, nil
}

// substituteAddr is the address inside a parsed line, or the zero Addr for a shape the
// parser never emits.
func substituteAddr(line string) netip.Addr {
	if ap, err := netip.ParseAddrPort(line); err == nil {
		return ap.Addr()
	}
	addr, _ := netip.ParseAddr(line)
	return addr
}

// tunnelPrefixesFromRaw is what this configuration makes the tunnel's own: the fake-ip
// ranges (parseTun derives the tun address, and so the NEDNSSettings address, from
// fake-ip-range) and the tun IPv6 addresses. tun.inet4-address is not a raw field upstream.
func tunnelPrefixesFromRaw(raw *config.RawConfig) []netip.Prefix {
	prefixes := append([]netip.Prefix(nil), raw.Tun.Inet6Address...)
	for _, s := range []string{raw.DNS.FakeIPRange, raw.DNS.FakeIPRange6} {
		if prefix, err := netip.ParsePrefix(strings.TrimSpace(s)); err == nil {
			prefixes = append(prefixes, prefix)
		}
	}
	return prefixes
}

// tunnelPrefixesFromRoot is tunnelPrefixesFromRaw over the plan's document tree, so the
// plan drops exactly the substitutes the runtime drops.
func tunnelPrefixesFromRoot(root map[string]any) []netip.Prefix {
	var prefixes []netip.Prefix
	add := func(v any) {
		walkStrings(v, func(s string) {
			if prefix, err := netip.ParsePrefix(strings.TrimSpace(s)); err == nil {
				prefixes = append(prefixes, prefix)
			}
		})
	}
	if tun, ok := root["tun"].(map[string]any); ok {
		add(tun["inet6-address"])
	}
	if dns, ok := root["dns"].(map[string]any); ok {
		add(dns["fake-ip-range"])
		add(dns["fake-ip-range6"])
	}
	return prefixes
}

// usableSystemResolverSubstitutes drops every supplied resolver that is the tunnel itself --
// by the product's default ranges or by this configuration's own. A list that names the
// tunnel was read after the tunnel's DNS settings applied; substituting it would reproduce
// issue #21 in a new shape, so those entries are reported and ignored.
func usableSystemResolverSubstitutes(supplied []string, prefixes []netip.Prefix) (usable, dropped []string) {
	for _, line := range supplied {
		addr := substituteAddr(line)
		if addr.IsValid() && (insideAnyPrefix(addr, tunnelOwnedPrefixes) || insideAnyPrefix(addr, prefixes)) {
			dropped = append(dropped, line)
			continue
		}
		usable = append(usable, line)
	}
	return usable, dropped
}

func usableSubstitutesFor(raw *config.RawConfig, supplied []string) []string {
	usable, _ := usableSystemResolverSubstitutes(supplied, tunnelPrefixesFromRaw(raw))
	return usable
}

func usableSubstitutesForRoot(root map[string]any) []string {
	usable, _ := usableSystemResolverSubstitutes(systemDNSServerSubstitutes(), tunnelPrefixesFromRoot(root))
	return usable
}

// systemResolverSubstitution records one system/dhcp entry the substitution replaced.
type systemResolverSubstitution struct {
	field string // the dns.* key
	key   string // the policy key, for the two policy maps
	entry string // the entry that was replaced, as written
}

func (s systemResolverSubstitution) where() string {
	if s.key != "" {
		return s.field + " " + s.key
	}
	return s.field
}

// substituteSystemResolvers replaces, in place, every `system` / `dhcp://` entry in the seven
// resolver slots the strip reaches (stripNEIncompatibleNameservers) with the usable supplied
// resolvers. One expansion per list, at the first such entry: a second system-class entry in
// the same list names the same resolvers and is dropped rather than expanded twice. A policy
// whose entries were all system therefore keeps its domains on the system resolvers, where
// the strip alone would have failed them closed with rcode://name_error.
func substituteSystemResolvers(raw *config.RawConfig, usable []string) []systemResolverSubstitution {
	if len(usable) == 0 {
		return nil
	}
	changes := []systemResolverSubstitution{}
	replace := func(field, key string, list []string) []string {
		out := make([]string, 0, len(list)+len(usable))
		expanded := false
		for _, ns := range list {
			if !isNEIncompatibleNameserver(ns) {
				out = append(out, ns)
				continue
			}
			changes = append(changes, systemResolverSubstitution{field: field, key: key, entry: ns})
			if !expanded {
				out = append(out, usable...)
				expanded = true
			}
		}
		return out
	}
	raw.DNS.NameServer = replace("nameserver", "", raw.DNS.NameServer)
	raw.DNS.Fallback = replace("fallback", "", raw.DNS.Fallback)
	raw.DNS.ProxyServerNameserver = replace("proxy-server-nameserver", "", raw.DNS.ProxyServerNameserver)
	raw.DNS.DirectNameServer = replace("direct-nameserver", "", raw.DNS.DirectNameServer)
	raw.DNS.DefaultNameserver = replace("default-nameserver", "", raw.DNS.DefaultNameserver)
	replacePolicy := func(field string, policy *orderedmap.OrderedMap[string, any]) {
		if policy == nil {
			return
		}
		type edit struct {
			key   string
			value []any
		}
		var edits []edit
		for pair := policy.Oldest(); pair != nil; pair = pair.Next() {
			servers := dnsServerStrings(pair.Value)
			if len(servers) == 0 {
				continue
			}
			before := len(changes)
			replaced := replace(field, pair.Key, servers)
			if len(changes) == before {
				continue
			}
			value := make([]any, 0, len(replaced))
			for _, ns := range replaced {
				value = append(value, ns)
			}
			edits = append(edits, edit{key: pair.Key, value: value})
		}
		for _, e := range edits {
			policy.Set(e.key, e.value)
		}
	}
	replacePolicy("nameserver-policy", raw.DNS.NameServerPolicy)
	replacePolicy("proxy-server-nameserver-policy", raw.DNS.ProxyServerNameserverPolicy)
	return changes
}
