//go:build darwin

package hako

import (
	"net"
	"net/netip"
	"os"
	"reflect"
	"testing"
)

// The routing socket answers for real on a Mac: loopback routes through lo0, and the
// default route names a non-loopback interface (skipped on a machine with no default route).
func TestRoutingSocketAnswersOnDarwin(t *testing.T) {
	lo0, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Skip("no lo0")
	}
	index, err := routeInterfaceIndex(netip.MustParseAddr("127.0.0.1"))
	if err != nil {
		t.Fatalf("RTM_GET 127.0.0.1: %v", err)
	}
	if index != lo0.Index {
		t.Fatalf("127.0.0.1 routes through interface %d, want lo0 (%d)", index, lo0.Index)
	}
	primary, err := defaultRouteInterfaceIndex()
	if err != nil {
		t.Skip("this machine has no default route")
	}
	iface, err := net.InterfaceByIndex(primary)
	if err != nil || iface.Flags&net.FlagLoopback != 0 {
		t.Fatalf("default route interface %d (%v, %v) is not a usable primary", primary, iface, err)
	}
	public, err := routeInterfaceIndex(netip.MustParseAddr("1.1.1.1"))
	if err != nil {
		t.Fatalf("RTM_GET 1.1.1.1: %v", err)
	}
	t.Logf("default route via %s; 1.1.1.1 via %s", iface.Name, interfaceNameByIndex(public))
}

// Where Tailscale runs, its MagicDNS address is routed through Tailscale's own utun and
// the default route is the physical interface: the exact reading from the reader's Mac.
// Skipped on a machine without that route, so it is evidence where it can be and silent
// where it cannot.
func TestMagicDNSIsDroppedWhereTailscaleRuns(t *testing.T) {
	magic := netip.MustParseAddr("100.100.100.100")
	index, err := routeInterfaceIndex(magic)
	if err != nil {
		t.Skipf("no route to MagicDNS here (%v)", err)
	}
	primary, err := defaultRouteInterfaceIndex()
	if err != nil {
		t.Skip("no default route here")
	}
	if index == primary {
		t.Skipf("MagicDNS routes through the primary interface %s here; nothing to prove", interfaceNameByIndex(primary))
	}
	got := reachableFromThePhysicalPath([]string{"100.100.100.100", "fd7a:115c:a1e0::53", "127.0.0.1"})
	for _, kept := range got {
		if kept == "100.100.100.100" {
			t.Fatalf("MagicDNS through %s was kept although the tunnel binds to %s: %v", interfaceNameByIndex(index), interfaceNameByIndex(primary), got)
		}
	}
	t.Logf("MagicDNS via %s dropped; primary %s; kept %v", interfaceNameByIndex(index), interfaceNameByIndex(primary), got)
}

// On a Mac the resolver library and /etc/resolv.conf read the same configuration, so the
// two sources must agree -- the file is the oracle for the library here, and the library
// is the only source on iOS.
func TestTheResolverLibraryAgreesWithTheFileOnMacOS(t *testing.T) {
	fromLibrary, err := libresolvResolvers()
	if err != nil {
		t.Fatalf("libresolv: %v", err)
	}
	file, err := os.Open("/etc/resolv.conf")
	if err != nil {
		t.Skipf("no /etc/resolv.conf here: %v", err)
	}
	defer file.Close()
	fromFile := readResolvConf(file)
	filtered := make([]string, 0, len(fromLibrary))
	for _, line := range fromLibrary {
		if addr := substituteAddr(line); addr.IsValid() && usableSystemResolver(addr) {
			filtered = append(filtered, line)
		}
	}
	if !reflect.DeepEqual(filtered, fromFile) {
		t.Fatalf("library %v (filtered %v) vs file %v", fromLibrary, filtered, fromFile)
	}
	t.Logf("library %v == file %v", filtered, fromFile)
}
