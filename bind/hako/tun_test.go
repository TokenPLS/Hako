package hako

import (
	"net/netip"
	"testing"

	LC "github.com/TokenPLS/Hako/listener/config"
)

func TestTunOptionsGetters(t *testing.T) {
	tun := &LC.Tun{
		Inet4Address:      []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")},
		Inet6Address:      []netip.Prefix{netip.MustParsePrefix("fdfe:dcba:9876::1/126")},
		MTU:               0, // exercise the effective setup MTU fallback
		AutoRoute:         true,
		Inet4RouteAddress: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		RouteAddress: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/8"),
			netip.MustParsePrefix("2001:db8::/32"),
		},
		RouteExcludeAddress: []netip.Prefix{
			netip.MustParsePrefix("192.168.0.0/16"),
			netip.MustParsePrefix("fd00::/8"),
		},
	}
	o := newTunOptions(tun)

	setTunMTU(0)
	if o.GetMTU() != defaultTunMTU {
		t.Fatalf("GetMTU with unset MTU = %d, want defaultTunMTU %d", o.GetMTU(), defaultTunMTU)
	}
	if TunMTU() != defaultTunMTU {
		t.Fatalf("TunMTU() = %d, want %d", TunMTU(), defaultTunMTU)
	}
	if !o.GetAutoRoute() {
		t.Fatal("GetAutoRoute lost")
	}

	inet4 := o.GetInet4Address()
	if inet4.Len() != 1 || inet4.Next().String() != "198.18.0.1/30" {
		t.Fatal("GetInet4Address mismatch")
	}

	// DNS server = tun gateway + 1 (libbox parity).
	dns, err := o.GetDNSServerAddress()
	if err != nil {
		t.Fatalf("GetDNSServerAddress: %v", err)
	}
	if dns.Value != "198.18.0.2" {
		t.Fatalf("DNS server = %q, want 198.18.0.2", dns.Value)
	}

	r4 := o.GetInet4RouteAddress()
	if r4.Len() != 2 || r4.Next().String() != "0.0.0.0/0" || r4.Next().String() != "10.0.0.0/8" {
		t.Fatal("GetInet4RouteAddress mismatch")
	}
	r6 := o.GetInet6RouteAddress()
	if r6.Len() != 1 || r6.Next().String() != "2001:db8::/32" {
		t.Fatal("generic IPv6 route was lost")
	}
	e4 := o.GetInet4RouteExcludeAddress()
	if e4.Len() != 1 || e4.Next().String() != "192.168.0.0/16" {
		t.Fatal("generic IPv4 exclude route was lost")
	}
	e6 := o.GetInet6RouteExcludeAddress()
	if e6.Len() != 1 || e6.Next().String() != "fd00::/8" {
		t.Fatal("generic IPv6 exclude route was lost")
	}
}

func TestDNSServerAddressRequiresRoom(t *testing.T) {
	// A /32 leaves no next address for the DNS server.
	o := newTunOptions(&LC.Tun{
		Inet4Address: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")},
	})
	if _, err := o.GetDNSServerAddress(); err == nil {
		t.Fatal("expected error for /32 inet4 address")
	}
	// No inet4 address at all is also an error, not a panic.
	if _, err := newTunOptions(&LC.Tun{}).GetDNSServerAddress(); err == nil {
		t.Fatal("expected error for missing inet4 address")
	}
}
