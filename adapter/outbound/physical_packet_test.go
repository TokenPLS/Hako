package outbound

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/component/dialer"
)

func TestPhysicalAddressPacketConnRestoresLogicalUDPAddress(t *testing.T) {
	server, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	defer server.Close()
	serverPort := server.LocalAddr().(*net.UDPAddr).AddrPort().Port()

	original := dialer.DefaultAddressTransform
	dialer.DefaultAddressTransform = func(_ string, destination netip.Addr) (netip.Addr, error) {
		if destination.String() == "192.0.2.1" {
			return netip.IPv6Loopback(), nil
		}
		return destination, nil
	}
	t.Cleanup(func() { dialer.DefaultAddressTransform = original })

	client, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	logical := netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), serverPort)
	physical := netip.AddrPortFrom(netip.IPv6Loopback(), serverPort)
	wrapped := newPhysicalAddressPacketConn(client, logical, physical)
	defer wrapped.Close()

	echoDone := make(chan error, 1)
	go func() {
		buffer := make([]byte, 16)
		count, source, readErr := server.ReadFrom(buffer)
		if readErr == nil {
			_, readErr = server.WriteTo(buffer[:count], source)
		}
		echoDone <- readErr
	}()
	_ = wrapped.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := wrapped.WriteTo([]byte("nat64"), net.UDPAddrFromAddrPort(logical)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 16)
	count, source, err := wrapped.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:count]) != "nat64" {
		t.Fatalf("echo payload = %q", buffer[:count])
	}
	if got := source.(*net.UDPAddr).AddrPort(); got != logical {
		t.Fatalf("logical response source = %s, want %s", got, logical)
	}
	if err := <-echoDone; err != nil {
		t.Fatal(err)
	}
}
