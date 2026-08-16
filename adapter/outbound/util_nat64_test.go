package outbound

import (
	"context"
	"net/netip"
	"testing"

	"github.com/TokenPLS/Hako/component/dialer"
	C "github.com/TokenPLS/Hako/constant"
)

func TestResolveUDPAddrAppliesPhysicalAddressTransform(t *testing.T) {
	original := dialer.DefaultAddressTransform
	dialer.DefaultAddressTransform = func(network string, destination netip.Addr) (netip.Addr, error) {
		if network != "udp" || destination.String() != "192.0.2.1" {
			t.Fatalf("transform input = %s %s", network, destination)
		}
		return netip.MustParseAddr("64:ff9b::c000:201"), nil
	}
	t.Cleanup(func() { dialer.DefaultAddressTransform = original })

	address, err := resolveUDPAddr(context.Background(), "udp", "192.0.2.1:443", C.DualStack)
	if err != nil {
		t.Fatal(err)
	}
	if got := address.AddrPort().String(); got != "[64:ff9b::c000:201]:443" {
		t.Fatalf("resolved UDP address = %s", got)
	}
}
