package tun

import (
	"net"
	"net/netip"
	"testing"

	"github.com/metacubex/sing/common/logger"
)

// interfaceIndexCarrying is the load-bearing half of the IP_BOUND_IF fix: it finds the real utun
// index by address, because the tun's device name is a bridge placeholder that binding-by-name
// cannot use. If it silently returned -1 the fix would silently not apply and the System stack
// would stay broken with no error -- exactly the kind of "a measurement that returns a
// good-looking value instead of the answer" this project keeps meeting. So it is pinned against
// a real interface (loopback, which every host has) and against an address nothing owns.
//
// The platform branch is on bindListenerSupported -- a compile-time constant selected by the
// same build constraints that pick the implementation -- NOT on runtime.GOOS, which is "ios" on
// a platform where the darwin file IS the compiled implementation.
func TestInterfaceIndexCarryingFindsTheInterfaceByAddress(t *testing.T) {
	index, carriers, lookupErr := interfaceIndexCarrying(netip.MustParseAddr("127.0.0.1"))
	if lookupErr != nil {
		t.Fatalf("loopback lookup must not error: %v", lookupErr)
	}
	if bindListenerSupported {
		loopback, err := net.InterfaceByName(loopbackInterfaceName(t))
		if err != nil {
			t.Fatalf("resolve the loopback interface: %v", err)
		}
		if index != loopback.Index {
			t.Errorf("interfaceIndexCarrying(127.0.0.1) = %d, want the loopback index %d", index, loopback.Index)
		}
		if carriers < 1 {
			t.Errorf("loopback carries 127.0.0.1 but carriers = %d", carriers)
		}
	} else {
		if index != -1 || carriers != 0 {
			t.Errorf("off darwin the stub must report -1/0, got %d/%d", index, carriers)
		}
	}
}

// An address no interface carries must report -1/0, so the caller applies no bind rather than
// binding to a wrong or zero index.
func TestInterfaceIndexCarryingReportsNotFoundForAnUnownedAddress(t *testing.T) {
	// 203.0.113.201 is in the RFC 5737 documentation range: never assigned to a real interface.
	if index, carriers, err := interfaceIndexCarrying(netip.MustParseAddr("203.0.113.201")); index != -1 || carriers != 0 || err != nil {
		t.Errorf("interfaceIndexCarrying(unowned) = %d/%d/%v, want -1/0/nil", index, carriers, err)
	}
	if index, carriers, err := interfaceIndexCarrying(netip.Addr{}); index != -1 || carriers != 0 || err != nil {
		t.Errorf("interfaceIndexCarrying(invalid) = %d/%d/%v, want -1/0/nil", index, carriers, err)
	}
}

// A negative index yields no hook: the fallback when the lookup fails must be "leave the listener
// as it was", never a bind to index -1.
func TestBindControlIsNilWhenTheIndexIsNotFound(t *testing.T) {
	if bindListenerToInterfaceControl(-1, logger.NOP()) != nil {
		t.Error("a not-found index (-1) must produce no bind hook")
	}
}

func loopbackInterfaceName(t *testing.T) string {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("list interfaces: %v", err)
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 {
			return iface.Name
		}
	}
	t.Skip("no loopback interface on this host")
	return ""
}
