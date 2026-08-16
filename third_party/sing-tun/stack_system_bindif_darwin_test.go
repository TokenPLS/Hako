//go:build darwin

package tun

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/sing/common/logger"
	"golang.org/x/sys/unix"
)

// Selection-rule tests run against fabricated interface tables through the enumeration seams,
// because the two rules they pin -- up-only and newest-wins -- exist for states a healthy dev
// machine never exhibits (an orphaned utun holding a stale copy of the tun address, or two live
// interfaces claiming the same fake-ip range).

func withInterfaceTable(t *testing.T, table []net.Interface, addrs map[string][]net.Addr) {
	t.Helper()
	prevEnum, prevAddrs := enumerateInterfaces, interfaceAddresses
	enumerateInterfaces = func() ([]net.Interface, error) { return table, nil }
	interfaceAddresses = func(i *net.Interface) ([]net.Addr, error) { return addrs[i.Name], nil }
	t.Cleanup(func() { enumerateInterfaces, interfaceAddresses = prevEnum, prevAddrs })
}

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	ip, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatal(err)
	}
	ipNet.IP = ip
	return ipNet
}

func TestLookupSkipsDownInterfaces(t *testing.T) {
	// The down interface has the LOWER index and comes first: under the old first-match rule it
	// would have won, binding the listener to a dying utun that drops every packet.
	withInterfaceTable(t,
		[]net.Interface{
			{Index: 5, Name: "utun4", Flags: 0}, // down: an orphaned utun mid-teardown
			{Index: 9, Name: "utun5", Flags: net.FlagUp},
		},
		map[string][]net.Addr{
			"utun4": {mustCIDR(t, "198.18.0.1/16")},
			"utun5": {mustCIDR(t, "198.18.0.1/16")},
		})
	index, carriers, err := interfaceIndexCarrying(netip.MustParseAddr("198.18.0.1"))
	if err != nil {
		t.Fatalf("fabricated table must not error: %v", err)
	}
	if index != 9 {
		t.Fatalf("the up interface must win over a down one carrying the same address, got index %d", index)
	}
	if carriers != 1 {
		t.Fatalf("a down interface is not a carrier, got %d", carriers)
	}
}

func TestLookupPrefersNewestWhenTwoLiveInterfacesCarryTheAddress(t *testing.T) {
	// Two live claimants (say a second clash instance's utun with the same fake-ip range). The
	// tun this stack serves was created moments ago, so the newest -- highest index -- is ours.
	withInterfaceTable(t,
		[]net.Interface{
			{Index: 4, Name: "utun2", Flags: net.FlagUp},
			{Index: 11, Name: "utun6", Flags: net.FlagUp},
		},
		map[string][]net.Addr{
			"utun2": {mustCIDR(t, "198.18.0.1/16")},
			"utun6": {mustCIDR(t, "198.18.0.1/16")},
		})
	index, carriers, err := interfaceIndexCarrying(netip.MustParseAddr("198.18.0.1"))
	if err != nil {
		t.Fatalf("fabricated table must not error: %v", err)
	}
	if index != 11 {
		t.Fatalf("the newest live carrier must win, got index %d", index)
	}
	if carriers != 2 {
		t.Fatalf("both live carriers must be counted (the caller warns on >1), got %d", carriers)
	}
}

// An enumeration failure is not "address not found": it is returned as itself, wrapped
// retryably, so the log names the real thing to chase and the retry loop still gets to heal a
// transient.
func TestLookupReportsEnumerationFailureAsItself(t *testing.T) {
	prevEnum := enumerateInterfaces
	boom := errors.New("getifaddrs: cannot allocate memory")
	enumerateInterfaces = func() ([]net.Interface, error) { return nil, boom }
	t.Cleanup(func() { enumerateInterfaces = prevEnum })
	index, carriers, err := interfaceIndexCarrying(netip.MustParseAddr("198.18.0.1"))
	if index != -1 || carriers != 0 {
		t.Fatalf("enumeration failure must report -1/0, got %d/%d", index, carriers)
	}
	if !errors.Is(err, boom) {
		t.Fatalf("the enumeration error must be preserved, got %v", err)
	}
	if !errors.Is(err, unix.EADDRNOTAVAIL) {
		t.Fatalf("the enumeration error must stay retryable, got %v", err)
	}
}

// The two halves of listenWithTunBind's contract, pinned end to end on a real socket:
//
//  1. A resolvable address listens bound (the fix engages).
//  2. An unresolvable address does NOT listen unbound -- it fails with an error the caller's
//     retry loop recognises, because "up but unbound" is the silent-dead-TCP state.
func TestListenWithTunBindBindsWhenAddressResolves(t *testing.T) {
	s := &System{ctx: context.Background(), logger: logger.NOP()}
	ln, err := s.listenWithTunBind(net.ListenConfig{}, "tcp4", "127.0.0.1:0", netip.MustParseAddr("127.0.0.1"))
	if err != nil {
		t.Fatalf("listen with a resolvable tun address must succeed, got %v", err)
	}
	defer ln.Close()
}

func TestListenWithTunBindFailsRetryablyWhenAddressAbsent(t *testing.T) {
	s := &System{ctx: context.Background(), logger: logger.NOP()}
	ln, err := s.listenWithTunBind(net.ListenConfig{}, "tcp4", "127.0.0.1:0", netip.MustParseAddr("203.0.113.254"))
	if err == nil {
		ln.Close()
		t.Fatal("an absent tun address must not produce an unbound listener -- that is the silent-dead-TCP state")
	}
	if !retryableListenError(err) {
		t.Fatalf("a lookup miss is the same \"address not there yet\" condition the retry loop exists for; got non-retryable %v", err)
	}
	if !errors.Is(err, unix.EADDRNOTAVAIL) {
		t.Fatalf("the miss must wrap EADDRNOTAVAIL, got %v", err)
	}
}

// A found index whose interface dies before the socket is created must FAIL the listen -- not
// warn and serve unbound. The index was live a moment ago, so the caller's retry re-resolves a
// fresh one: returning the error IS the healing path, and swallowing it was measured to produce
// both a dead listener and a lying success log. 1<<24 is far above any real if_index, so the
// setsockopt reliably fails.
func TestBindHookFailsClosedAndRetryablyOnSetsockoptFailure(t *testing.T) {
	hook := bindListenerToInterfaceControl(1<<24, logger.NOP())
	if hook == nil {
		t.Fatal("a non-negative index must yield a hook")
	}
	lc := net.ListenConfig{Control: hook}
	ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err == nil {
		ln.Close()
		t.Fatal("a failed setsockopt must fail the listen: an unbound listener is the exact state this file exists to end")
	}
	if !retryableListenError(err) {
		t.Fatalf("a setsockopt failure means the tun changed under us -- it must stay retryable so the next attempt re-resolves, got %v", err)
	}
}

// The routing pin: start() must reach its TCP listeners only through listenWithTunBind. The
// compile-level tripwire (no bare `listener` in start()) catches a partial upstream-merge
// resolution; this test catches the wholesale one. With the enumeration seam returning an empty
// table, a start() that routes through listenWithTunBind CANNOT succeed -- the lookup misses,
// every attempt fails retryably, and start() returns the miss. A start() reverted to upstream's
// plain listener.Listen succeeds on loopback, and this test then fails.
func TestStartRoutesItsListenersThroughTunBind(t *testing.T) {
	withInterfaceTable(t, nil, nil) // no interfaces: the lookup can never resolve
	s := &System{
		ctx:              context.Background(),
		logger:           logger.NOP(),
		inet4Address:     netip.MustParseAddr("127.0.0.1"),
		inet4NextAddress: netip.MustParseAddr("127.0.0.2"),
		udpTimeout:       time.Minute,
		icmpTimeout:      time.Minute,
	}
	err := s.start()
	if err == nil {
		t.Fatal("with no interface carrying the tun address, a start() that routes through " +
			"listenWithTunBind cannot succeed; success means the routing was dropped " +
			"(an upstream merge took the whole function) and the bind is gone")
	}
	if !errors.Is(err, unix.EADDRNOTAVAIL) {
		t.Fatalf("the failure must be the retryable lookup miss, got %v", err)
	}
	if s.tcpListener != nil {
		t.Fatal("a failed start must not leave a live TCP listener behind")
	}
}

// The leak pin for the half-started case: v4 comes up, v6 cannot. start() must close the live
// v4 listener before returning the v6 failure -- each leaked listener is a socket plus an
// accept goroutine in a memory-capped extension process, once per failed start.
func TestStartClosesV4ListenerWhenV6Fails(t *testing.T) {
	s := &System{
		ctx:              context.Background(),
		logger:           logger.NOP(),
		inet4Address:     netip.MustParseAddr("127.0.0.1"),
		inet4NextAddress: netip.MustParseAddr("127.0.0.2"),
		// TEST-NET-style documentation v6 address: no interface carries it, so the v6 leg's
		// lookup misses while the v4 leg (loopback) binds and starts its accept goroutine.
		inet6Address:     netip.MustParseAddr("2001:db8::1"),
		inet6NextAddress: netip.MustParseAddr("2001:db8::2"),
		udpTimeout:       time.Minute,
		icmpTimeout:      time.Minute,
	}
	start := time.Now()
	err := s.start()
	if err == nil {
		t.Fatal("the v6 lookup cannot resolve 2001:db8::1; start() must fail")
	}
	if s.tcpListener != nil {
		t.Fatal("the v4 listener must be closed when the v6 leg fails, or every failed start leaks a socket and a goroutine")
	}
	// Sanity on the retry pacing this test rides through: three v6 attempts with two sleeps.
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("start() took %v; the retry loop grew beyond its documented three attempts", elapsed)
	}
}
