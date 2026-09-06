package hako

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/TokenPLS/Hako/component/dialer"
)

func setupNAT64PolicyTest(t *testing.T) {
	t.Helper()
	originalTransform := dialer.DefaultAddressTransform
	originalSynthesize := synthesizeIPv4Literal
	originalIPv4 := physicalPathSupportsIPv4.Load()
	originalIPv6 := physicalPathSupportsIPv6.Load()
	t.Cleanup(func() {
		dialer.DefaultAddressTransform = originalTransform
		synthesizeIPv4Literal = originalSynthesize
		physicalPathSupportsIPv4.Store(originalIPv4)
		physicalPathSupportsIPv6.Store(originalIPv6)
		nat64SynthesisAttempts.Store(0)
		nat64SynthesisApplied.Store(0)
		nat64SynthesisFailures.Store(0)
	})
	installPhysicalAddressTransform(true)
}

// The synthesized address comes from the SYSTEM resolver, which on an
// IPv6-only path derives it from a NAT64 prefix the NETWORK advertises (RFC
// 7050 / DNS64). On a hostile network that prefix is attacker-chosen, so the
// answer is attacker-influenced input and has to be checked like any other:
// what comes back must look like the address it claims to be a translation of.
// Without that, a crafted answer redirects an outbound dial anywhere the
// attacker likes -- loopback (reaching this device's own services),
// link-local, or multicast -- while the core believes it is talking to the
// destination the configuration named.
//
// Threat model: whoever controls the network this device joined.
func TestNAT64SynthesisRejectsAddressesThatCannotBeATranslation(t *testing.T) {
	setupNAT64PolicyTest(t)
	physicalPathSupportsIPv4.Store(false)
	physicalPathSupportsIPv6.Store(true)

	destination := netip.MustParseAddr("93.184.216.34")
	for _, hostile := range []struct {
		name      string
		synthetic string
	}{
		{"loopback", "::1"},
		{"link-local", "fe80::1"},
		{"multicast", "ff02::1"},
		{"unspecified", "::"},
		{"unrelated destination", "2001:db8:64::c0a8:0101"},
	} {
		synthesizeIPv4Literal = func(string, netip.Addr) (netip.Addr, error) {
			return netip.MustParseAddr(hostile.synthetic), nil
		}
		got, err := transformPhysicalAddressForApple("tcp", destination)
		if err == nil {
			t.Fatalf("%s: a synthesized %s was accepted and would be dialed (%v)", hostile.name, hostile.synthetic, got)
		}
	}

	// A well-formed translation still works: the well-known prefix with the
	// destination's four bytes embedded where RFC 6052 puts them.
	synthesizeIPv4Literal = func(string, netip.Addr) (netip.Addr, error) {
		return netip.MustParseAddr("64:ff9b::5db8:d822"), nil
	}
	got, err := transformPhysicalAddressForApple("tcp", destination)
	if err != nil {
		t.Fatalf("a real NAT64 translation must be accepted: %v", err)
	}
	if got.String() != "64:ff9b::5db8:d822" {
		t.Fatalf("the accepted address changed: %v", got)
	}
}

// RFC 6052 defines SIX prefix lengths and only /96 puts the address in the
// last four bytes; /32../64 place it around the u-byte at offset 8. A check
// that only understands /96 rejects every legitimate translation on a network
// using any of the other five -- and the rejection is a hard abort
// (component/dialer/dialer.go dialContext returns the error), so on such a
// network every IPv4 destination becomes unreachable. That is a security fix
// turning into an outage, which is worse than the exposure it closes.
//
// Caught by the iOS lane before this shipped. The premise it removed ("no
// Apple platform emits the others") existed only in the comment that asserted
// it: the prefix comes from the network via RFC 7050 discovery, and this
// fork's own C-side note says providers may advertise a different one.
func TestNAT64SynthesisAcceptsEveryRFC6052PrefixLength(t *testing.T) {
	setupNAT64PolicyTest(t)
	physicalPathSupportsIPv4.Store(false)
	physicalPathSupportsIPv6.Store(true)
	destination := netip.MustParseAddr("192.0.2.33") // c0 00 02 21

	for _, form := range []struct {
		name      string
		synthetic string
	}{
		// v4 bytes at 4..7
		{"/32", "2001:db8:c000:221::"},
		// v4 bytes at 5,6,7,9 -- byte 8 is the reserved u-byte and must be zero
		{"/40", "2001:db8:1c0:2:21::"},
		// v4 bytes at 6,7,9,10
		{"/48", "2001:db8:122:c000:2:2100::"},
		// v4 bytes at 7,9,10,11
		{"/56", "2001:db8:122:3c0:0:221::"},
		// v4 bytes at 9..12
		{"/64", "2001:db8:122:344:c0:2:2100:0"},
		// v4 bytes at 12..15
		{"/96", "64:ff9b::c000:221"},
	} {
		synthesizeIPv4Literal = func(string, netip.Addr) (netip.Addr, error) {
			return netip.MustParseAddr(form.synthetic), nil
		}
		got, err := transformPhysicalAddressForApple("tcp", destination)
		if err != nil {
			t.Fatalf("%s translation %s was rejected; on a network using that prefix length every IPv4 destination would become unreachable: %v",
				form.name, form.synthetic, err)
		}
		if got.String() != netip.MustParseAddr(form.synthetic).String() {
			t.Fatalf("%s: dial address changed to %v", form.name, got)
		}
	}

	// An address that embeds the destination NOWHERE is still refused: that is
	// the property this validation exists for.
	synthesizeIPv4Literal = func(string, netip.Addr) (netip.Addr, error) {
		return netip.MustParseAddr("2001:db8::dead:beef"), nil
	}
	if _, err := transformPhysicalAddressForApple("tcp", destination); err == nil {
		t.Fatal("an address embedding the destination nowhere was accepted")
	}
}

// The /96 case above uses 64:ff9b::, the well-known prefix. Real networks do not
// have to use it, and the one Apple itself builds does not.
//
// These vectors were MEASURED, not invented: an Apple "Create NAT64 Network"
// internet-sharing network on macOS 26.6.1 (2026-08-15) advertises the
// network-specific prefix 2001:2:0:1baa::/96, and its DNS64 answered with the
// addresses below. An iPad on that network reported ipv4=false / ipv6=true, so
// this is the exact input transformPhysicalAddressForApple sees there.
//
// What this guards is OUR half. The prefix is discovered by the system --
// nat64_darwin.go calls getaddrinfo(PF_UNSPEC, AI_DEFAULT) and deliberately
// does not form a prefix itself -- so the only way we can break an IPv6-only
// network is by REFUSING a legitimate answer here, which aborts the dial
// outright. Anyone tempted to "tighten" this to the well-known prefix would
// make every IPv4 destination unreachable on Apple's own test network.
func TestNAT64SynthesisAcceptsAppleNetworkSpecificPrefix(t *testing.T) {
	setupNAT64PolicyTest(t)
	physicalPathSupportsIPv4.Store(false)
	physicalPathSupportsIPv6.Store(true)

	for _, measured := range []struct {
		name        string
		destination string
		synthesized string
	}{
		// ipv4only.arpa, the RFC 7050 discovery name: 192.0.0.170 = c0 00 00 aa
		{"ipv4only.arpa", "192.0.0.170", "2001:2:0:1baa::c000:aa"},
		// ipv4.google.com, an ordinary IPv4-only host: 74.125.130.100 = 4a 7d 82 64
		{"ipv4-only host", "74.125.130.100", "2001:2:0:1baa::4a7d:8264"},
	} {
		destination := netip.MustParseAddr(measured.destination)
		synthesizeIPv4Literal = func(string, netip.Addr) (netip.Addr, error) {
			return netip.MustParseAddr(measured.synthesized), nil
		}
		got, err := transformPhysicalAddressForApple("tcp", destination)
		if err != nil {
			t.Fatalf("%s: a real Apple NAT64 network's answer %s was refused; every IPv4 destination there would be unreachable: %v",
				measured.name, measured.synthesized, err)
		}
		if got.String() != netip.MustParseAddr(measured.synthesized).String() {
			t.Fatalf("%s: dial address changed to %v", measured.name, got)
		}
	}

	// Negative control, so the two acceptances above are not vacuous: the same
	// real prefix carrying someone else's four bytes must still be refused.
	synthesizeIPv4Literal = func(string, netip.Addr) (netip.Addr, error) {
		return netip.MustParseAddr("2001:2:0:1baa::dead:beef"), nil
	}
	if _, err := transformPhysicalAddressForApple("tcp", netip.MustParseAddr("74.125.130.100")); err == nil {
		t.Fatal("the real prefix carrying an unrelated address was accepted; the prefix alone is not what makes an answer a translation")
	}
}

// A destination that is private or link-local has no business being handed to
// a network-provided translator at all: the answer would send traffic meant
// for this LAN through whatever prefix the network advertises.
func TestNAT64SynthesisSkipsPrivateAndLinkLocalDestinations(t *testing.T) {
	setupNAT64PolicyTest(t)
	physicalPathSupportsIPv4.Store(false)
	physicalPathSupportsIPv6.Store(true)
	synthesizeIPv4Literal = func(string, netip.Addr) (netip.Addr, error) {
		t.Fatal("a private destination must never reach the system translator")
		return netip.Addr{}, nil
	}

	for _, address := range []string{"10.0.0.5", "192.168.1.1", "172.16.0.9", "169.254.1.1"} {
		destination := netip.MustParseAddr(address)
		got, err := transformPhysicalAddressForApple("tcp", destination)
		if err != nil {
			t.Fatalf("%s: a private destination must pass through untouched: %v", address, err)
		}
		if got != destination {
			t.Fatalf("%s: destination was rewritten to %v", address, got)
		}
	}
}

func TestNAT64TransformOnlyRunsOnIPv6OnlyPhysicalPath(t *testing.T) {
	setupNAT64PolicyTest(t)
	called := 0
	synthesizeIPv4Literal = func(network string, destination netip.Addr) (netip.Addr, error) {
		called++
		if network != "tcp" || destination.String() != "192.0.2.1" {
			t.Fatalf("synthesis input = %s %s", network, destination)
		}
		return netip.MustParseAddr("64:ff9b::c000:201"), nil
	}

	v4 := netip.MustParseAddr("192.0.2.1")
	setPhysicalNetworkCapabilities(true, true)
	if got, err := transformPhysicalAddressForApple("tcp", v4); err != nil || got != v4 {
		t.Fatalf("dual-stack transform = %s, %v", got, err)
	}
	setPhysicalNetworkCapabilities(false, false)
	if got, err := transformPhysicalAddressForApple("tcp", v4); err != nil || got != v4 {
		t.Fatalf("unavailable-path transform = %s, %v", got, err)
	}
	setPhysicalNetworkCapabilities(false, true)
	got, err := transformPhysicalAddressForApple("tcp", v4)
	if err != nil || got.String() != "64:ff9b::c000:201" {
		t.Fatalf("IPv6-only transform = %s, %v", got, err)
	}
	if called != 1 {
		t.Fatalf("synthesizer called %d times, want 1", called)
	}
	snapshot := nat64DiagnosticsSnapshot()
	if snapshot.attempts != 1 || snapshot.applied != 1 || snapshot.failures != 0 {
		t.Fatalf("NAT64 metrics = %#v", snapshot)
	}
}

func TestNAT64TransformFailsClosedAndLeavesIPv6AndLoopbackUntouched(t *testing.T) {
	setupNAT64PolicyTest(t)
	want := errors.New("injected synthesis failure")
	synthesizeIPv4Literal = func(string, netip.Addr) (netip.Addr, error) {
		return netip.Addr{}, want
	}
	setPhysicalNetworkCapabilities(false, true)

	if got, err := transformPhysicalAddressForApple("udp", netip.IPv6Loopback()); err != nil || got != netip.IPv6Loopback() {
		t.Fatalf("native IPv6 changed: %s, %v", got, err)
	}
	loopback4 := netip.MustParseAddr("127.0.0.1")
	if got, err := transformPhysicalAddressForApple("tcp", loopback4); err != nil || got != loopback4 {
		t.Fatalf("loopback changed: %s, %v", got, err)
	}
	_, err := transformPhysicalAddressForApple("udp", netip.MustParseAddr("198.51.100.7"))
	if !errors.Is(err, want) {
		t.Fatalf("transform error = %v, want %v", err, want)
	}
	snapshot := nat64DiagnosticsSnapshot()
	if snapshot.attempts != 1 || snapshot.applied != 0 || snapshot.failures != 1 {
		t.Fatalf("NAT64 failure metrics = %#v", snapshot)
	}
}

func TestInstallSocketHookOwnsPhysicalAddressTransform(t *testing.T) {
	setupNAT64PolicyTest(t)
	installSocketHook(&hookPlatform{enabled: false})
	if dialer.DefaultAddressTransform != nil {
		t.Fatal("opt-out left physical address transform installed")
	}
	installSocketHook(&hookPlatform{enabled: true})
	if dialer.DefaultAddressTransform == nil {
		t.Fatal("opt-in did not install physical address transform")
	}
}
