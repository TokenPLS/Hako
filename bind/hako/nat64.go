package hako

import (
	"errors"
	"fmt"
	"net/netip"
	"sync/atomic"

	"github.com/TokenPLS/Hako/component/dialer"
)

var (
	physicalPathSupportsIPv4 atomic.Bool
	physicalPathSupportsIPv6 atomic.Bool
	nat64SynthesisAttempts   atomic.Uint64
	nat64SynthesisApplied    atomic.Uint64
	nat64SynthesisFailures   atomic.Uint64

	synthesizeIPv4Literal = systemSynthesizeIPv4Literal
)

type nat64Snapshot struct {
	supportsIPv4 bool
	supportsIPv6 bool
	attempts     uint64
	applied      uint64
	failures     uint64
}

func installPhysicalAddressTransform(enabled bool) {
	physicalPathSupportsIPv4.Store(false)
	physicalPathSupportsIPv6.Store(false)
	nat64SynthesisAttempts.Store(0)
	nat64SynthesisApplied.Store(0)
	nat64SynthesisFailures.Store(0)
	if !enabled {
		dialer.DefaultAddressTransform = nil
		return
	}
	dialer.DefaultAddressTransform = transformPhysicalAddressForApple
}

func setPhysicalNetworkCapabilities(supportsIPv4, supportsIPv6 bool) {
	physicalPathSupportsIPv4.Store(supportsIPv4)
	physicalPathSupportsIPv6.Store(supportsIPv6)
}

func transformPhysicalAddressForApple(network string, destination netip.Addr) (netip.Addr, error) {
	if !destination.IsValid() || !destination.Is4() || destination.IsLoopback() {
		return destination, nil
	}
	// A destination on this LAN is not something a network-provided translator
	// should ever be asked about: the answer would route traffic meant for the
	// local network through whatever prefix that same network advertises.
	if destination.IsPrivate() || destination.IsLinkLocalUnicast() || destination.IsLinkLocalMulticast() {
		return destination, nil
	}
	if physicalPathSupportsIPv4.Load() || !physicalPathSupportsIPv6.Load() {
		return destination, nil
	}

	nat64SynthesisAttempts.Add(1)
	synthesized, err := synthesizeIPv4Literal(network, destination)
	if err != nil {
		nat64SynthesisFailures.Add(1)
		return netip.Addr{}, fmt.Errorf("hako: system NAT64 synthesis for %s destination failed: %w", network, err)
	}
	if err := validateNAT64Synthesis(synthesized, destination); err != nil {
		nat64SynthesisFailures.Add(1)
		return netip.Addr{}, err
	}
	nat64SynthesisApplied.Add(1)
	return synthesized, nil
}

// validateNAT64Synthesis checks that the system's answer looks like a
// translation of the destination it was asked about.
//
// The answer is derived from a NAT64 prefix the NETWORK advertises (RFC 7050
// discovery / DNS64), so on a hostile network it is attacker-influenced input
// reaching a dial address. Unchecked, a crafted answer redirects an outbound
// connection anywhere: ::1 reaches this device's own listeners, a link-local
// address reaches a neighbour, and any unrelated address silently replaces the
// destination the configuration named -- while the core believes it is talking
// to the original.
//
// Two things are required. The address must be one that can be dialed as a
// remote destination at all, and it must EMBED the destination's four bytes at
// one of the six positions RFC 6052 defines. That embedding is what makes it a
// translation rather than an unrelated address.
//
// All six are accepted, not just /96. The first version checked the low 32
// bits alone, on the stated premise that no Apple platform emits the other
// lengths -- a premise that existed only in the comment asserting it. The
// prefix comes from the NETWORK (RFC 7050 discovery), the synthesis is the
// system's getaddrinfo, and a rejection here aborts the dial outright
// (component/dialer/dialer.go dialContext), so on any network advertising a
// /32../64 translation prefix that premise would have made every IPv4
// destination unreachable. Tightening a limit needs the same standard of
// proof as loosening one; the iOS lane caught this before it shipped.

// allowLoopbackNAT64Synthesis exists for the interop test, which needs the
// synthesized address to land on a listener it started on ::1. Production
// never sets it: a real translation is never loopback, and accepting one is
// exactly the redirection this validation exists to refuse.
var allowLoopbackNAT64Synthesis = false

func validateNAT64Synthesis(synthesized, destination netip.Addr) error {
	if !synthesized.IsValid() || !synthesized.Is6() || synthesized.Is4In6() {
		return errors.New("hako: system NAT64 synthesis did not return a native IPv6 destination")
	}
	if allowLoopbackNAT64Synthesis && synthesized.IsLoopback() {
		return nil
	}
	if synthesized.IsLoopback() || synthesized.IsUnspecified() ||
		synthesized.IsLinkLocalUnicast() || synthesized.IsLinkLocalMulticast() ||
		synthesized.IsMulticast() || synthesized.IsInterfaceLocalMulticast() {
		return errors.New("hako: system NAT64 synthesis returned an address that cannot be a remote destination")
	}
	if !embedsIPv4PerRFC6052(synthesized, destination) {
		return errors.New("hako: system NAT64 synthesis does not embed the requested destination")
	}
	return nil
}

// rfc6052EmbeddingOffsets lists, per prefix length, the four byte positions
// holding the embedded IPv4 address (RFC 6052 section 2.2). Byte 8 is the
// reserved u-byte and never carries address data, which is why the shorter
// prefixes skip it.
var rfc6052EmbeddingOffsets = [][4]int{
	{4, 5, 6, 7},     // /32
	{5, 6, 7, 9},     // /40
	{6, 7, 9, 10},    // /48
	{7, 9, 10, 11},   // /56
	{9, 10, 11, 12},  // /64
	{12, 13, 14, 15}, // /96
}

func embedsIPv4PerRFC6052(synthesized, destination netip.Addr) bool {
	address := synthesized.As16()
	want := destination.Unmap().As4()
	for _, offsets := range rfc6052EmbeddingOffsets {
		if address[offsets[0]] == want[0] && address[offsets[1]] == want[1] &&
			address[offsets[2]] == want[2] && address[offsets[3]] == want[3] {
			return true
		}
	}
	return false
}

func nat64DiagnosticsSnapshot() nat64Snapshot {
	return nat64Snapshot{
		supportsIPv4: physicalPathSupportsIPv4.Load(),
		supportsIPv6: physicalPathSupportsIPv6.Load(),
		attempts:     nat64SynthesisAttempts.Load(),
		applied:      nat64SynthesisApplied.Load(),
		failures:     nat64SynthesisFailures.Load(),
	}
}
