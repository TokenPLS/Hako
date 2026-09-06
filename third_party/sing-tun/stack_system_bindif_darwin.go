//go:build darwin

package tun

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"

	"github.com/metacubex/sing/common/logger"
	"golang.org/x/sys/unix"
)

// This file exists because of one measured fact about Apple's Network Extension: the kernel
// gives a provider process's sockets an interface scope. That scope is what keeps the core's own
// outbound dials from looping back into the tunnel -- but it also means a socket in the extension
// does NOT receive packets injected on the tun by default. The System stack's TCP handling is a
// NAT loopback (rewrite the SYN to dst=inet4Address:tcpPort, write it back to the tun, and rely
// on the OS delivering it locally to the stack's own listener), so under NE that listener never
// receives anything and TCP carries no traffic. UDP is unaffected -- it does not use this
// loopback.
//
// A device A/B/C experiment settled it: the same injected packet is NOT received by an
// extension socket left unbound, IS received by a host process (positive control), and IS
// received by the extension socket once it is bound to the utun via IP_BOUND_IF. The fix is one
// setsockopt, and it is a public, documented option (netinet/in.h). It needs no private API.
//
// It is applied ONLY to the System stack's TCP listeners. The core's outbound dialer must NEVER
// be bound this way: binding egress to the utun is exactly the loop the NE scope exists to
// prevent. (The bind is two setsockopt lines rather than a reuse of sing's forwarder bind on
// purpose: that helper skips loopback listen addresses, which would make this load-bearing NE
// invariant untestable against the only interface every host has.)
//
// Failure semantics are uniform: every way the bind can fail -- enumeration error, no live
// carrier, setsockopt refusal -- fails the listen attempt with an error that wraps
// EADDRNOTAVAIL, because each one means "the tun is not in the state the bind needs yet", which
// is the same condition the caller's retry loop already exists for. Each retry re-resolves the
// index from scratch, so a transient (an address landing late, a utun replaced between resolve
// and bind) heals on the next attempt, and a persistent failure stops start() with an
// actionable error instead of coming up as a listener that is up but unbound -- the
// silent-dead-TCP state this file exists to end. A "listen anyway" fallback is exactly that
// state, so there is none.

// bindListenerSupported reports at compile time whether this platform implements the listener
// bind. The test suite branches on this constant -- not on runtime.GOOS, which is "ios" on a
// platform where this darwin file IS the compiled implementation.
const bindListenerSupported = true

// errTunAddressNotPresent wraps EADDRNOTAVAIL so retryableListenError treats a failed lookup
// exactly like upstream treats Listen on the not-yet-assigned tun address: retry, then fail
// start() with an actionable error instead of coming up with an unbound listener.
var errTunAddressNotPresent = fmt.Errorf("no up interface carries the tun address yet: %w", unix.EADDRNOTAVAIL)

// Test seams: interface enumeration is swappable so the selection rules (up-only, newest-wins)
// and the routing of start() through the bind path can be pinned against fabricated tables.
var (
	enumerateInterfaces = net.Interfaces
	interfaceAddresses  = (*net.Interface).Addrs
)

// interfaceIndexCarrying returns the index of the newest up interface configured with addr, how
// many up interfaces carry it, and any enumeration error. index is -1 when none does. An
// enumeration failure is returned as itself rather than folded into "not found": the two need
// different responses from whoever reads the resulting log line.
//
// The lookup is by address rather than by name on purpose: this fork hands sing-tun a bridge
// placeholder device name ("hako-packet-flow", forced in the Apple override), so binding by name
// fails. The tun's own address uniquely identifies the real utun, which is what IP_BOUND_IF
// needs.
func interfaceIndexCarrying(addr netip.Addr) (index int, carriers int, err error) {
	index = -1
	if !addr.IsValid() {
		return index, 0, nil
	}
	want := addr.Unmap()
	interfaces, err := enumerateInterfaces()
	if err != nil {
		// Wrapped retryably here rather than at the caller: the caller compiles on every
		// platform and must not name unix errnos.
		return index, 0, fmt.Errorf("enumerate interfaces: %w: %w", err, unix.EADDRNOTAVAIL)
	}
	for i := range interfaces {
		iface := &interfaces[i]
		if iface.Flags&net.FlagUp == 0 {
			// A down interface can still hold a stale copy of the address -- an orphaned utun
			// from a session the OS is tearing down. Binding the listener to it would drop
			// every packet.
			continue
		}
		addresses, addrsErr := interfaceAddresses(iface)
		if addrsErr != nil {
			continue
		}
		for _, ifaceAddr := range addresses {
			var got netip.Addr
			switch typed := ifaceAddr.(type) {
			case *net.IPNet:
				got, _ = netip.AddrFromSlice(typed.IP)
			case *net.IPAddr:
				got, _ = netip.AddrFromSlice(typed.IP)
			}
			if got.Unmap() == want {
				carriers++
				if iface.Index > index {
					// Interface indices are assigned in creation order and the tun this stack
					// serves was created moments ago: when more than one live interface claims
					// the address (say a second clash instance's utun using the same fake-ip
					// range), the newest one is ours.
					index = iface.Index
				}
				break // count each interface once even if it repeats the address
			}
		}
	}
	return index, carriers, nil
}

// bindListenerToInterfaceControl returns a ListenConfig.Control hook that binds the socket to
// the given interface index via IP_BOUND_IF (v4) or IPV6_BOUND_IF (v6 networks, derived from
// the network string the hook receives). index < 0 yields no hook.
//
// A failing setsockopt FAILS the listen (wrapping EADDRNOTAVAIL so the caller's retry loop
// re-resolves a fresh index and tries again): the index was resolved a moment ago, so a refusal
// means the utun changed under us, and the retry is the healing path. Swallowing the error was
// tried and is worse on both sides -- it produces a listener that is up but unbound (dead TCP,
// silently) and it makes the success log above it a lie.
func bindListenerToInterfaceControl(index int, log logger.Logger) func(network, address string, conn syscall.RawConn) error {
	if index < 0 {
		return nil
	}
	return func(network, _ string, conn syscall.RawConn) error {
		var opErr error
		controlErr := conn.Control(func(fd uintptr) {
			if strings.HasSuffix(network, "6") {
				opErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, index)
			} else {
				opErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, index)
			}
		})
		if controlErr != nil {
			return controlErr
		}
		if opErr != nil {
			log.Warn("[bindif] setsockopt bound-if index ", index, ": ", opErr)
			return fmt.Errorf("bind %s listener to interface index %d: %w: %w", network, index, opErr, unix.EADDRNOTAVAIL)
		}
		return nil
	}
}
