//go:build darwin

package hako

import (
	"errors"
	"net/netip"
	"os"
	"syscall"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// routeInterfaceIndex asks the routing socket where a packet to addr leaves right now
// (RTM_GET, what `route -n get` does) and returns that interface's index. An address the
// table cannot route answers errNoRoute.
func routeInterfaceIndex(addr netip.Addr) (int, error) {
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, 0)
	if err != nil {
		return 0, err
	}
	defer func() { _ = unix.Close(fd) }()
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1})

	const seq = 0x4841 // "HA"
	message := route.RouteMessage{
		Version: unix.RTM_VERSION,
		Type:    unix.RTM_GET,
		Flags:   unix.RTF_UP | unix.RTF_HOST | unix.RTF_GATEWAY,
		Seq:     seq,
		ID:      uintptr(os.Getpid()),
	}
	if addr.Is4() {
		message.Addrs = []route.Addr{syscall.RTAX_DST: &route.Inet4Addr{IP: addr.As4()}}
	} else {
		message.Addrs = []route.Addr{syscall.RTAX_DST: &route.Inet6Addr{IP: addr.As16(), ZoneID: int(zoneIndex(addr))}}
	}
	request, err := message.Marshal()
	if err != nil {
		return 0, err
	}
	if _, err := unix.Write(fd, request); err != nil {
		if errors.Is(err, unix.ESRCH) || errors.Is(err, unix.ENETUNREACH) || errors.Is(err, unix.EHOSTUNREACH) {
			return 0, errNoRoute
		}
		return 0, err
	}
	buffer := make([]byte, 4096)
	for attempt := 0; attempt < 32; attempt++ {
		n, err := unix.Read(fd, buffer)
		if err != nil {
			return 0, err
		}
		messages, err := route.ParseRIB(route.RIBTypeRoute, buffer[:n])
		if err != nil {
			continue
		}
		for _, parsed := range messages {
			reply, ok := parsed.(*route.RouteMessage)
			if !ok || reply.Type != unix.RTM_GET || reply.Seq != seq || reply.ID != uintptr(os.Getpid()) {
				continue
			}
			if reply.Index == 0 {
				return 0, errNoRoute
			}
			return reply.Index, nil
		}
	}
	return 0, errors.New("routing socket answered nothing for the lookup")
}

func zoneIndex(addr netip.Addr) uint32 {
	if addr.Zone() == "" {
		return 0
	}
	return 0
}

// defaultRouteInterfaceIndex is the interface of the unscoped default route -- the
// physical path before this product's tunnel is up -- preferring IPv4's, falling back to
// IPv6's when IPv4 has none.
func defaultRouteInterfaceIndex() (int, error) {
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		table, err := route.FetchRIB(family, route.RIBTypeRoute, 0)
		if err != nil {
			continue
		}
		messages, err := route.ParseRIB(route.RIBTypeRoute, table)
		if err != nil {
			continue
		}
		for _, parsed := range messages {
			entry, ok := parsed.(*route.RouteMessage)
			if !ok || entry.Flags&unix.RTF_GATEWAY == 0 || entry.Flags&unix.RTF_IFSCOPE != 0 || entry.Index == 0 {
				continue
			}
			if !isUnspecifiedDestination(entry.Addrs) {
				continue
			}
			return entry.Index, nil
		}
	}
	return 0, errNoRoute
}

func isUnspecifiedDestination(addrs []route.Addr) bool {
	if len(addrs) <= syscall.RTAX_DST || addrs[syscall.RTAX_DST] == nil {
		return false
	}
	switch destination := addrs[syscall.RTAX_DST].(type) {
	case *route.Inet4Addr:
		if destination.IP != [4]byte{} {
			return false
		}
	case *route.Inet6Addr:
		if destination.IP != [16]byte{} {
			return false
		}
	default:
		return false
	}
	if len(addrs) <= syscall.RTAX_NETMASK || addrs[syscall.RTAX_NETMASK] == nil {
		return true
	}
	switch mask := addrs[syscall.RTAX_NETMASK].(type) {
	case *route.Inet4Addr:
		return mask.IP == [4]byte{}
	case *route.Inet6Addr:
		return mask.IP == [16]byte{}
	}
	return true
}
