//go:build darwin && cgo

package hako

/*
#cgo LDFLAGS: -lresolv
#include <arpa/inet.h>
#include <netinet/in.h>
#include <resolv.h>
#include <stdlib.h>
#include <string.h>

// hako_system_resolvers fills text[i*width] with the i-th resolver the platform's resolver
// library currently lists (res_ninit reads configd's DNS configuration, the same source
// /etc/resolv.conf mirrors where that file exists) and ports[i] with its port in host order.
// Returns the count, or -1 when the library refuses to initialise.
static int hako_system_resolvers(char *text, unsigned short *ports, int max, int width) {
	struct __res_state state;
	memset(&state, 0, sizeof(state));
	if (res_ninit(&state) != 0) {
		return -1;
	}
	union res_sockaddr_union addrs[MAXNS];
	int n = res_getservers(&state, addrs, MAXNS);
	int count = 0;
	for (int i = 0; i < n && count < max; i++) {
		const void *source = NULL;
		int family = addrs[i].sin.sin_family;
		unsigned short port = 0;
		if (family == AF_INET) {
			source = &addrs[i].sin.sin_addr;
			port = ntohs(addrs[i].sin.sin_port);
		} else if (family == AF_INET6) {
			source = &addrs[i].sin6.sin6_addr;
			port = ntohs(addrs[i].sin6.sin6_port);
		} else {
			continue;
		}
		if (inet_ntop(family, source, text + count * width, width) == NULL) {
			continue;
		}
		ports[count] = port;
		count++;
	}
	res_ndestroy(&state);
	return count;
}
*/
import "C"

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
	"unsafe"
)

// libresolvResolvers asks the platform resolver library for the resolvers in force right
// now. On iOS there is no /etc/resolv.conf at all (measured 2026-09-06 on an iPhone 17 Pro
// Max: ENOENT from both the App and the extension), so this is the only source there; on
// macOS it answers the same list the file mirrors. Each entry comes back as `ip` or
// `ip:port` when the port is not 53, already in the shape SystemDNSServerLines accepts.
func libresolvResolvers() ([]string, error) {
	const width = C.INET6_ADDRSTRLEN
	text := make([]byte, C.MAXNS*width)
	ports := make([]C.ushort, C.MAXNS)
	n := int(C.hako_system_resolvers((*C.char)(unsafe.Pointer(&text[0])), (*C.ushort)(unsafe.Pointer(&ports[0])), C.MAXNS, width))
	if n < 0 {
		return nil, errors.New("res_ninit failed")
	}
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		entry := text[i*width : (i+1)*width]
		if end := indexByte(entry, 0); end >= 0 {
			entry = entry[:end]
		}
		addr, err := netip.ParseAddr(string(entry))
		if err != nil {
			continue
		}
		line := addr.String()
		if port := int(ports[i]); port != 0 && port != 53 {
			line = net.JoinHostPort(line, strconv.Itoa(port))
		}
		out = append(out, line)
	}
	return out, nil
}

func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}
