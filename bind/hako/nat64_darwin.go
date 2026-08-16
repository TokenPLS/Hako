//go:build darwin && cgo

package hako

/*
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

// Apple documents getaddrinfo(PF_UNSPEC, AI_DEFAULT) as the supported way to
// synthesize a network-specific NAT64 IPv6 address from an IPv4 literal. Do
// not form 64:ff9b::/96 manually: providers may advertise a different prefix.
static int hako_synthesize_nat64(const char *host, int socket_type, char *output, size_t output_size) {
	struct addrinfo hints;
	struct addrinfo *results = NULL;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = socket_type;
	hints.ai_flags = AI_DEFAULT;

	int result = getaddrinfo(host, NULL, &hints, &results);
	if (result != 0) {
		return result;
	}
	int found = EAI_NONAME;
	for (struct addrinfo *current = results; current != NULL; current = current->ai_next) {
		if (current->ai_family != AF_INET6 || current->ai_addrlen < sizeof(struct sockaddr_in6)) {
			continue;
		}
		struct sockaddr_in6 *address = (struct sockaddr_in6 *)current->ai_addr;
		if (inet_ntop(AF_INET6, &address->sin6_addr, output, (socklen_t)output_size) != NULL) {
			found = 0;
			break;
		}
	}
	freeaddrinfo(results);
	return found;
}
*/
import "C"

import (
	"fmt"
	"net/netip"
	"strings"
	"unsafe"
)

func systemSynthesizeIPv4Literal(network string, destination netip.Addr) (netip.Addr, error) {
	host := C.CString(destination.String())
	defer C.free(unsafe.Pointer(host))
	socketType := C.int(C.SOCK_STREAM)
	if strings.HasPrefix(network, "udp") {
		socketType = C.int(C.SOCK_DGRAM)
	}
	var output [C.INET6_ADDRSTRLEN]C.char
	result := C.hako_synthesize_nat64(host, socketType, &output[0], C.size_t(len(output)))
	if result != 0 {
		return netip.Addr{}, fmt.Errorf("getaddrinfo: %s", C.GoString(C.gai_strerror(result)))
	}
	address, err := netip.ParseAddr(C.GoString(&output[0]))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("parse synthesized address: %w", err)
	}
	return address, nil
}
