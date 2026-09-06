//go:build !darwin || !cgo

package hako

import (
	"errors"
	"net/netip"
)

func systemSynthesizeIPv4Literal(string, netip.Addr) (netip.Addr, error) {
	return netip.Addr{}, errors.New("system NAT64 synthesis is unavailable on this platform")
}
