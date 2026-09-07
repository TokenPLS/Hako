//go:build !darwin

package hako

import "net/netip"

func routeInterfaceIndex(netip.Addr) (int, error) { return 0, errRouteLookupUnsupported }

func defaultRouteInterfaceIndex() (int, error) { return 0, errRouteLookupUnsupported }
