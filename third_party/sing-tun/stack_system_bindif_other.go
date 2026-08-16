//go:build !darwin

package tun

import (
	"errors"
	"net/netip"
	"syscall"

	"github.com/metacubex/sing/common/logger"
)

// The IP_BOUND_IF listener bind is an Apple Network Extension fix (see the darwin file). Off
// darwin there is nothing to do: the lookup reports "not found", bindListenerSupported keeps
// listenWithTunBind from treating that as an error, and the System stack listens exactly as it
// always has.
const bindListenerSupported = false

// Never returned off darwin (the bindListenerSupported branch is dead); defined so
// stack_system.go type-checks on every platform.
var errTunAddressNotPresent = errors.New("no up interface carries the tun address")

func interfaceIndexCarrying(netip.Addr) (index int, carriers int, err error) { return -1, 0, nil }

func bindListenerToInterfaceControl(int, logger.Logger) func(network, address string, conn syscall.RawConn) error {
	return nil
}
