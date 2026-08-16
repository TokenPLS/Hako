package hako

import (
	"syscall"

	"github.com/TokenPLS/Hako/component/dialer"
)

// installSocketHook wires mihomo's dialer.DefaultSocketHook to the platform's
// AutoDetectControl. Every outbound socket is handed to
// Swift, which binds it to the physical default interface via IP_BOUND_IF
// (index from NWPathMonitor) — the "don't route our own traffic back into the
// tunnel" guarantee. When the
// platform opts out (UsePlatformAutoDetectControl false, e.g. app-process
// runs) the hook is cleared so no stale global lingers.
func installSocketHook(platform PlatformInterface) {
	if platform == nil || !platform.UsePlatformAutoDetectInterfaceControl() {
		dialer.DefaultSocketHook = nil
		installPhysicalAddressTransform(false)
		return
	}
	installPhysicalAddressTransform(true)
	dialer.DefaultSocketHook = func(_, _ string, conn syscall.RawConn) error {
		var ctrlErr error
		if err := conn.Control(func(fd uintptr) {
			ctrlErr = platform.AutoDetectInterfaceControl(int32(fd))
		}); err != nil {
			return err
		}
		return ctrlErr
	}
}
