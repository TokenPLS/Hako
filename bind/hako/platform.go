package hako

// PlatformInterface is the callback contract Swift must implement (libbox
// platform.go analogue, trimmed to what iOS mihomo consumes — Android-only
// members like UIDByPackageName/UseProcFS are intentionally absent, and
// process-owner lookup is an OS red line on iOS).
type PlatformInterface interface {
	// WriteLog receives one formatted log line (no trailing newline).
	// Wired in NewService: logrus output is redirected here.
	// Called from arbitrary Go threads; must not block — a slow consumer
	// stalls core logging.
	WriteLog(message string)

	// OpenTun asks the NE to apply NEPacketTunnelNetworkSettings and start the
	// public NEPacketTunnelFlow adapter. It returns the core-facing end of the
	// adapter's internal SOCK_DGRAM socketpair — never Apple's private utun fd.
	// Go dups the returned bridge fd, so Swift owns the original and can cancel
	// the bridge during provider teardown.
	OpenTun(options TunOptions) (int32, error)

	// UsePlatformAutoDetectInterfaceControl reports whether Swift wants to
	// bind outbound sockets itself. When true, AutoDetectInterfaceControl
	// is installed as mihomo's dialer socket hook.
	UsePlatformAutoDetectInterfaceControl() bool

	// AutoDetectInterfaceControl binds one outbound socket fd to the
	// current physical default interface (IP_BOUND_IF with the index from
	// NWPathMonitor). Called on every outbound dial once installed —
	// keep it allocation-free and fast.
	AutoDetectInterfaceControl(fd int32) error

	// StartDefaultInterfaceMonitor starts NWPathMonitor and pushes changes
	// through listener until CloseDefaultInterfaceMonitor. Wiring into
	// mihomo's dialer/resolver happens Go-side (the
	// sing-tun monitor-override question).
	StartDefaultInterfaceMonitor(listener InterfaceUpdateListener) error
	CloseDefaultInterfaceMonitor(listener InterfaceUpdateListener) error

	// GetInterfaces enumerates system interfaces (name/index/addresses),
	// feeding mihomo's interface cache on path changes.
	GetInterfaces() (NetworkInterfaceIterator, error)

	// UnderNetworkExtension distinguishes NE from in-app hosting: memory
	// tuning and probes differ between the two.
	UnderNetworkExtension() bool
}

// TunOptions is defined in tun.go (the getter surface OpenTun receives).

// InterfaceUpdateListener receives default-route changes from NWPathMonitor
// (Swift calls Go). isExpensive/isConstrained mirror NWPath flags.
type InterfaceUpdateListener interface {
	UpdateDefaultInterface(interfaceName string, interfaceIndex int32, isExpensive bool, isConstrained bool, supportsIPv4 bool, supportsIPv6 bool)
}
