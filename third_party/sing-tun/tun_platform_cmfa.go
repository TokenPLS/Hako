//go:build cmfa

package tun

// A cmfa framework is embedded in an Apple platform host. NetworkExtension or
// a future macOS platform adapter must create and configure the virtual
// interface through Apple-owned APIs, then provide the descriptor to sing-tun.
const platformTunRequiresFileDescriptor = true
