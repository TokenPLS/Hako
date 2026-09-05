package hako

import "sync/atomic"

// includeAllNetworksRequested is the extension's reading of
// NETunnelProviderProtocol.includeAllNetworks for the session it is starting, handed in
// through SetupOptions before Start. It is startup-only: the setting lives on the saved
// tunnel configuration and only takes effect on a reconnect, so a running core never sees
// it change.
//
// What the bit decides. Under Include All Networks the kernel drops every packet that does
// not leave through the tunnel. The gVisor stack terminates the tunnel's TCP inside the
// process and dials out on the extension's own sockets, which do leave through the tunnel.
// The system and mixed stacks instead re-inject the tunnel's TCP through the kernel's own
// stack, and those packets are exactly what the setting drops -- the session looks alive
// (proxy tests use the extension's sockets), while every flow through the tun goes nowhere,
// and nothing in the core's log says so. sing-tun refuses `system` and `mixed` when it is
// told about the setting (ErrIncludeAllNetworks), but this core never told it.
//
// Two consumers read the bit. overrideTunForIOS moves a written system/mixed stack to
// gVisor and the move is reported as a forced, recoverable deviation on tun.stack; Setup
// also hands the bit to the stack layer (listener/sing_tun.IncludeAllNetworks) so that a
// stack the override does not catch fails at Start with sing-tun's own error instead of
// running silently.
var includeAllNetworksRequested atomic.Bool

func includeAllNetworksActive() bool {
	return includeAllNetworksRequested.Load()
}
