//go:build darwin

package keepalive

import "time"

// Apple platforms need explicit keepalive defaults because Go's are wrong for a radio.
//
// Nothing in this tree ever assigns keepAliveIdle or keepAliveInterval: they are only
// set from configuration, and no configuration default exists, so both stay zero. Zero
// reaches net/tcpsockopt_darwin.go, which substitutes Go's own
// defaultTCPKeepAliveIdle/Interval of 15 seconds each. Meanwhile
// component/dialer/dialer.go calls SetNetDialer above the DefaultSocketHook branch, so
// Apple builds get it on every outbound socket.
//
// Darwin resets the idle timer after an ACKed probe and uses TCP_KEEPINTVL only for
// unanswered retransmits, so the steady-state probe rate is governed by idle alone:
// every 15 seconds instead of every 5 minutes, twenty times as often. tunnel/tunnel.go
// has no idle teardown for relayed TCP, so an idle outbound socket keeps probing for as
// long as it exists, and each probe on cellular promotes the radio out of idle.
//
// The values match the reference implementation that ships this on Apple platforms
// (5 minutes, 75 seconds). Dead-peer detection moves from roughly 150 seconds to roughly
// 975 seconds with the unchanged probe count of 9 -- still inside a plausible session,
// and the right trade for a phone.
//
// Scoped to darwin on purpose: 15s/15s is upstream's behaviour and costs nothing on
// platforms without a radio to wake, so diverging there would be stricter than upstream
// without the platform requiring it. SetDisableKeepAlive already establishes the shape
// with its android carve-out.
const (
	defaultKeepAliveIdle     = 5 * time.Minute
	defaultKeepAliveInterval = 75 * time.Second
)
