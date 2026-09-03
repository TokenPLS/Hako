//go:build with_gvisor

package tun

import (
	"testing"
	"time"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv4"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	"github.com/metacubex/gvisor/pkg/waiter"
)

// Every TCP connection an application opens through the tunnel becomes a gVisor
// endpoint on this side of the TUN. Forcing keepalive to idle 15 s / interval 15 s on
// each of them meant every idle connection on the phone woke the extension four times
// a minute for a probe and its answer that never left the device. sing-tun v0.8.12
// dropped the forced values and left gVisor's own (idle 2 h, interval 75 s); mihomo's
// fork still carries them. Keepalive itself stays on, so a peer that vanished is still
// noticed -- at the pace the rest of the system uses, not twenty times faster.
func TestForwardedTCPEndpointsKeepGVisorsOwnKeepalivePace(t *testing.T) {
	ipStack, err := NewGVisorStack(channel.New(1, 1500, ""))
	if err != nil {
		t.Fatal(err)
	}
	defer ipStack.Close()
	var wq waiter.Queue
	endpoint, tcpErr := ipStack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if tcpErr != nil {
		t.Fatal(tcpErr)
	}
	defer endpoint.Close()

	configureForwardedTCPEndpoint(endpoint)

	if !endpoint.SocketOptions().GetKeepAlive() {
		t.Fatal("keepalive must stay enabled: a peer that vanished without a FIN is still to be noticed")
	}
	var idle tcpip.KeepaliveIdleOption
	if err := endpoint.GetSockOpt(&idle); err != nil {
		t.Fatal(err)
	}
	var interval tcpip.KeepaliveIntervalOption
	if err := endpoint.GetSockOpt(&interval); err != nil {
		t.Fatal(err)
	}
	if time.Duration(idle) == 15*time.Second || time.Duration(interval) == 15*time.Second {
		t.Fatalf("the forced 15 s keepalive is back: idle=%v interval=%v", time.Duration(idle), time.Duration(interval))
	}
	if time.Duration(idle) != tcp.DefaultKeepaliveIdle || time.Duration(interval) != tcp.DefaultKeepaliveInterval {
		t.Fatalf("expected gVisor's own pace (idle %v, interval %v), got idle=%v interval=%v", tcp.DefaultKeepaliveIdle, tcp.DefaultKeepaliveInterval, time.Duration(idle), time.Duration(interval))
	}
}
