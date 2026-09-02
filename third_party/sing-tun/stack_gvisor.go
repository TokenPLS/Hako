//go:build with_gvisor

package tun

import (
	"context"
	"net/netip"
	"sort"
	"time"

	E "github.com/metacubex/sing/common/exceptions"
	"github.com/metacubex/sing/common/logger"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv4"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv6"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/icmp"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/udp"
)

const WithGVisor = true

const DefaultNIC tcpip.NICID = 1

type GVisor struct {
	ctx                  context.Context
	tun                  GVisorTun
	inet4Address         netip.Addr
	inet6Address         netip.Addr
	inet4LoopbackAddress []netip.Addr
	inet6LoopbackAddress []netip.Addr
	udpTimeout           time.Duration
	icmpTimeout          time.Duration
	broadcastAddr        netip.Addr
	handler              Handler
	logger               logger.Logger
	stack                *stack.Stack
	endpoint             stack.LinkEndpoint
}

type GVisorTun interface {
	Tun
	WritePacket(pkt *stack.PacketBuffer) (int, error)
	NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error)
}

func NewGVisor(
	options StackOptions,
) (Stack, error) {
	gTun, isGTun := options.Tun.(GVisorTun)
	if !isGTun {
		return nil, E.New("gVisor stack is unsupported on current platform")
	}

	var (
		inet4Address netip.Addr
		inet6Address netip.Addr
	)
	if len(options.TunOptions.Inet4Address) > 0 {
		inet4Address = options.TunOptions.Inet4Address[0].Addr()
	}
	if len(options.TunOptions.Inet6Address) > 0 {
		inet6Address = options.TunOptions.Inet6Address[0].Addr()
	}

	gStack := &GVisor{
		ctx:                  options.Context,
		tun:                  gTun,
		inet4Address:         inet4Address,
		inet6Address:         inet6Address,
		inet4LoopbackAddress: options.TunOptions.Inet4LoopbackAddress,
		inet6LoopbackAddress: options.TunOptions.Inet6LoopbackAddress,
		udpTimeout:           options.UDPTimeout,
		icmpTimeout:          options.ICMPTimeout,
		broadcastAddr:        BroadcastAddr(options.TunOptions.Inet4Address),
		handler:              options.Handler,
		logger:               options.Logger,
	}
	return gStack, nil
}

func (t *GVisor) Start() error {
	linkEndpoint, nicOptions, err := t.tun.NewEndpoint()
	if err != nil {
		return err
	}
	linkEndpoint = &LinkEndpointFilter{linkEndpoint, t.broadcastAddr, t.tun}
	ipStack, err := NewGVisorStackWithOptions(linkEndpoint, nicOptions)
	if err != nil {
		return err
	}
	ipStack.SetTransportProtocolHandler(tcp.ProtocolNumber, NewTCPForwarderWithLoopback(t.ctx, ipStack, t.handler, t.inet4LoopbackAddress, t.inet6LoopbackAddress, t.tun).HandlePacket)
	ipStack.SetTransportProtocolHandler(udp.ProtocolNumber, NewUDPForwarder(t.ctx, ipStack, t.handler).HandlePacket)
	icmpForwarder := NewICMPForwarder(t.ctx, ipStack, t.inet4Address, t.inet6Address, t.handler, t.icmpTimeout)
	ipStack.SetTransportProtocolHandler(icmp.ProtocolNumber4, icmpForwarder.HandlePacket)
	ipStack.SetTransportProtocolHandler(icmp.ProtocolNumber6, icmpForwarder.HandlePacket)
	t.stack = ipStack
	t.endpoint = linkEndpoint
	GVisorTCPWindowSnapshot = newGVisorWindowSnapshot(ipStack)
	return nil
}

func (t *GVisor) Close() error {
	if t.stack == nil {
		return nil
	}
	GVisorTCPWindowSnapshot = nil
	t.endpoint.Attach(nil)
	t.stack.Close()
	for _, endpoint := range t.stack.CleanupEndpoints() {
		endpoint.Abort()
	}
	return nil
}

// newGVisorWindowSnapshot reads the window state LIVE from the stack: the
// installed range option (proving the tunable wiring, not restating it) and
// the effective receive/send buffer size of every registered TCP endpoint.
func newGVisorWindowSnapshot(s *stack.Stack) func() GVisorTCPWindowReport {
	return func() GVisorTCPWindowReport {
		var report GVisorTCPWindowReport
		var recvRange tcpip.TCPReceiveBufferSizeRangeOption
		if err := s.TransportProtocolOption(tcp.ProtocolNumber, &recvRange); err == nil {
			report.MinBytes = recvRange.Min
			report.DefaultBytes = recvRange.Default
			report.MaxBytes = recvRange.Max
		}
		var occupancy []int
		for _, transportEndpoint := range s.RegisteredEndpoints() {
			endpoint, ok := transportEndpoint.(tcpip.Endpoint)
			if !ok {
				continue
			}
			info, ok := endpoint.Info().(*stack.TransportEndpointInfo)
			if !ok || info.TransProto != tcp.ProtocolNumber {
				continue
			}
			// Per-endpoint drop count first: it is meaningful even for an endpoint
			// whose occupancy cannot be read, and it is the only direct evidence that
			// the memory gate ever refused a segment.
			if endpointStats, ok := endpoint.Stats().(*tcp.Stats); ok {
				report.SegmentQueueDroppedTotal += endpointStats.ReceiveErrors.SegmentQueueDropped.Value()
			}
			// RcvBufUsed = queued PAYLOAD bytes, not memory; see the field comment on
			// GVisorTCPWindowReport. SO_RCVBUF (GetReceiveBufferSize) reports a 1 MiB
			// nominal default that is never clamped and would overstate by ~8x.
			used, err := endpoint.GetSockOptInt(tcpip.ReceiveQueueSizeOption)
			if err != nil {
				continue
			}
			occupancy = append(occupancy, used)
		}
		report.TCPConnections = len(occupancy)
		report.ReceiveOccupancyP50Bytes, report.ReceiveOccupancyP95Bytes, report.ReceiveOccupancyMaxBytes = distribution(occupancy)
		if report.MaxBytes > 0 {
			threshold := report.MaxBytes * 9 / 10
			for _, used := range occupancy {
				if used >= threshold {
					report.ConnectionsNearReceiveMax++
				}
			}
		}
		return report
	}
}

func distribution(sizes []int) (p50, p95, max int) {
	if len(sizes) == 0 {
		return 0, 0, 0
	}
	sorted := make([]int, len(sizes))
	copy(sorted, sizes)
	sort.Ints(sorted)
	return sorted[len(sorted)/2], sorted[len(sorted)*95/100], sorted[len(sorted)-1]
}

func AddressFromAddr(destination netip.Addr) tcpip.Address {
	if destination.Is6() {
		return tcpip.AddrFrom16(destination.As16())
	} else {
		return tcpip.AddrFrom4(destination.As4())
	}
}

func AddrFromAddress(address tcpip.Address) netip.Addr {
	if address.Len() == 16 {
		return netip.AddrFrom16(address.As16())
	} else {
		return netip.AddrFrom4(address.As4())
	}
}

func NewGVisorStack(ep stack.LinkEndpoint) (*stack.Stack, error) {
	return NewGVisorStackWithOptions(ep, stack.NICOptions{})
}

func NewGVisorStackWithOptions(ep stack.LinkEndpoint, opts stack.NICOptions) (*stack.Stack, error) {
	ipStack := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
			icmp.NewProtocol6,
		},
	})
	err := ipStack.CreateNICWithOptions(DefaultNIC, ep, opts)
	if err != nil {
		return nil, gonet.TranslateNetstackError(err)
	}
	ipStack.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: DefaultNIC},
		{Destination: header.IPv6EmptySubnet, NIC: DefaultNIC},
	})
	ipStack.SetSpoofing(DefaultNIC, true)
	ipStack.SetPromiscuousMode(DefaultNIC, true)
	// Receive/send window range {4 KiB, 32 KiB, 128 KiB} with moderation on is
	// deliberately IDENTICAL to sing-box/sing-tun's shipping iOS production
	// value (SagerNet/sing-tun stack_gvisor.go, commit 1664d083f "Reduce iOS
	// TCP buffers"): connections start at 32 KiB and gVisor's moderation grows
	// busy ones only toward 128 KiB, so per-connection memory follows load and
	// is bounded at ~Max (window ≈ Max/2). Do NOT chase a smaller fixed window
	// (mihomo's 20 KiB throttles single-stream throughput to ~1.6 Mbit/s at
	// 50 ms RTT) and do NOT disable moderation (documented to cause stalls,
	// sing-box#3976). On-device A/B confirmed the win over the old 20 KiB:
	// 20K≈305 Mbps, 64K≈526, 128K≈600+ with a core-memory delta under load of
	// ~0.3 MiB. iOS NE hard cap is 50 MiB (jetsam); the real many-connection
	// backstops are the Go soft memory limit + TCP connection admission cap,
	// not this window (gVisor has no global receive-memory limit). A positive
	// GVisorTCPBufferBytes pins Default==Max (fixed window) for benchmarks.
	bufMin, bufDefault, bufMax := 4096, 32*1024, 128*1024
	if GVisorTCPBufferBytes > 0 {
		bufMin, bufDefault, bufMax = 1, GVisorTCPBufferBytes, GVisorTCPBufferBytes
	}
	ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     bufMin,
		Default: bufDefault,
		Max:     bufMax,
	})
	ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpip.TCPSendBufferSizeRangeOption{
		Min:     bufMin,
		Default: bufDefault,
		Max:     bufMax,
	})
	sOpt := tcpip.TCPSACKEnabled(true)
	ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &sOpt)
	mOpt := tcpip.TCPModerateReceiveBufferOption(true)
	ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &mOpt)
	return ipStack, nil
}
