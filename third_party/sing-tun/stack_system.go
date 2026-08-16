package tun

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/metacubex/sing-tun/internal/gtcpip/checksum"
	"github.com/metacubex/sing-tun/internal/gtcpip/header"
	"github.com/metacubex/sing/common"
	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/control"
	E "github.com/metacubex/sing/common/exceptions"
	"github.com/metacubex/sing/common/logger"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

var ErrIncludeAllNetworks = E.New("`system` and `mixed` stack are not available when `includeAllNetworks` is enabled. See https://github.com/SagerNet/sing-tun/issues/25")

type System struct {
	ctx                  context.Context
	tun                  Tun
	tunName              string
	mtu                  int
	handler              Handler
	logger               logger.Logger
	inet4Prefixes        []netip.Prefix
	inet6Prefixes        []netip.Prefix
	inet4Address         netip.Addr
	inet4NextAddress     netip.Addr
	inet6Address         netip.Addr
	inet6NextAddress     netip.Addr
	broadcastAddr        netip.Addr
	inet4LoopbackAddress []netip.Addr
	inet6LoopbackAddress []netip.Addr
	udpTimeout           time.Duration
	icmpTimeout          time.Duration
	tcpListener          net.Listener
	tcpListener6         net.Listener
	tcpPort              uint16
	tcpPort6             uint16
	tcpNat               *TCPNat
	directNat            *DirectRouteMapping
	bindInterface        bool
	interfaceFinder      control.InterfaceFinder
	enforceBind          bool
	frontHeadroom        int
	txChecksumOffload    bool
	recvMsgX             bool
}

type Session struct {
	SourceAddress      netip.Addr
	DestinationAddress netip.Addr
	SourcePort         uint16
	DestinationPort    uint16
}

func NewSystem(options StackOptions) (Stack, error) {
	stack := &System{
		ctx:                  options.Context,
		tun:                  options.Tun,
		tunName:              options.TunOptions.Name,
		mtu:                  int(options.TunOptions.MTU),
		inet4LoopbackAddress: options.TunOptions.Inet4LoopbackAddress,
		inet6LoopbackAddress: options.TunOptions.Inet6LoopbackAddress,
		udpTimeout:           options.UDPTimeout,
		icmpTimeout:          options.ICMPTimeout,
		handler:              options.Handler,
		logger:               options.Logger,
		inet4Prefixes:        options.TunOptions.Inet4Address,
		inet6Prefixes:        options.TunOptions.Inet6Address,
		broadcastAddr:        BroadcastAddr(options.TunOptions.Inet4Address),
		bindInterface:        options.ForwarderBindInterface,
		interfaceFinder:      options.InterfaceFinder,
		recvMsgX:             options.TunOptions.EXP_RecvMsgX,
		enforceBind:          options.EnforceBindInterface,
	}
	if len(options.TunOptions.Inet4Address) > 0 {
		if !HasNextAddress(options.TunOptions.Inet4Address[0], 1) {
			return nil, E.New("need one more IPv4 address in first prefix for system stack")
		}
		stack.inet4Address = options.TunOptions.Inet4Address[0].Addr()
		stack.inet4NextAddress = stack.inet4Address.Next()
	}
	if len(options.TunOptions.Inet6Address) > 0 {
		if !HasNextAddress(options.TunOptions.Inet6Address[0], 1) {
			return nil, E.New("need one more IPv6 address in first prefix for system stack")
		}
		stack.inet6Address = options.TunOptions.Inet6Address[0].Addr()
		stack.inet6NextAddress = stack.inet6Address.Next()
	}
	if !stack.inet4NextAddress.IsValid() && !stack.inet6NextAddress.IsValid() {
		return nil, E.New("missing interface address")
	}
	return stack, nil
}

func (s *System) Close() error {
	return common.Close(
		s.tcpListener,
		s.tcpListener6,
	)
}

func (s *System) Start() error {
	err := s.start()
	if err != nil {
		return err
	}
	go s.tunLoop()
	return nil
}

func (s *System) start() error {
	_ = fixWindowsFirewall()
	var listenConfig net.ListenConfig
	if s.bindInterface || s.enforceBind {
		listenConfig.Control = control.Append(listenConfig.Control, func(network, address string, conn syscall.RawConn) error {
			bindErr := control.BindToInterface0(s.interfaceFinder, conn, network, address, s.tunName, -1, true)
			if bindErr != nil {
				s.logger.Warn("bind forwarder to interface: ", bindErr)
			}
			if s.enforceBind {
				return bindErr
			}
			return nil
		})
	}
	var tcpListener net.Listener
	var err error
	if s.inet4NextAddress.IsValid() {
		address := net.JoinHostPort(s.inet4Address.String(), "0")
		if s.enforceBind {
			address = "0.0.0.0:0"
		}
		for i := 0; i < 3; i++ {
			tcpListener, err = s.listenWithTunBind(listenConfig, "tcp4", address, s.inet4Address)
			if !retryableListenError(err) {
				break
			}
			time.Sleep(time.Second)
		}
		if err != nil {
			return err
		}
		s.tcpListener = tcpListener
		s.tcpPort = M.SocksaddrFromNet(tcpListener.Addr()).Port
		go s.acceptLoop(tcpListener)
	}
	if s.inet6NextAddress.IsValid() {
		address := net.JoinHostPort(s.inet6Address.String(), "0")
		if s.enforceBind {
			address = "[:]:0"
		}
		for i := 0; i < 3; i++ {
			tcpListener, err = s.listenWithTunBind(listenConfig, "tcp6", address, s.inet6Address)
			if !retryableListenError(err) {
				break
			}
			time.Sleep(time.Second)
		}
		if err != nil {
			// The v4 listener and its accept goroutine are already live; leaving them behind on
			// a failed start leaks a socket and a goroutine per attempt into a memory-capped
			// extension process, and nobody upstream of here closes a stack that never started.
			if s.tcpListener != nil {
				_ = s.tcpListener.Close()
				s.tcpListener = nil
			}
			return err
		}
		s.tcpListener6 = tcpListener
		s.tcpPort6 = M.SocksaddrFromNet(tcpListener.Addr()).Port
		go s.acceptLoop(tcpListener)
	}
	s.tcpNat = NewNat(s.ctx, s.udpTimeout)
	s.directNat = NewDirectRouteMapping(s.icmpTimeout)
	return nil
}

// listenWithTunBind is the only way start() opens its TCP listeners. It attaches the
// IP_BOUND_IF hook that lets an NE-scoped extension socket receive packets injected on the tun
// (see stack_system_bindif_darwin.go), and it re-resolves the tun's interface index on EVERY
// call on purpose: the caller's retry loop exists because the tun address may not be on the
// interface yet when start() begins -- retryableListenError retries exactly that condition --
// and that is the same window in which the index lookup cannot succeed. Resolving once before
// the loop would skip the bind in precisely the runs the loop was built to save, and a lookup
// miss is itself retryable (errTunAddressNotPresent wraps EADDRNOTAVAIL) for the same reason.
//
// NOTHING here touches the outbound dialer -- binding egress to the tun is the loop the NE
// scope exists to prevent. Off darwin the lookup reports -1, bindListenerSupported is false,
// and this is a plain Listen.
//
// To whoever resolves the next upstream merge: upstream's version of start() listens through a
// ListenConfig named `listener`; that variable is deliberately gone from this fork so a
// PARTIAL conflict resolved in upstream's favour fails to compile. A wholesale take-theirs of
// the whole function compiles -- that direction is pinned behaviourally instead, by the test
// that swaps the enumeration seam to an empty table and requires start() to FAIL (it can only
// fail there by routing through this method).
func (s *System) listenWithTunBind(base net.ListenConfig, network, address string, tunAddr netip.Addr) (net.Listener, error) {
	index, carriers, enumErr := interfaceIndexCarrying(tunAddr)
	if enumErr != nil && bindListenerSupported {
		// Not "address not there yet" -- the enumeration itself failed, and the reader of this
		// line needs to chase getifaddrs, not their tun addressing. The platform side already
		// wrapped it retryably: a transient (ENOMEM under the extension's memory cap) heals on
		// the next attempt.
		s.logger.Warn("[bindif] interface enumeration failed: ", enumErr)
		return nil, enumErr
	}
	if carriers > 1 {
		s.logger.Warn("[bindif] ", carriers, " up interfaces carry ", tunAddr, "; binding to the newest, index ", index)
	}
	if hook := bindListenerToInterfaceControl(index, s.logger); hook != nil {
		base.Control = control.Append(base.Control, hook)
	} else if bindListenerSupported {
		// Listening unbound "successfully" would be a tunnel that starts with TCP silently
		// dead -- the multi-day failure the bind exists to end. Fail the attempt the same way
		// upstream's own Listen on the absent address would, and let the caller retry.
		s.logger.Warn("[bindif] no up interface carries ", tunAddr, " yet; not listening unbound on ", network)
		return nil, errTunAddressNotPresent
	}
	ln, err := base.Listen(s.ctx, network, address)
	if err == nil && index >= 0 {
		// True by construction: the bind hook fails the Listen when the setsockopt fails, so
		// reaching here with an index means the listener really is bound to it.
		s.logger.Info("[bindif] ", network, " listener bound to interface index ", index)
	}
	return ln, err
}

func (s *System) tunLoop() {
	if winTun, isWinTun := s.tun.(WinTun); isWinTun {
		s.wintunLoop(winTun)
		return
	}
	if linuxTUN, isLinuxTUN := s.tun.(LinuxTUN); isLinuxTUN {
		s.frontHeadroom = linuxTUN.FrontHeadroom()
		s.txChecksumOffload = linuxTUN.TXChecksumOffload()
		batchSize := linuxTUN.BatchSize()
		if batchSize > 1 {
			s.batchLoopLinux(linuxTUN, batchSize)
			return
		}
	}
	if darwinTUN, isDarwinTUN := s.tun.(DarwinTUN); isDarwinTUN && s.recvMsgX {
		s.batchLoopDarwin(darwinTUN)
		return
	}
	packetBuffer := make([]byte, s.mtu+PacketOffset)
	for {
		n, err := s.tun.Read(packetBuffer)
		if err != nil {
			if E.IsClosed(err) {
				return
			}
			s.logger.Error(E.Cause(err, "read packet"))
		}
		if n < header.IPv4MinimumSize {
			continue
		}
		rawPacket := packetBuffer[:n]
		packet := packetBuffer[PacketOffset:n]
		if s.processPacket(packet) {
			_, err = s.tun.Write(rawPacket)
			if err != nil {
				s.logger.Trace(E.Cause(err, "write packet"))
			}
		}
	}
}

func (s *System) wintunLoop(winTun WinTun) {
	for {
		packet, release, err := winTun.ReadPacket()
		if err != nil {
			return
		}
		if len(packet) < header.IPv4MinimumSize {
			release()
			continue
		}
		if s.processPacket(packet) {
			_, err = winTun.Write(packet)
			if err != nil {
				s.logger.Trace(E.Cause(err, "write packet"))
			}
		}
		release()
	}
}

func (s *System) batchLoopLinux(linuxTUN LinuxTUN, batchSize int) {
	packetBuffers := make([][]byte, batchSize)
	writeBuffers := make([][]byte, batchSize)
	packetSizes := make([]int, batchSize)
	for i := range packetBuffers {
		packetBuffers[i] = make([]byte, s.mtu+s.frontHeadroom)
	}
	for {
		n, err := linuxTUN.BatchRead(packetBuffers, s.frontHeadroom, packetSizes)
		if err != nil {
			if E.IsClosed(err) {
				return
			}
			s.logger.Error(E.Cause(err, "batch read packet"))
		}
		if n == 0 {
			continue
		}
		for i := 0; i < n; i++ {
			packetSize := packetSizes[i]
			if packetSize < header.IPv4MinimumSize {
				continue
			}
			packetBuffer := packetBuffers[i]
			packet := packetBuffer[s.frontHeadroom : s.frontHeadroom+packetSize]
			if s.processPacket(packet) {
				writeBuffers = append(writeBuffers, packetBuffer[:s.frontHeadroom+packetSize])
			}
		}
		if len(writeBuffers) > 0 {
			_, err = linuxTUN.BatchWrite(writeBuffers, s.frontHeadroom)
			if err != nil {
				s.logger.Trace(E.Cause(err, "batch write packet"))
			}
			writeBuffers = writeBuffers[:0]
		}
	}
}

func (s *System) batchLoopDarwin(darwinTUN DarwinTUN) {
	var writeBuffers []*buf.Buffer
	for {
		buffers, err := darwinTUN.BatchRead()
		if err != nil {
			if E.IsClosed(err) {
				return
			}
			s.logger.Error(E.Cause(err, "batch read packet"))
		}
		if len(buffers) == 0 {
			continue
		}
		writeBuffers = writeBuffers[:0]
		for _, buffer := range buffers {
			packetSize := buffer.Len()
			if packetSize < header.IPv4MinimumSize {
				buffer.Release()
				continue
			}
			if s.processPacket(buffer.Bytes()) {
				writeBuffers = append(writeBuffers, buffer)
			} else {
				buffer.Release()
			}
		}
		if len(writeBuffers) > 0 {
			err = darwinTUN.BatchWrite(writeBuffers)
			if err != nil {
				s.logger.Trace(E.Cause(err, "batch write packet"))
			}
			buf.ReleaseMulti(writeBuffers)
		}
	}
}

func (s *System) processPacket(packet []byte) bool {
	var (
		writeBack bool
		err       error
	)
	switch ipVersion := header.IPVersion(packet); ipVersion {
	case header.IPv4Version:
		writeBack, err = s.processIPv4(packet)
	case header.IPv6Version:
		writeBack, err = s.processIPv6(packet)
	default:
		err = E.New("ip: unknown version: ", ipVersion)
	}
	if err != nil {
		s.logger.Trace(err)
		return false
	}
	return writeBack
}

func (s *System) acceptLoop(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		connPort := M.SocksaddrFromNet(conn.RemoteAddr()).Port
		session := s.tcpNat.LookupBack(connPort)
		if session == nil {
			s.logger.Trace(E.New("unknown session with port ", connPort))
			continue
		}
		go func() {
			_ = s.handler.NewConnection(s.ctx, conn, M.Metadata{
				Source:      M.SocksaddrFromNetIP(session.Source),
				Destination: M.SocksaddrFromNetIP(session.Destination),
			})
			if tcpConn, isTCPConn := conn.(*net.TCPConn); isTCPConn {
				_ = tcpConn.SetLinger(0)
			}
			_ = conn.Close()
		}()
	}
}

func (s *System) processIPv4(ipHdr header.IPv4) (writeBack bool, err error) {
	destination := ipHdr.DestinationAddr()
	if destination == s.broadcastAddr || !destination.IsGlobalUnicast() {
		return
	}
	writeBack = true
	switch ipHdr.TransportProtocol() {
	case header.TCPProtocolNumber:
		writeBack, err = s.processIPv4TCP(ipHdr, ipHdr.Payload())
	case header.UDPProtocolNumber:
		writeBack = false
		err = s.processIPv4UDP(ipHdr, ipHdr.Payload())
	case header.ICMPv4ProtocolNumber:
		writeBack, err = s.processIPv4ICMP(ipHdr, ipHdr.Payload())
	}
	if err != nil {
		writeBack = false
	}
	return
}

func (s *System) processIPv6(ipHdr header.IPv6) (writeBack bool, err error) {
	if !ipHdr.DestinationAddr().IsGlobalUnicast() {
		return
	}
	writeBack = true
	switch ipHdr.TransportProtocol() {
	case header.TCPProtocolNumber:
		writeBack, err = s.processIPv6TCP(ipHdr, ipHdr.Payload())
	case header.UDPProtocolNumber:
		writeBack = false
		err = s.processIPv6UDP(ipHdr, ipHdr.Payload())
	case header.ICMPv6ProtocolNumber:
		writeBack, err = s.processIPv6ICMP(ipHdr, ipHdr.Payload())
	}
	if err != nil {
		writeBack = false
	}
	return
}

func (s *System) processIPv4TCP(ipHdr header.IPv4, tcpHdr header.TCP) (bool, error) {
	source := netip.AddrPortFrom(ipHdr.SourceAddr(), tcpHdr.SourcePort())
	destination := netip.AddrPortFrom(ipHdr.DestinationAddr(), tcpHdr.DestinationPort())
	if !destination.Addr().IsGlobalUnicast() {
		return false, nil
	} else if source.Addr() == s.inet4Address && source.Port() == s.tcpPort {
		session := s.tcpNat.LookupBack(destination.Port())
		if session == nil {
			return false, E.New("ipv4: tcp: session not found: ", destination.Port())
		}
		ipHdr.SetSourceAddr(session.Destination.Addr())
		tcpHdr.SetSourcePort(session.Destination.Port())
		ipHdr.SetDestinationAddr(session.Source.Addr())
		tcpHdr.SetDestinationPort(session.Source.Port())
	} else {
		var loopback bool
		for _, inet4LoopbackAddress := range s.inet4LoopbackAddress {
			if destination.Addr() == inet4LoopbackAddress {
				ipHdr.SetDestinationAddr(ipHdr.SourceAddr())
				ipHdr.SetSourceAddr(inet4LoopbackAddress)
				loopback = true
				break
			}
		}
		if !loopback {
			natPort := s.tcpNat.Lookup(source, destination)
			ipHdr.SetSourceAddr(s.inet4NextAddress)
			tcpHdr.SetSourcePort(natPort)
			ipHdr.SetDestinationAddr(s.inet4Address)
			tcpHdr.SetDestinationPort(s.tcpPort)
		}
	}
	if !s.txChecksumOffload {
		tcpHdr.SetChecksum(^checksum.Checksum(tcpHdr.Payload(), tcpHdr.CalculateChecksum(
			header.PseudoHeaderChecksum(header.TCPProtocolNumber, ipHdr.SourceAddressSlice(), ipHdr.DestinationAddressSlice(), ipHdr.PayloadLength()),
		)))
	} else {
		tcpHdr.SetChecksum(0)
	}
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
	return true, nil
}

func (s *System) resetIPv4TCP(origIPHdr header.IPv4, origTCPHdr header.TCP) error {
	frontHeadroom := s.frontHeadroom + PacketOffset
	newPacket := buf.NewSize(frontHeadroom + header.IPv4MinimumSize + header.TCPMinimumSize)
	defer newPacket.Release()
	newPacket.Resize(frontHeadroom, header.IPv4MinimumSize+header.TCPMinimumSize)
	ipHdr := header.IPv4(newPacket.Bytes())
	ipHdr.Encode(&header.IPv4Fields{
		TotalLength: uint16(newPacket.Len()),
		Protocol:    uint8(header.TCPProtocolNumber),
		SrcAddr:     origIPHdr.DestinationAddr(),
		DstAddr:     origIPHdr.SourceAddr(),
	})
	tcpHdr := header.TCP(ipHdr.Payload())
	fields := header.TCPFields{
		SrcPort:    origTCPHdr.DestinationPort(),
		DstPort:    origTCPHdr.SourcePort(),
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagRst,
	}
	if origTCPHdr.Flags()&header.TCPFlagAck != 0 {
		fields.SeqNum = origTCPHdr.AckNumber()
	} else {
		fields.Flags |= header.TCPFlagAck
		ackNum := origTCPHdr.SequenceNumber() + uint32(len(origTCPHdr.Payload()))
		if origTCPHdr.Flags()&header.TCPFlagSyn != 0 {
			ackNum++
		}
		if origTCPHdr.Flags()&header.TCPFlagFin != 0 {
			ackNum++
		}
		fields.AckNum = ackNum
	}
	tcpHdr.Encode(&fields)
	if !s.txChecksumOffload {
		tcpHdr.SetChecksum(^tcpHdr.CalculateChecksum(header.PseudoHeaderChecksum(header.TCPProtocolNumber, ipHdr.SourceAddressSlice(), ipHdr.DestinationAddressSlice(), header.TCPMinimumSize)))
	}
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
	if PacketOffset > 0 {
		PacketFillHeader(newPacket.ExtendHeader(PacketOffset), header.IPv4Version)
	} else {
		newPacket.Advance(-s.frontHeadroom)
	}
	return common.Error(s.tun.Write(newPacket.Bytes()))
}

func (s *System) processIPv6TCP(ipHdr header.IPv6, tcpHdr header.TCP) (bool, error) {
	source := netip.AddrPortFrom(ipHdr.SourceAddr(), tcpHdr.SourcePort())
	destination := netip.AddrPortFrom(ipHdr.DestinationAddr(), tcpHdr.DestinationPort())
	if !destination.Addr().IsGlobalUnicast() {
		return false, nil
	} else if source.Addr() == s.inet6Address && source.Port() == s.tcpPort6 {
		session := s.tcpNat.LookupBack(destination.Port())
		if session == nil {
			return false, E.New("ipv6: tcp: session not found: ", destination.Port())
		}
		ipHdr.SetSourceAddr(session.Destination.Addr())
		tcpHdr.SetSourcePort(session.Destination.Port())
		ipHdr.SetDestinationAddr(session.Source.Addr())
		tcpHdr.SetDestinationPort(session.Source.Port())
	} else {
		var loopback bool
		for _, inet6LoopbackAddress := range s.inet6LoopbackAddress {
			if destination.Addr() == inet6LoopbackAddress {
				ipHdr.SetDestinationAddr(ipHdr.SourceAddr())
				ipHdr.SetSourceAddr(inet6LoopbackAddress)
				loopback = true
				break
			}
		}
		if !loopback {
			natPort := s.tcpNat.Lookup(source, destination)
			ipHdr.SetSourceAddr(s.inet6NextAddress)
			tcpHdr.SetSourcePort(natPort)
			ipHdr.SetDestinationAddr(s.inet6Address)
			tcpHdr.SetDestinationPort(s.tcpPort6)
		}
	}
	if !s.txChecksumOffload {
		tcpHdr.SetChecksum(^checksum.Checksum(tcpHdr.Payload(), tcpHdr.CalculateChecksum(
			header.PseudoHeaderChecksum(header.TCPProtocolNumber, ipHdr.SourceAddressSlice(), ipHdr.DestinationAddressSlice(), ipHdr.PayloadLength()),
		)))
	} else {
		tcpHdr.SetChecksum(0)
	}
	return true, nil
}

func (s *System) resetIPv6TCP(origIPHdr header.IPv6, origTCPHdr header.TCP) error {
	frontHeadroom := s.frontHeadroom + PacketOffset
	newPacket := buf.NewSize(frontHeadroom + header.IPv6MinimumSize + header.TCPMinimumSize)
	defer newPacket.Release()
	newPacket.Resize(frontHeadroom, header.IPv6MinimumSize+header.TCPMinimumSize)
	ipHdr := header.IPv6(newPacket.Bytes())
	ipHdr.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(header.TCPMinimumSize),
		TransportProtocol: header.TCPProtocolNumber,
		SrcAddr:           origIPHdr.DestinationAddr(),
		DstAddr:           origIPHdr.SourceAddr(),
	})
	tcpHdr := header.TCP(ipHdr.Payload())
	fields := header.TCPFields{
		SrcPort:    origTCPHdr.DestinationPort(),
		DstPort:    origTCPHdr.SourcePort(),
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagRst,
	}
	if origTCPHdr.Flags()&header.TCPFlagAck != 0 {
		fields.SeqNum = origTCPHdr.AckNumber()
	} else {
		fields.Flags |= header.TCPFlagAck
		ackNum := origTCPHdr.SequenceNumber() + uint32(len(origTCPHdr.Payload()))
		if origTCPHdr.Flags()&header.TCPFlagSyn != 0 {
			ackNum++
		}
		if origTCPHdr.Flags()&header.TCPFlagFin != 0 {
			ackNum++
		}
		fields.AckNum = ackNum
	}
	tcpHdr.Encode(&fields)
	if !s.txChecksumOffload {
		tcpHdr.SetChecksum(^tcpHdr.CalculateChecksum(header.PseudoHeaderChecksum(header.TCPProtocolNumber, ipHdr.SourceAddressSlice(), ipHdr.DestinationAddressSlice(), header.TCPMinimumSize)))
	}
	if PacketOffset > 0 {
		PacketFillHeader(newPacket.ExtendHeader(PacketOffset), header.IPv6Version)
	} else {
		newPacket.Advance(-s.frontHeadroom)
	}
	return common.Error(s.tun.Write(newPacket.Bytes()))
}

func (s *System) processIPv4UDP(ipHdr header.IPv4, udpHdr header.UDP) error {
	if ipHdr.Flags()&header.IPv4FlagMoreFragments != 0 {
		return E.New("ipv4: fragment dropped")
	}
	if ipHdr.FragmentOffset() != 0 {
		return E.New("ipv4: udp: fragment dropped")
	}
	source := netip.AddrPortFrom(ipHdr.SourceAddr(), udpHdr.SourcePort())
	destination := netip.AddrPortFrom(ipHdr.DestinationAddr(), udpHdr.DestinationPort())
	if !destination.Addr().IsGlobalUnicast() {
		return nil
	}
	data := buf.As(udpHdr.Payload())
	if data.Len() == 0 {
		return nil
	}
	metadata := M.Metadata{
		Source:      M.SocksaddrFromNetIP(source),
		Destination: M.SocksaddrFromNetIP(destination),
	}
	s.handler.NewPacket(s.ctx, source, data.ToOwned(), metadata, func(natConn N.PacketConn) N.PacketWriter {
		headerLen := ipHdr.HeaderLength() + header.UDPMinimumSize
		headerCopy := make([]byte, headerLen)
		copy(headerCopy, ipHdr[:headerLen])
		return &systemUDPPacketWriter4{
			s.tun,
			s.frontHeadroom + PacketOffset,
			headerCopy,
			source,
			s.txChecksumOffload,
		}
	})
	return nil
}

func (s *System) processIPv6UDP(ipHdr header.IPv6, udpHdr header.UDP) error {
	source := netip.AddrPortFrom(ipHdr.SourceAddr(), udpHdr.SourcePort())
	destination := netip.AddrPortFrom(ipHdr.DestinationAddr(), udpHdr.DestinationPort())
	if !destination.Addr().IsGlobalUnicast() {
		return nil
	}
	data := buf.As(udpHdr.Payload())
	if data.Len() == 0 {
		return nil
	}
	metadata := M.Metadata{
		Source:      M.SocksaddrFromNetIP(source),
		Destination: M.SocksaddrFromNetIP(destination),
	}
	s.handler.NewPacket(s.ctx, source, data.ToOwned(), metadata, func(natConn N.PacketConn) N.PacketWriter {
		headerLen := len(ipHdr) - int(ipHdr.PayloadLength()) + header.UDPMinimumSize
		headerCopy := make([]byte, headerLen)
		copy(headerCopy, ipHdr[:headerLen])
		return &systemUDPPacketWriter6{
			s.tun,
			s.frontHeadroom + PacketOffset,
			headerCopy,
			source,
			s.txChecksumOffload,
		}
	})
	return nil
}

func (s *System) processIPv4ICMP(ipHdr header.IPv4, icmpHdr header.ICMPv4) (bool, error) {
	if icmpHdr.Type() != header.ICMPv4Echo || icmpHdr.Code() != 0 {
		return false, nil
	}
	sourceAddr := ipHdr.SourceAddr()
	destinationAddr := ipHdr.DestinationAddr()
	if destinationAddr != s.inet4Address {
		action, err := s.directNat.Lookup(DirectRouteSession{Source: sourceAddr, Destination: destinationAddr}, func(timeout time.Duration) (DirectRouteDestination, error) {
			return s.handler.PrepareConnection(
				N.NetworkICMP,
				M.SocksaddrFrom(sourceAddr, 0),
				M.SocksaddrFrom(destinationAddr, 0),
				&systemICMPDirectPacketWriter4{s.tun, s.frontHeadroom + PacketOffset, sourceAddr},
				timeout,
			)
		})
		if errors.Is(err, ErrReset) {
			return false, s.rejectIPv4WithICMP(ipHdr, header.ICMPv4HostUnreachable)
		} else if errors.Is(err, ErrDrop) {
			return false, nil
		}
		if action != nil {
			return false, action.WritePacket(buf.As(ipHdr).ToOwned())
		}
	}
	icmpHdr.SetType(header.ICMPv4EchoReply)
	sourceAddress := ipHdr.SourceAddr()
	ipHdr.SetSourceAddr(ipHdr.DestinationAddr())
	ipHdr.SetDestinationAddr(sourceAddress)
	icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr, 0))
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
	return true, nil
}

func (s *System) rejectIPv4WithICMP(ipHdr header.IPv4, code header.ICMPv4Code) error {
	frontHeadroom := s.frontHeadroom + PacketOffset
	mtu := s.mtu
	const maxIPData = header.IPv4MinimumProcessableDatagramSize - header.IPv4MinimumSize
	if mtu > maxIPData {
		mtu = maxIPData
	}
	available := mtu - header.ICMPv4MinimumSize
	if available < len(ipHdr)+header.ICMPv4MinimumErrorPayloadSize {
		return nil
	}
	payload := ipHdr
	if len(payload) > available {
		payload = payload[:available]
	}
	newPacket := buf.NewSize(frontHeadroom + header.IPv4MinimumSize + header.ICMPv4MinimumSize + len(payload))
	defer newPacket.Release()
	newPacket.Resize(frontHeadroom, header.IPv4MinimumSize+header.ICMPv4MinimumSize+len(payload))
	newIPHdr := header.IPv4(newPacket.Bytes())
	newIPHdr.Encode(&header.IPv4Fields{
		TotalLength: uint16(newPacket.Len()),
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     ipHdr.DestinationAddr(),
		DstAddr:     ipHdr.SourceAddr(),
	})
	newIPHdr.SetChecksum(^newIPHdr.CalculateChecksum())
	icmpHdr := header.ICMPv4(newIPHdr.Payload())
	icmpHdr.SetType(header.ICMPv4DstUnreachable)
	icmpHdr.SetCode(code)
	icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr[:header.ICMPv4MinimumSize], checksum.Checksum(ipHdr.Payload(), 0)))
	copy(icmpHdr.Payload(), payload)
	if PacketOffset > 0 {
		PacketFillHeader(newPacket.ExtendHeader(PacketOffset), header.IPv4Version)
	} else {
		newPacket.Advance(-s.frontHeadroom)
	}
	return common.Error(s.tun.Write(newPacket.Bytes()))
}

func (s *System) processIPv6ICMP(ipHdr header.IPv6, icmpHdr header.ICMPv6) (bool, error) {
	if icmpHdr.Type() != header.ICMPv6EchoRequest || icmpHdr.Code() != 0 {
		return false, nil
	}
	sourceAddr := ipHdr.SourceAddr()
	destinationAddr := ipHdr.DestinationAddr()
	if destinationAddr != s.inet6Address {
		action, err := s.directNat.Lookup(DirectRouteSession{Source: sourceAddr, Destination: destinationAddr}, func(timeout time.Duration) (DirectRouteDestination, error) {
			return s.handler.PrepareConnection(
				N.NetworkICMP,
				M.SocksaddrFrom(sourceAddr, 0),
				M.SocksaddrFrom(destinationAddr, 0),
				&systemICMPDirectPacketWriter6{s.tun, s.frontHeadroom + PacketOffset, sourceAddr},
				timeout,
			)
		})
		if err != nil {
			if errors.Is(err, ErrReset) {
				return false, s.rejectIPv6WithICMP(ipHdr, header.ICMPv6AddressUnreachable)
			} else if errors.Is(err, ErrDrop) {
				return false, nil
			}
		}
		if action != nil {
			return false, action.WritePacket(buf.As(ipHdr).ToOwned())
		}
	}
	icmpHdr.SetType(header.ICMPv6EchoReply)
	sourceAddress := ipHdr.SourceAddr()
	ipHdr.SetSourceAddr(ipHdr.DestinationAddr())
	ipHdr.SetDestinationAddr(sourceAddress)
	icmpHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header: icmpHdr,
		Src:    ipHdr.SourceAddressSlice(),
		Dst:    ipHdr.DestinationAddressSlice(),
	}))
	return true, nil
}

func (s *System) rejectIPv6WithICMP(ipHdr header.IPv6, code header.ICMPv6Code) error {
	frontHeadroom := s.frontHeadroom + PacketOffset
	mtu := s.mtu
	const maxIPv6Data = header.IPv6MinimumMTU - header.IPv6FixedHeaderSize
	if mtu > maxIPv6Data {
		mtu = maxIPv6Data
	}
	available := mtu - header.ICMPv6ErrorHeaderSize
	if available < header.IPv6MinimumSize {
		return nil
	}
	payload := ipHdr
	if len(payload) > available {
		payload = payload[:available]
	}
	newPacket := buf.NewSize(frontHeadroom + header.IPv6MinimumSize + header.ICMPv6DstUnreachableMinimumSize + len(payload))
	defer newPacket.Release()
	newPacket.Resize(frontHeadroom, header.IPv6MinimumSize+header.ICMPv6DstUnreachableMinimumSize+len(payload))
	newIPHdr := header.IPv6(newPacket.Bytes())
	newIPHdr.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(header.ICMPv6DstUnreachableMinimumSize + len(payload)),
		TransportProtocol: header.ICMPv6ProtocolNumber,
		SrcAddr:           ipHdr.DestinationAddr(),
		DstAddr:           ipHdr.SourceAddr(),
	})
	icmpHdr := header.ICMPv6(newIPHdr.Payload())
	icmpHdr.SetType(header.ICMPv6DstUnreachable)
	icmpHdr.SetCode(code)
	icmpHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header:      icmpHdr[:header.ICMPv6DstUnreachableMinimumSize],
		Src:         newIPHdr.SourceAddressSlice(),
		Dst:         newIPHdr.DestinationAddressSlice(),
		PayloadCsum: checksum.Checksum(payload, 0),
		PayloadLen:  len(payload),
	}))
	copy(icmpHdr.Payload(), payload)
	if PacketOffset > 0 {
		PacketFillHeader(newPacket.ExtendHeader(PacketOffset), header.IPv6Version)
	} else {
		newPacket.Advance(-s.frontHeadroom)
	}
	return common.Error(s.tun.Write(newPacket.Bytes()))
}

type systemUDPPacketWriter4 struct {
	tun               Tun
	frontHeadroom     int
	header            []byte
	source            netip.AddrPort
	txChecksumOffload bool
}

func (w *systemUDPPacketWriter4) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	newPacket := buf.NewSize(w.frontHeadroom + len(w.header) + buffer.Len())
	defer newPacket.Release()
	newPacket.Resize(w.frontHeadroom, 0)
	newPacket.Write(w.header)
	newPacket.Write(buffer.Bytes())
	ipHdr := header.IPv4(newPacket.Bytes())
	ipHdr.SetTotalLength(uint16(newPacket.Len()))
	ipHdr.SetDestinationAddress(ipHdr.SourceAddress())
	ipHdr.SetSourceAddr(destination.Addr)
	udpHdr := header.UDP(ipHdr.Payload())
	udpHdr.SetDestinationPort(udpHdr.SourcePort())
	udpHdr.SetSourcePort(destination.Port)
	udpHdr.SetLength(uint16(buffer.Len() + header.UDPMinimumSize))
	if !w.txChecksumOffload {
		udpHdr.SetChecksum(^checksum.Checksum(udpHdr.Payload(), udpHdr.CalculateChecksum(
			header.PseudoHeaderChecksum(header.UDPProtocolNumber, ipHdr.SourceAddressSlice(), ipHdr.DestinationAddressSlice(), ipHdr.PayloadLength()),
		)))
	} else {
		udpHdr.SetChecksum(0)
	}
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
	if PacketOffset > 0 {
		PacketFillHeader(newPacket.ExtendHeader(PacketOffset), header.IPv4Version)
	} else {
		newPacket.Advance(-w.frontHeadroom)
	}
	return common.Error(w.tun.Write(newPacket.Bytes()))
}

type systemUDPPacketWriter6 struct {
	tun               Tun
	frontHeadroom     int
	header            []byte
	source            netip.AddrPort
	txChecksumOffload bool
}

func (w *systemUDPPacketWriter6) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	newPacket := buf.NewSize(w.frontHeadroom + len(w.header) + buffer.Len())
	defer newPacket.Release()
	newPacket.Resize(w.frontHeadroom, 0)
	newPacket.Write(w.header)
	newPacket.Write(buffer.Bytes())
	ipHdr := header.IPv6(newPacket.Bytes())
	udpLen := uint16(header.UDPMinimumSize + buffer.Len())
	ipHdr.SetPayloadLength(udpLen)
	ipHdr.SetDestinationAddress(ipHdr.SourceAddress())
	ipHdr.SetSourceAddr(destination.Addr)
	udpHdr := header.UDP(ipHdr.Payload())
	udpHdr.SetDestinationPort(udpHdr.SourcePort())
	udpHdr.SetSourcePort(destination.Port)
	udpHdr.SetLength(udpLen)
	if !w.txChecksumOffload {
		udpHdr.SetChecksum(^checksum.Checksum(udpHdr.Payload(), udpHdr.CalculateChecksum(
			header.PseudoHeaderChecksum(header.UDPProtocolNumber, ipHdr.SourceAddressSlice(), ipHdr.DestinationAddressSlice(), ipHdr.PayloadLength()),
		)))
	} else {
		udpHdr.SetChecksum(0)
	}
	if PacketOffset > 0 {
		PacketFillHeader(newPacket.ExtendHeader(PacketOffset), header.IPv6Version)
	} else {
		newPacket.Advance(-w.frontHeadroom)
	}
	return common.Error(w.tun.Write(newPacket.Bytes()))
}

type systemICMPDirectPacketWriter4 struct {
	tun           Tun
	frontHeadroom int
	source        netip.Addr
}

func (w *systemICMPDirectPacketWriter4) WritePacket(p []byte) error {
	newPacket := buf.NewSize(w.frontHeadroom + len(p))
	defer newPacket.Release()
	newPacket.Resize(w.frontHeadroom, 0)
	newPacket.Write(p)
	ipHdr := header.IPv4(newPacket.Bytes())
	ipHdr.SetDestinationAddr(w.source)
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
	if PacketOffset > 0 {
		PacketFillHeader(newPacket.ExtendHeader(PacketOffset), header.IPv4Version)
	} else {
		newPacket.Advance(-w.frontHeadroom)
	}
	return common.Error(w.tun.Write(newPacket.Bytes()))
}

type systemICMPDirectPacketWriter6 struct {
	tun           Tun
	frontHeadroom int
	source        netip.Addr
}

func (w *systemICMPDirectPacketWriter6) WritePacket(p []byte) error {
	newPacket := buf.NewSize(w.frontHeadroom + len(p))
	defer newPacket.Release()
	newPacket.Resize(w.frontHeadroom, 0)
	newPacket.Write(p)
	ipHdr := header.IPv6(newPacket.Bytes())
	ipHdr.SetDestinationAddr(w.source)
	if PacketOffset > 0 {
		PacketFillHeader(newPacket.ExtendHeader(PacketOffset), header.IPv6Version)
	} else {
		newPacket.Advance(-w.frontHeadroom)
	}
	return common.Error(w.tun.Write(newPacket.Bytes()))
}
