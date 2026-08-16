package stun

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	DefaultServer = "stun.voipgate.com:3478"
	DefaultPort   = uint16(3478)

	magicCookie = uint32(0x2112A442)
	headerSize  = 20

	bindingRequest         = uint16(0x0001)
	bindingSuccessResponse = uint16(0x0101)
	bindingErrorResponse   = uint16(0x0111)

	attrMappedAddress    = uint16(0x0001)
	attrChangeRequest    = uint16(0x0003)
	attrErrorCode        = uint16(0x0009)
	attrXORMappedAddress = uint16(0x0020)
	attrOtherAddress     = uint16(0x802c)

	familyIPv4 = byte(0x01)
	familyIPv6 = byte(0x02)

	changeIP   = byte(0x04)
	changePort = byte(0x02)

	maxResponseSize = 2048
	maxServerLength = 320
	defaultRTO      = 500 * time.Millisecond
	minimumRTO      = 250 * time.Millisecond
	maximumRTO      = 2 * time.Second
	maxRetransmits  = 2
	defaultTimeout  = 12 * time.Second
)

type Phase int32

const (
	PhaseBinding Phase = iota
	PhaseNATMapping
	PhaseNATFiltering
	PhaseDone
)

type AddressFamily int32

const (
	AddressFamilyUnknown AddressFamily = iota
	AddressFamilyIPv4
	AddressFamilyIPv6
)

type NATMapping int32

const (
	NATMappingUnknown NATMapping = iota
	NATMappingReserved
	NATMappingEndpointIndependent
	NATMappingAddressDependent
	NATMappingAddressAndPortDependent
)

func (m NATMapping) String() string {
	switch m {
	case NATMappingEndpointIndependent:
		return "Endpoint Independent"
	case NATMappingAddressDependent:
		return "Address Dependent"
	case NATMappingAddressAndPortDependent:
		return "Address and Port Dependent"
	default:
		return "Unknown"
	}
}

type NATFiltering int32

const (
	NATFilteringUnknown NATFiltering = iota
	NATFilteringEndpointIndependent
	NATFilteringAddressDependent
	NATFilteringAddressAndPortDependent
)

func (f NATFiltering) String() string {
	switch f {
	case NATFilteringEndpointIndependent:
		return "Endpoint Independent"
	case NATFilteringAddressDependent:
		return "Address Dependent"
	case NATFilteringAddressAndPortDependent:
		return "Address and Port Dependent"
	default:
		return "Unknown"
	}
}

type TransactionID [12]byte

// DialFunc creates one UDP socket routed through the caller-selected data
// plane and returns the exact logical address used for the first request. The
// socket must support WriteTo for RFC 5780's alternate server addresses.
type DialFunc func(ctx context.Context, endpoint string) (net.PacketConn, netip.AddrPort, error)

type Options struct {
	Server     string
	Context    context.Context
	Timeout    time.Duration
	Dial       DialFunc
	OnProgress func(Progress)
}

type Progress struct {
	Phase                 Phase
	ExternalAddr          string
	ExternalAddressFamily AddressFamily
	LatencyMs             int32
	NATMapping            NATMapping
	NATFiltering          NATFiltering
}

type Result struct {
	ExternalAddr          string
	ExternalAddressFamily AddressFamily
	LatencyMs             int32
	NATMapping            NATMapping
	NATFiltering          NATFiltering
	NATTypeSupported      bool
}

type parsedResponse struct {
	xorMappedAddr netip.AddrPort
	mappedAddr    netip.AddrPort
	otherAddr     netip.AddrPort
}

func (r *parsedResponse) externalAddr() (netip.AddrPort, bool) {
	if r.xorMappedAddr.IsValid() {
		return r.xorMappedAddr, true
	}
	if r.mappedAddr.IsValid() {
		return r.mappedAddr, true
	}
	return netip.AddrPort{}, false
}

type stunAttribute struct {
	typ   uint16
	value []byte
}

func newTransactionID() (TransactionID, error) {
	var id TransactionID
	if _, err := rand.Read(id[:]); err != nil {
		return id, fmt.Errorf("generate transaction ID: %w", err)
	}
	return id, nil
}

func buildBindingRequest(txID TransactionID, attrs ...stunAttribute) []byte {
	attributeLength := 0
	for _, attribute := range attrs {
		attributeLength += 4 + len(attribute.value) + paddingLength(len(attribute.value))
	}
	message := make([]byte, headerSize+attributeLength)
	binary.BigEndian.PutUint16(message[0:2], bindingRequest)
	binary.BigEndian.PutUint16(message[2:4], uint16(attributeLength))
	binary.BigEndian.PutUint32(message[4:8], magicCookie)
	copy(message[8:20], txID[:])
	offset := headerSize
	for _, attribute := range attrs {
		binary.BigEndian.PutUint16(message[offset:offset+2], attribute.typ)
		binary.BigEndian.PutUint16(message[offset+2:offset+4], uint16(len(attribute.value)))
		copy(message[offset+4:], attribute.value)
		offset += 4 + len(attribute.value) + paddingLength(len(attribute.value))
	}
	return message
}

func changeRequestAttribute(flags byte) stunAttribute {
	return stunAttribute{typ: attrChangeRequest, value: []byte{0, 0, 0, flags}}
}

func parseResponse(data []byte, expected TransactionID) (*parsedResponse, error) {
	if len(data) < headerSize {
		return nil, errors.New("response too short")
	}
	if len(data) > maxResponseSize {
		return nil, fmt.Errorf("response exceeds %d bytes", maxResponseSize)
	}
	messageType := binary.BigEndian.Uint16(data[0:2])
	if messageType&0xc000 != 0 {
		return nil, errors.New("invalid STUN message type bits")
	}
	if binary.BigEndian.Uint32(data[4:8]) != magicCookie {
		return nil, errors.New("invalid magic cookie")
	}
	var transactionID TransactionID
	copy(transactionID[:], data[8:20])
	if transactionID != expected {
		return nil, errors.New("transaction ID mismatch")
	}
	messageLength := int(binary.BigEndian.Uint16(data[2:4]))
	if messageLength%4 != 0 {
		return nil, errors.New("message length is not 32-bit aligned")
	}
	if headerSize+messageLength != len(data) {
		return nil, errors.New("message length does not match datagram")
	}
	attributeData := data[headerSize:]
	if messageType == bindingErrorResponse {
		return nil, parseErrorResponse(attributeData)
	}
	if messageType != bindingSuccessResponse {
		return nil, fmt.Errorf("unexpected message type 0x%04x", messageType)
	}

	response := &parsedResponse{}
	seen := make(map[uint16]bool, 3)
	for offset := 0; offset < len(attributeData); {
		if len(attributeData)-offset < 4 {
			return nil, errors.New("truncated attribute header")
		}
		attributeType := binary.BigEndian.Uint16(attributeData[offset : offset+2])
		attributeLength := int(binary.BigEndian.Uint16(attributeData[offset+2 : offset+4]))
		paddedLength := attributeLength + paddingLength(attributeLength)
		if attributeLength > len(attributeData)-offset-4 || paddedLength > len(attributeData)-offset-4 {
			return nil, errors.New("attribute length exceeds message")
		}
		attributeValue := attributeData[offset+4 : offset+4+attributeLength]
		switch attributeType {
		case attrXORMappedAddress, attrMappedAddress, attrOtherAddress:
			if seen[attributeType] {
				return nil, fmt.Errorf("duplicate address attribute 0x%04x", attributeType)
			}
			seen[attributeType] = true
			var address netip.AddrPort
			var err error
			if attributeType == attrXORMappedAddress {
				address, err = parseXORMappedAddress(attributeValue, transactionID)
			} else {
				address, err = parseMappedAddress(attributeValue)
			}
			if err != nil {
				return nil, err
			}
			switch attributeType {
			case attrXORMappedAddress:
				response.xorMappedAddr = address
			case attrMappedAddress:
				response.mappedAddr = address
			case attrOtherAddress:
				response.otherAddr = address
			}
		}
		offset += 4 + paddedLength
	}
	return response, nil
}

func parseErrorResponse(data []byte) error {
	for offset := 0; offset+4 <= len(data); {
		attributeType := binary.BigEndian.Uint16(data[offset : offset+2])
		attributeLength := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		paddedLength := attributeLength + paddingLength(attributeLength)
		if attributeLength > len(data)-offset-4 || paddedLength > len(data)-offset-4 {
			return errors.New("malformed STUN error response")
		}
		if attributeType == attrErrorCode {
			if attributeLength < 4 {
				return errors.New("malformed STUN error code")
			}
			value := data[offset+4 : offset+4+attributeLength]
			code := int(value[2]&0x07)*100 + int(value[3])
			reason := strings.TrimSpace(string(value[4:]))
			if len(reason) > 128 {
				reason = reason[:128]
			}
			if reason == "" {
				return fmt.Errorf("STUN error %d", code)
			}
			return fmt.Errorf("STUN error %d: %s", code, reason)
		}
		offset += 4 + paddedLength
	}
	return errors.New("STUN error response")
}

func parseXORMappedAddress(data []byte, transactionID TransactionID) (netip.AddrPort, error) {
	if len(data) < 4 || data[0] != 0 {
		return netip.AddrPort{}, errors.New("invalid XOR-MAPPED-ADDRESS header")
	}
	port := binary.BigEndian.Uint16(data[2:4]) ^ uint16(magicCookie>>16)
	switch data[1] {
	case familyIPv4:
		if len(data) != 8 {
			return netip.AddrPort{}, errors.New("invalid XOR-MAPPED-ADDRESS IPv4 length")
		}
		var addressBytes [4]byte
		binary.BigEndian.PutUint32(addressBytes[:], binary.BigEndian.Uint32(data[4:8])^magicCookie)
		return validatedAddressPort(netip.AddrFrom4(addressBytes), port)
	case familyIPv6:
		if len(data) != 20 {
			return netip.AddrPort{}, errors.New("invalid XOR-MAPPED-ADDRESS IPv6 length")
		}
		var addressBytes, key [16]byte
		binary.BigEndian.PutUint32(key[0:4], magicCookie)
		copy(key[4:], transactionID[:])
		for index := range addressBytes {
			addressBytes[index] = data[4+index] ^ key[index]
		}
		return validatedAddressPort(netip.AddrFrom16(addressBytes), port)
	default:
		return netip.AddrPort{}, fmt.Errorf("unknown address family %d", data[1])
	}
}

func parseMappedAddress(data []byte) (netip.AddrPort, error) {
	if len(data) < 4 || data[0] != 0 {
		return netip.AddrPort{}, errors.New("invalid MAPPED-ADDRESS header")
	}
	port := binary.BigEndian.Uint16(data[2:4])
	switch data[1] {
	case familyIPv4:
		if len(data) != 8 {
			return netip.AddrPort{}, errors.New("invalid MAPPED-ADDRESS IPv4 length")
		}
		return validatedAddressPort(netip.AddrFrom4([4]byte(data[4:8])), port)
	case familyIPv6:
		if len(data) != 20 {
			return netip.AddrPort{}, errors.New("invalid MAPPED-ADDRESS IPv6 length")
		}
		var addressBytes [16]byte
		copy(addressBytes[:], data[4:20])
		return validatedAddressPort(netip.AddrFrom16(addressBytes), port)
	default:
		return netip.AddrPort{}, fmt.Errorf("unknown address family %d", data[1])
	}
}

func validatedAddressPort(address netip.Addr, port uint16) (netip.AddrPort, error) {
	address = address.Unmap()
	if !address.IsValid() || address.IsUnspecified() || address.IsMulticast() || port == 0 {
		return netip.AddrPort{}, errors.New("invalid STUN address or port")
	}
	return netip.AddrPortFrom(address, port), nil
}

func roundTrip(
	ctx context.Context,
	connection net.PacketConn,
	destination netip.AddrPort,
	expectedSources []netip.AddrPort,
	transactionID TransactionID,
	attributes []stunAttribute,
	rto time.Duration,
) (*parsedResponse, time.Duration, error) {
	request := buildBindingRequest(transactionID, attributes...)
	currentRTO := min(max(rto, minimumRTO), maximumRTO)
	retransmissions := 0
	sendTime := time.Now()
	if _, err := connection.WriteTo(request, net.UDPAddrFromAddrPort(destination)); err != nil {
		if contextError := ctx.Err(); contextError != nil {
			return nil, 0, contextError
		}
		return nil, 0, fmt.Errorf("send STUN request: %w", err)
	}
	buffer := make([]byte, maxResponseSize+1)
	for {
		deadline := sendTime.Add(currentRTO)
		if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
			deadline = contextDeadline
		}
		if err := connection.SetReadDeadline(deadline); err != nil {
			if contextError := ctx.Err(); contextError != nil {
				return nil, 0, contextError
			}
			return nil, 0, fmt.Errorf("set STUN read deadline: %w", err)
		}
		count, source, err := connection.ReadFrom(buffer)
		if err != nil {
			if contextError := ctx.Err(); contextError != nil {
				return nil, 0, contextError
			}
			if isTimeout(err) && retransmissions < maxRetransmits {
				retransmissions++
				currentRTO = min(currentRTO*2, maximumRTO)
				sendTime = time.Now()
				if _, writeError := connection.WriteTo(request, net.UDPAddrFromAddrPort(destination)); writeError != nil {
					if contextError := ctx.Err(); contextError != nil {
						return nil, 0, contextError
					}
					return nil, 0, fmt.Errorf("retransmit STUN request: %w", writeError)
				}
				continue
			}
			return nil, 0, fmt.Errorf("read STUN response: %w", err)
		}
		if count > maxResponseSize {
			return nil, 0, fmt.Errorf("response exceeds %d bytes", maxResponseSize)
		}
		sourceAddress, ok := addressPortFromNetAddr(source)
		if !ok || !containsAddress(expectedSources, sourceAddress) {
			continue
		}
		if count < headerSize || buffer[0]&0xc0 != 0 || binary.BigEndian.Uint32(buffer[4:8]) != magicCookie {
			continue
		}
		var receivedTransactionID TransactionID
		copy(receivedTransactionID[:], buffer[8:20])
		if receivedTransactionID != transactionID {
			continue
		}
		response, parseError := parseResponse(buffer[:count], transactionID)
		if parseError != nil {
			return nil, 0, parseError
		}
		return response, time.Since(sendTime), nil
	}
}

func Run(options Options) (*Result, error) {
	parentContext := options.Context
	if parentContext == nil {
		parentContext = context.Background()
	}
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	if timeout > defaultTimeout {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(parentContext, timeout)
	defer cancel()
	endpoint, err := NormalizeServer(options.Server)
	if err != nil {
		return nil, err
	}
	dial := options.Dial
	if dial == nil {
		dial = SystemDial
	}
	connection, serverAddress, err := dial(ctx, endpoint)
	if err != nil {
		return nil, fmt.Errorf("create STUN UDP socket: %w", err)
	}
	var closeOnce sync.Once
	closeConnection := func() { closeOnce.Do(func() { _ = connection.Close() }) }
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			closeConnection()
		case <-done:
		}
	}()
	defer close(done)
	defer closeConnection()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	reportProgress := options.OnProgress
	if reportProgress == nil {
		reportProgress = func(Progress) {}
	}

	reportProgress(Progress{Phase: PhaseBinding})
	transactionID, err := newTransactionID()
	if err != nil {
		return nil, err
	}
	response, latency, err := roundTrip(
		ctx, connection, serverAddress, []netip.AddrPort{serverAddress},
		transactionID, nil, defaultRTO,
	)
	if err != nil {
		return nil, fmt.Errorf("binding request: %w", err)
	}
	externalAddress, ok := response.externalAddr()
	if !ok {
		return nil, errors.New("binding response has no mapped address")
	}
	result := &Result{
		ExternalAddr:          externalAddress.String(),
		ExternalAddressFamily: addressFamily(externalAddress.Addr()),
		LatencyMs:             int32(latency.Milliseconds()),
	}
	reportProgress(progressFromResult(PhaseBinding, result))
	if !response.otherAddr.IsValid() {
		reportProgress(progressFromResult(PhaseDone, result))
		return result, nil
	}
	result.NATTypeSupported = true
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	rto := min(max(3*latency, minimumRTO), maximumRTO)
	reportProgress(progressFromResult(PhaseNATMapping, result))
	result.NATMapping, err = detectNATMapping(
		ctx, connection, serverAddress, externalAddress, response.otherAddr, rto,
	)
	if err != nil {
		return nil, err
	}
	reportProgress(progressFromResult(PhaseNATMapping, result))
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	reportProgress(progressFromResult(PhaseNATFiltering, result))
	result.NATFiltering, err = detectNATFiltering(
		ctx, connection, serverAddress, response.otherAddr, rto,
	)
	if err != nil {
		return nil, err
	}
	reportProgress(progressFromResult(PhaseDone, result))
	return result, nil
}

func detectNATMapping(
	ctx context.Context,
	connection net.PacketConn,
	serverAddress netip.AddrPort,
	externalAddress netip.AddrPort,
	otherAddress netip.AddrPort,
	rto time.Duration,
) (NATMapping, error) {
	testTwoAddress := netip.AddrPortFrom(otherAddress.Addr(), serverAddress.Port())
	transactionID, err := newTransactionID()
	if err != nil {
		return NATMappingUnknown, err
	}
	response, _, err := roundTrip(
		ctx, connection, testTwoAddress, []netip.AddrPort{testTwoAddress}, transactionID, nil, rto,
	)
	if err != nil {
		if ctx.Err() != nil {
			return NATMappingUnknown, ctx.Err()
		}
		if isTimeout(err) {
			return NATMappingUnknown, nil
		}
		return NATMappingUnknown, fmt.Errorf("NAT mapping test II: %w", err)
	}
	externalAddressTwo, ok := response.externalAddr()
	if !ok {
		return NATMappingUnknown, errors.New("NAT mapping test II has no mapped address")
	}
	if externalAddress == externalAddressTwo {
		return NATMappingEndpointIndependent, nil
	}
	transactionID, err = newTransactionID()
	if err != nil {
		return NATMappingUnknown, err
	}
	response, _, err = roundTrip(
		ctx, connection, otherAddress, []netip.AddrPort{otherAddress}, transactionID, nil, rto,
	)
	if err != nil {
		if ctx.Err() != nil {
			return NATMappingUnknown, ctx.Err()
		}
		if isTimeout(err) {
			return NATMappingUnknown, nil
		}
		return NATMappingUnknown, fmt.Errorf("NAT mapping test III: %w", err)
	}
	externalAddressThree, ok := response.externalAddr()
	if !ok {
		return NATMappingUnknown, errors.New("NAT mapping test III has no mapped address")
	}
	if externalAddressTwo == externalAddressThree {
		return NATMappingAddressDependent, nil
	}
	return NATMappingAddressAndPortDependent, nil
}

func detectNATFiltering(
	ctx context.Context,
	connection net.PacketConn,
	serverAddress netip.AddrPort,
	otherAddress netip.AddrPort,
	rto time.Duration,
) (NATFiltering, error) {
	transactionID, err := newTransactionID()
	if err != nil {
		return NATFilteringUnknown, err
	}
	_, _, err = roundTrip(
		ctx, connection, serverAddress, []netip.AddrPort{otherAddress}, transactionID,
		[]stunAttribute{changeRequestAttribute(changeIP | changePort)}, rto,
	)
	if err == nil {
		return NATFilteringEndpointIndependent, nil
	}
	if ctx.Err() != nil {
		return NATFilteringUnknown, ctx.Err()
	}
	if !isTimeout(err) {
		return NATFilteringUnknown, fmt.Errorf("NAT filtering test II: %w", err)
	}

	transactionID, err = newTransactionID()
	if err != nil {
		return NATFilteringUnknown, err
	}
	alternatePortAddress := netip.AddrPortFrom(serverAddress.Addr(), otherAddress.Port())
	_, _, err = roundTrip(
		ctx, connection, serverAddress, []netip.AddrPort{alternatePortAddress}, transactionID,
		[]stunAttribute{changeRequestAttribute(changePort)}, rto,
	)
	if err == nil {
		return NATFilteringAddressDependent, nil
	}
	if ctx.Err() != nil {
		return NATFilteringUnknown, ctx.Err()
	}
	if !isTimeout(err) {
		return NATFilteringUnknown, fmt.Errorf("NAT filtering test III: %w", err)
	}
	return NATFilteringAddressAndPortDependent, nil
}

func progressFromResult(phase Phase, result *Result) Progress {
	return Progress{
		Phase:                 phase,
		ExternalAddr:          result.ExternalAddr,
		ExternalAddressFamily: result.ExternalAddressFamily,
		LatencyMs:             result.LatencyMs,
		NATMapping:            result.NATMapping,
		NATFiltering:          result.NATFiltering,
	}
}

func addressFamily(address netip.Addr) AddressFamily {
	if address.Is4() || address.Is4In6() {
		return AddressFamilyIPv4
	}
	if address.Is6() {
		return AddressFamilyIPv6
	}
	return AddressFamilyUnknown
}

func addressPortFromNetAddr(address net.Addr) (netip.AddrPort, bool) {
	if address == nil {
		return netip.AddrPort{}, false
	}
	if value, ok := address.(interface{ AddrPort() netip.AddrPort }); ok {
		addressPort := value.AddrPort()
		if addressPort.IsValid() {
			return netip.AddrPortFrom(addressPort.Addr().Unmap(), addressPort.Port()), true
		}
	}
	host, portText, err := net.SplitHostPort(address.String())
	if err != nil {
		return netip.AddrPort{}, false
	}
	ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return netip.AddrPort{}, false
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ip.Unmap(), uint16(port)), true
}

func containsAddress(addresses []netip.AddrPort, candidate netip.AddrPort) bool {
	for _, address := range addresses {
		if netip.AddrPortFrom(address.Addr().Unmap(), address.Port()) == candidate {
			return true
		}
	}
	return false
}

func isTimeout(err error) bool {
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Timeout()
}

func paddingLength(length int) int {
	return (4 - length%4) % 4
}

// NormalizeServer accepts host, host:port, IPv4 and bracketed or bare IPv6.
// Schemes, paths, control characters and zero ports are rejected before any
// resolver or socket work occurs.
func NormalizeServer(raw string) (string, error) {
	server := strings.TrimSpace(raw)
	if server == "" {
		server = DefaultServer
	}
	if len(server) > maxServerLength {
		return "", fmt.Errorf("STUN server exceeds %d bytes", maxServerLength)
	}
	if strings.ContainsAny(server, "\x00\r\n\t /\\?#%") || strings.Contains(server, "://") {
		return "", errors.New("STUN server must be a host with an optional UDP port")
	}
	if address, err := netip.ParseAddr(strings.Trim(server, "[]")); err == nil {
		return net.JoinHostPort(address.String(), strconv.Itoa(int(DefaultPort))), nil
	}
	host, portText, err := net.SplitHostPort(server)
	if err != nil {
		if strings.Contains(server, ":") {
			return "", errors.New("invalid STUN server address")
		}
		host = server
		portText = strconv.Itoa(int(DefaultPort))
	}
	host = strings.Trim(host, "[]")
	if host == "" || host == "." || len(host) > 253 || strings.HasPrefix(host, ".") {
		return "", errors.New("invalid STUN server host")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return "", errors.New("invalid STUN server port")
	}
	return net.JoinHostPort(host, strconv.FormatUint(port, 10)), nil
}

// SystemDial is used by the standalone app-process test. When a Packet Tunnel
// is active, iOS routes this ordinary UDP socket through that tunnel.
func SystemDial(ctx context.Context, endpoint string) (net.PacketConn, netip.AddrPort, error) {
	host, portText, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return nil, netip.AddrPort{}, errors.New("invalid STUN server port")
	}
	address, parseError := netip.ParseAddr(strings.Trim(host, "[]"))
	if parseError != nil {
		addresses, lookupError := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if lookupError != nil {
			return nil, netip.AddrPort{}, lookupError
		}
		for _, candidate := range addresses {
			if candidate.IsValid() && !candidate.IsUnspecified() && !candidate.IsMulticast() {
				address = candidate
				break
			}
		}
	}
	if !address.IsValid() {
		return nil, netip.AddrPort{}, errors.New("STUN server did not resolve to a usable address")
	}
	addressPort := netip.AddrPortFrom(address.Unmap(), uint16(port))
	var listenConfig net.ListenConfig
	connection, err := listenConfig.ListenPacket(ctx, "udp", "")
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	return connection, addressPort, nil
}
