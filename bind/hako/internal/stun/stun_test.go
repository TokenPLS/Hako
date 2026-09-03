package stun

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestNormalizeServer(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		input     string
		expected  string
		shouldErr bool
	}{
		{name: "default", expected: DefaultServer},
		{name: "hostname", input: "stun.example", expected: "stun.example:3478"},
		{name: "hostname port", input: "stun.example:5349", expected: "stun.example:5349"},
		{name: "IPv4", input: "192.0.2.1", expected: "192.0.2.1:3478"},
		{name: "IPv6", input: "2001:db8::1", expected: "[2001:db8::1]:3478"},
		{name: "IPv6 port", input: "[2001:db8::1]:5349", expected: "[2001:db8::1]:5349"},
		{name: "scheme", input: "stun://stun.example", shouldErr: true},
		{name: "path", input: "stun.example/path", shouldErr: true},
		{name: "zero port", input: "stun.example:0", shouldErr: true},
		{name: "newline", input: "stun.example\n:3478", shouldErr: true},
		{name: "unbracketed invalid IPv6", input: "2001:db8::not-an-ip", shouldErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := NormalizeServer(test.input)
			if test.shouldErr {
				if err == nil {
					t.Fatalf("NormalizeServer(%q) = %q, want error", test.input, actual)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeServer(%q): %v", test.input, err)
			}
			if actual != test.expected {
				t.Fatalf("NormalizeServer(%q) = %q, want %q", test.input, actual, test.expected)
			}
		})
	}
}

func TestParseResponseAddresses(t *testing.T) {
	t.Parallel()
	transactionID := TransactionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	mapped := netip.MustParseAddrPort("198.51.100.9:45678")
	other := netip.MustParseAddrPort("203.0.113.7:3479")
	response, err := parseResponse(successResponse(
		transactionID,
		xorAddressAttribute(attrXORMappedAddress, transactionID, mapped),
		mappedAddressAttribute(attrOtherAddress, other),
	), transactionID)
	if err != nil {
		t.Fatal(err)
	}
	if external, ok := response.externalAddr(); !ok || external != mapped {
		t.Fatalf("external = %v, %v, want %v", external, ok, mapped)
	}
	if response.otherAddr != other {
		t.Fatalf("other = %v, want %v", response.otherAddr, other)
	}

	ipv6 := netip.MustParseAddrPort("[2001:db8::9]:45678")
	response, err = parseResponse(successResponse(
		transactionID,
		xorAddressAttribute(attrXORMappedAddress, transactionID, ipv6),
	), transactionID)
	if err != nil {
		t.Fatal(err)
	}
	if external, ok := response.externalAddr(); !ok || external != ipv6 {
		t.Fatalf("IPv6 external = %v, %v, want %v", external, ok, ipv6)
	}
}

func TestParseResponseRejectsMalformedDatagrams(t *testing.T) {
	t.Parallel()
	transactionID := TransactionID{1}
	validAddress := netip.MustParseAddrPort("198.51.100.1:1234")
	valid := successResponse(transactionID, mappedAddressAttribute(attrMappedAddress, validAddress))
	tests := map[string][]byte{
		"short":      valid[:19],
		"trailing":   append(append([]byte(nil), valid...), 0),
		"bad cookie": append([]byte(nil), valid...),
		"duplicate": successResponse(transactionID,
			mappedAddressAttribute(attrMappedAddress, validAddress),
			mappedAddressAttribute(attrMappedAddress, validAddress),
		),
		"oversize": make([]byte, maxResponseSize+1),
	}
	tests["bad cookie"][4] = 0
	for name, datagram := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseResponse(datagram, transactionID); err == nil {
				t.Fatal("expected parse error")
			}
		})
	}
}

func TestRunBindingOnly(t *testing.T) {
	t.Parallel()
	server := netip.MustParseAddrPort("192.0.2.10:3478")
	external := netip.MustParseAddrPort("198.51.100.20:4567")
	connection := newScriptedPacketConn(func(payload []byte, destination net.Addr) packetRead {
		transactionID := transactionIDFromRequest(t, payload)
		return packetRead{
			payload: successResponse(transactionID, xorAddressAttribute(attrXORMappedAddress, transactionID, external)),
			source:  net.UDPAddrFromAddrPort(server),
		}
	})
	var phases []Phase
	result, err := Run(Options{
		Server: "stun.example",
		Dial: func(context.Context, string) (net.PacketConn, netip.AddrPort, error) {
			return connection, server, nil
		},
		OnProgress: func(progress Progress) { phases = append(phases, progress.Phase) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ExternalAddr != external.String() || result.ExternalAddressFamily != AddressFamilyIPv4 {
		t.Fatalf("result = %+v", result)
	}
	if result.NATTypeSupported {
		t.Fatal("NAT type should be unsupported without OTHER-ADDRESS")
	}
	wantPhases := []Phase{PhaseBinding, PhaseBinding, PhaseDone}
	if len(phases) != len(wantPhases) {
		t.Fatalf("phases = %v, want %v", phases, wantPhases)
	}
	for index := range phases {
		if phases[index] != wantPhases[index] {
			t.Fatalf("phases = %v, want %v", phases, wantPhases)
		}
	}
}

func TestRunEndpointIndependentMappingAndFiltering(t *testing.T) {
	t.Parallel()
	server := netip.MustParseAddrPort("192.0.2.10:3478")
	other := netip.MustParseAddrPort("192.0.2.11:3479")
	external := netip.MustParseAddrPort("198.51.100.20:4567")
	connection := newScriptedPacketConn(func(payload []byte, destination net.Addr) packetRead {
		transactionID := transactionIDFromRequest(t, payload)
		destinationAddress, ok := addressPortFromNetAddr(destination)
		if !ok {
			t.Fatalf("invalid destination %v", destination)
		}
		if len(payload) > headerSize && binary.BigEndian.Uint16(payload[headerSize:headerSize+2]) == attrChangeRequest {
			return packetRead{
				payload: successResponse(transactionID, mappedAddressAttribute(attrMappedAddress, external)),
				source:  net.UDPAddrFromAddrPort(other),
			}
		}
		attributes := []stunAttribute{mappedAddressAttribute(attrMappedAddress, external)}
		if destinationAddress == server {
			attributes = append(attributes, mappedAddressAttribute(attrOtherAddress, other))
		}
		return packetRead{
			payload: successResponse(transactionID, attributes...),
			source:  net.UDPAddrFromAddrPort(destinationAddress),
		}
	})
	result, err := Run(Options{
		Server: "stun.example",
		Dial: func(context.Context, string) (net.PacketConn, netip.AddrPort, error) {
			return connection, server, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.NATMapping != NATMappingEndpointIndependent || result.NATFiltering != NATFilteringEndpointIndependent {
		t.Fatalf("result = %+v", result)
	}
	if !result.NATTypeSupported {
		t.Fatal("RFC 5780 fixture should be supported")
	}
}

func TestRunTimeoutIsBounded(t *testing.T) {
	t.Parallel()
	server := netip.MustParseAddrPort("192.0.2.10:3478")
	connection := &queuedPacketConn{reads: make(chan packetRead), closed: make(chan struct{}), wrote: make(chan struct{})}
	started := time.Now()
	_, err := Run(Options{
		Timeout: 25 * time.Millisecond,
		Dial: func(context.Context, string) (net.PacketConn, netip.AddrPort, error) {
			return connection, server, nil
		},
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Run error = %v, want deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("timeout took %v", elapsed)
	}
}

func TestRoundTripIgnoresUnexpectedSource(t *testing.T) {
	t.Parallel()
	server := netip.MustParseAddrPort("192.0.2.10:3478")
	attacker := netip.MustParseAddrPort("192.0.2.99:3478")
	external := netip.MustParseAddrPort("198.51.100.20:4567")
	transactionID := TransactionID{9, 8, 7, 6}
	connection := &queuedPacketConn{reads: make(chan packetRead, 2), closed: make(chan struct{}), wrote: make(chan struct{})}
	response := successResponse(transactionID, mappedAddressAttribute(attrMappedAddress, external))
	connection.reads <- packetRead{payload: response, source: net.UDPAddrFromAddrPort(attacker)}
	connection.reads <- packetRead{payload: response, source: net.UDPAddrFromAddrPort(server)}
	parsed, _, err := roundTrip(
		context.Background(), connection, server, []netip.AddrPort{server}, transactionID, nil, time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	if actual, ok := parsed.externalAddr(); !ok || actual != external {
		t.Fatalf("external = %v, %v", actual, ok)
	}
}

func TestRunCancellationClosesSocket(t *testing.T) {
	t.Parallel()
	server := netip.MustParseAddrPort("192.0.2.10:3478")
	connection := &queuedPacketConn{reads: make(chan packetRead), closed: make(chan struct{}), wrote: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := Run(Options{
			Context: ctx,
			Dial: func(context.Context, string) (net.PacketConn, netip.AddrPort, error) {
				return connection, server, nil
			},
		})
		result <- err
	}()
	select {
	case <-connection.wrote:
	case <-time.After(time.Second):
		t.Fatal("STUN request was not written")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not unblock Run")
	}
	select {
	case <-connection.closed:
	default:
		t.Fatal("cancellation did not close packet connection")
	}
}

func TestConcurrentCancellation(t *testing.T) {
	server := netip.MustParseAddrPort("192.0.2.10:3478")
	for iteration := 0; iteration < 32; iteration++ {
		connection := &queuedPacketConn{reads: make(chan packetRead), closed: make(chan struct{}), wrote: make(chan struct{})}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = Run(Options{
				Context: ctx,
				Dial: func(context.Context, string) (net.PacketConn, netip.AddrPort, error) {
					return connection, server, nil
				},
			})
		}()
		<-connection.wrote
		var waitGroup sync.WaitGroup
		for caller := 0; caller < 8; caller++ {
			waitGroup.Add(1)
			go func() { defer waitGroup.Done(); cancel() }()
		}
		waitGroup.Wait()
		cancel() // Make context ownership explicit after the concurrent idempotency exercise.
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("concurrent cancellation did not finish")
		}
	}
}

func FuzzParseResponse(f *testing.F) {
	transactionID := TransactionID{1, 2, 3}
	f.Add(successResponse(
		transactionID,
		mappedAddressAttribute(attrMappedAddress, netip.MustParseAddrPort("198.51.100.1:1234")),
	))
	f.Add([]byte{0, 1, 2, 3})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseResponse(data, transactionID)
	})
}

type packetRead struct {
	payload []byte
	source  net.Addr
	err     error
}

type queuedPacketConn struct {
	reads     chan packetRead
	closed    chan struct{}
	closeOnce sync.Once
	wrote     chan struct{}
	writeOnce sync.Once
}

func (c *queuedPacketConn) ensure() {
	if c.wrote == nil {
		c.wrote = make(chan struct{})
	}
}

func (c *queuedPacketConn) ReadFrom(payload []byte) (int, net.Addr, error) {
	c.ensure()
	select {
	case <-c.closed:
		return 0, nil, net.ErrClosed
	case read := <-c.reads:
		copy(payload, read.payload)
		return len(read.payload), read.source, read.err
	}
}

func (c *queuedPacketConn) WriteTo(payload []byte, address net.Addr) (int, error) {
	c.ensure()
	c.writeOnce.Do(func() { close(c.wrote) })
	return len(payload), nil
}

func (c *queuedPacketConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (*queuedPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*queuedPacketConn) SetDeadline(time.Time) error      { return nil }
func (*queuedPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*queuedPacketConn) SetWriteDeadline(time.Time) error { return nil }

type scriptedPacketConn struct {
	*queuedPacketConn
	onWrite func([]byte, net.Addr) packetRead
}

func newScriptedPacketConn(onWrite func([]byte, net.Addr) packetRead) *scriptedPacketConn {
	return &scriptedPacketConn{
		queuedPacketConn: &queuedPacketConn{reads: make(chan packetRead, 16), closed: make(chan struct{}), wrote: make(chan struct{})},
		onWrite:          onWrite,
	}
}

func (c *scriptedPacketConn) WriteTo(payload []byte, address net.Addr) (int, error) {
	c.writeOnce.Do(func() { close(c.wrote) })
	copyPayload := append([]byte(nil), payload...)
	c.reads <- c.onWrite(copyPayload, address)
	return len(payload), nil
}

func transactionIDFromRequest(t *testing.T, request []byte) TransactionID {
	t.Helper()
	if len(request) < headerSize || binary.BigEndian.Uint16(request[0:2]) != bindingRequest {
		t.Fatalf("invalid binding request %x", request)
	}
	var transactionID TransactionID
	copy(transactionID[:], request[8:20])
	return transactionID
}

func successResponse(transactionID TransactionID, attributes ...stunAttribute) []byte {
	attributeLength := 0
	for _, attribute := range attributes {
		attributeLength += 4 + len(attribute.value) + paddingLength(len(attribute.value))
	}
	response := make([]byte, headerSize+attributeLength)
	binary.BigEndian.PutUint16(response[0:2], bindingSuccessResponse)
	binary.BigEndian.PutUint16(response[2:4], uint16(attributeLength))
	binary.BigEndian.PutUint32(response[4:8], magicCookie)
	copy(response[8:20], transactionID[:])
	offset := headerSize
	for _, attribute := range attributes {
		binary.BigEndian.PutUint16(response[offset:offset+2], attribute.typ)
		binary.BigEndian.PutUint16(response[offset+2:offset+4], uint16(len(attribute.value)))
		copy(response[offset+4:], attribute.value)
		offset += 4 + len(attribute.value) + paddingLength(len(attribute.value))
	}
	return response
}

func mappedAddressAttribute(attributeType uint16, address netip.AddrPort) stunAttribute {
	addressBytes := address.Addr().AsSlice()
	family := familyIPv6
	if address.Addr().Is4() {
		family = familyIPv4
	}
	value := make([]byte, 4+len(addressBytes))
	value[1] = family
	binary.BigEndian.PutUint16(value[2:4], address.Port())
	copy(value[4:], addressBytes)
	return stunAttribute{typ: attributeType, value: value}
}

func xorAddressAttribute(attributeType uint16, transactionID TransactionID, address netip.AddrPort) stunAttribute {
	attribute := mappedAddressAttribute(attributeType, address)
	binary.BigEndian.PutUint16(attribute.value[2:4], address.Port()^uint16(magicCookie>>16))
	var key [16]byte
	binary.BigEndian.PutUint32(key[0:4], magicCookie)
	copy(key[4:], transactionID[:])
	for index := 4; index < len(attribute.value); index++ {
		attribute.value[index] ^= key[index-4]
	}
	return attribute
}
