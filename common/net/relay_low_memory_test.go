//go:build with_low_memory

package net

import (
	"io"
	stdnet "net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/sing/common/buf"
)

const expectedLowMemoryRelayBufferSize = 2 * 1024

func TestRelayUsesBoundedCopyBuffers(t *testing.T) {
	left := &bufferRecordingConn{}
	right := &bufferRecordingConn{}

	Relay(left, right)

	for name, conn := range map[string]*bufferRecordingConn{
		"left":  left,
		"right": right,
	} {
		if got := conn.maximumReadBufferCapacity(); got != expectedLowMemoryRelayBufferSize {
			t.Errorf("%s relay read buffer capacity = %d, want %d", name, got, expectedLowMemoryRelayBufferSize)
		}
	}
}

func TestRelayBoundsReplaceableHandshakeBuffer(t *testing.T) {
	source := &relayReplaceableReader{
		handshake: []byte("handshake-"),
		upstream:  strings.NewReader("payload"),
	}
	if _, err := relayCopy(io.Discard, source); err != nil {
		t.Fatalf("relayCopy() error = %v", err)
	}
	if got := source.maxReadCapacity; got != expectedLowMemoryRelayBufferSize {
		t.Fatalf("replaceable handshake buffer capacity = %d, want %d", got, expectedLowMemoryRelayBufferSize)
	}
}

type bufferRecordingConn struct {
	mu             sync.Mutex
	readCapacities []int
}

func (c *bufferRecordingConn) Read(p []byte) (int, error) {
	c.recordReadCapacity(len(p))
	return 0, io.EOF
}

func (c *bufferRecordingConn) ReadBuffer(buffer *buf.Buffer) error {
	c.recordReadCapacity(buffer.Cap())
	return io.EOF
}

func (*bufferRecordingConn) Write(p []byte) (int, error) {
	return len(p), nil
}

func (*bufferRecordingConn) WriteBuffer(buffer *buf.Buffer) error {
	buffer.Release()
	return nil
}

func (*bufferRecordingConn) Close() error                     { return nil }
func (*bufferRecordingConn) LocalAddr() stdnet.Addr           { return testRelayAddr("local") }
func (*bufferRecordingConn) RemoteAddr() stdnet.Addr          { return testRelayAddr("remote") }
func (*bufferRecordingConn) SetDeadline(time.Time) error      { return nil }
func (*bufferRecordingConn) SetReadDeadline(time.Time) error  { return nil }
func (*bufferRecordingConn) SetWriteDeadline(time.Time) error { return nil }

func (c *bufferRecordingConn) recordReadCapacity(capacity int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readCapacities = append(c.readCapacities, capacity)
}

func (c *bufferRecordingConn) maximumReadBufferCapacity() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	var maximum int
	for _, capacity := range c.readCapacities {
		if capacity > maximum {
			maximum = capacity
		}
	}
	return maximum
}

type testRelayAddr string

func (a testRelayAddr) Network() string { return string(a) }
func (a testRelayAddr) String() string  { return string(a) }
