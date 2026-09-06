package hako

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/adapter"
	C "github.com/TokenPLS/Hako/constant"
)

func TestControlledRejectTCPFailsClosed(t *testing.T) {
	targetReached := make(chan struct{}, 1)
	target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		targetReached <- struct{}{}
		writer.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(target.Close)

	proxy, err := adapter.ParseProxy(map[string]any{
		"name": "controlled-reject-tcp",
		"type": "reject",
	})
	if err != nil {
		t.Fatalf("ParseProxy() error = %v", err)
	}
	t.Cleanup(func() { _ = proxy.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	delay, err := proxy.URLTest(ctx, target.URL, nil)
	if err == nil {
		t.Fatal("reject URLTest() unexpectedly succeeded")
	}
	if delay != 0 {
		t.Fatalf("reject URLTest() delay = %d, want failure sentinel 0", delay)
	}
	select {
	case <-targetReached:
		t.Fatal("reject leaked a TCP request to the target")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestControlledRejectUDPFailsClosed(t *testing.T) {
	target, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP() error = %v", err)
	}
	t.Cleanup(func() { _ = target.Close() })

	proxy, err := adapter.ParseProxy(map[string]any{
		"name": "controlled-reject-udp",
		"type": "reject",
	})
	if err != nil {
		t.Fatalf("ParseProxy() error = %v", err)
	}
	t.Cleanup(func() { _ = proxy.Close() })

	targetAddress := target.LocalAddr().(*net.UDPAddr)
	targetAddrPort := targetAddress.AddrPort()
	metadata := &C.Metadata{
		NetWork: C.UDP,
		Type:    C.TUN,
		DstIP:   targetAddrPort.Addr(),
		DstPort: targetAddrPort.Port(),
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	packetConnection, err := proxy.ListenPacketContext(ctx, metadata)
	if err != nil {
		t.Fatalf("ListenPacketContext() error = %v", err)
	}
	defer packetConnection.Close()

	payload := []byte("must-not-leak")
	if n, err := packetConnection.WriteTo(payload, targetAddress); err != nil || n != len(payload) {
		t.Fatalf("reject WriteTo() = (%d, %v), want consumed payload", n, err)
	}
	buffer := make([]byte, 64)
	if n, source, err := packetConnection.ReadFrom(buffer); !errors.Is(err, io.EOF) || n != 0 || source != nil {
		t.Fatalf("reject ReadFrom() = (%d, %v, %v), want (0, nil, EOF)", n, source, err)
	}

	if err := target.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("target SetReadDeadline() error = %v", err)
	}
	if n, source, err := target.ReadFromUDP(buffer); err == nil {
		t.Fatalf("reject leaked %d UDP bytes from %v to the target", n, source)
	} else if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("target ReadFromUDP() error = %v, want deadline", err)
	}
}
