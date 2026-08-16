package dialer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"testing"
)

func TestAddressTransformRunsBeforePhysicalSocketCreation(t *testing.T) {
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port

	original := DefaultAddressTransform
	DefaultAddressTransform = func(network string, destination netip.Addr) (netip.Addr, error) {
		if network != "tcp4" || destination.String() != "127.0.0.1" {
			t.Fatalf("transform input = %s %s", network, destination)
		}
		return netip.IPv6Loopback(), nil
	}
	t.Cleanup(func() { DefaultAddressTransform = original })

	accepted := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			_ = conn.Close()
		}
		accepted <- acceptErr
	}()
	conn, err := DialContext(
		context.Background(),
		"tcp4",
		net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
	)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}
}

func TestAddressTransformErrorFailsBeforeDial(t *testing.T) {
	want := errors.New("injected transform failure")
	original := DefaultAddressTransform
	DefaultAddressTransform = func(string, netip.Addr) (netip.Addr, error) {
		return netip.Addr{}, want
	}
	t.Cleanup(func() { DefaultAddressTransform = original })

	_, err := DialContext(context.Background(), "tcp", "192.0.2.1:443")
	if !errors.Is(err, want) {
		t.Fatalf("dial error = %v, want %v", err, want)
	}
}
