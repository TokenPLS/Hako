package hako

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/adapter"
	C "github.com/TokenPLS/Hako/constant"
)

func TestControlledNAT64OuterTransportInterop(t *testing.T) {
	tcpListener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 TCP loopback is unavailable: %v", err)
	}
	tcpTarget := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodHead {
			t.Errorf("target method = %s, want HEAD", request.Method)
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	tcpTarget.Listener = tcpListener
	tcpTarget.Start()
	t.Cleanup(tcpTarget.Close)

	udpTarget, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("IPv6 UDP loopback is unavailable: %v", err)
	}
	t.Cleanup(func() { _ = udpTarget.Close() })
	go serveUDPEcho(udpTarget)

	setupNAT64PolicyTest(t)
	// The synthesized address has to be a listener this test actually started,
	// which means loopback -- a shape production refuses on purpose (a network
	// that can name ::1 as a translation redirects egress at this device's own
	// services). The seam is opened only here.
	allowLoopbackNAT64Synthesis = true
	t.Cleanup(func() { allowLoopbackNAT64Synthesis = false })
	setPhysicalNetworkCapabilities(false, true)
	logicalAddress := netip.MustParseAddr("192.0.2.64")
	var tcpSynthesis atomic.Int32
	var udpSynthesis atomic.Int32
	synthesizeIPv4Literal = func(network string, destination netip.Addr) (netip.Addr, error) {
		if destination != logicalAddress {
			return netip.Addr{}, fmt.Errorf("unexpected logical destination %s", destination)
		}
		switch {
		case strings.HasPrefix(network, "tcp"):
			tcpSynthesis.Add(1)
		case strings.HasPrefix(network, "udp"):
			udpSynthesis.Add(1)
		default:
			return netip.Addr{}, fmt.Errorf("unexpected network %q", network)
		}
		return netip.IPv6Loopback(), nil
	}

	proxy, err := adapter.ParseProxy(map[string]any{
		"name":       "controlled-nat64-direct",
		"type":       "direct",
		"ip-version": "ipv4",
	})
	if err != nil {
		t.Fatalf("ParseProxy() error = %v", err)
	}
	t.Cleanup(func() { _ = proxy.Close() })

	tcpPort := tcpListener.Addr().(*net.TCPAddr).AddrPort().Port()
	logicalTCPURL := "http://" + net.JoinHostPort(logicalAddress.String(), fmt.Sprint(tcpPort))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	delay, err := proxy.URLTest(ctx, logicalTCPURL, nil)
	cancel()
	if err != nil {
		t.Fatalf("NAT64 TCP URLTest() error = %v", err)
	}
	if delay == 0 {
		t.Fatal("NAT64 TCP URLTest() returned the failure sentinel delay")
	}
	if count := tcpSynthesis.Load(); count != 1 {
		t.Fatalf("TCP synthesis count = %d, want 1", count)
	}

	udpPort := udpTarget.LocalAddr().(*net.UDPAddr).AddrPort().Port()
	logicalUDPAddress := netip.AddrPortFrom(logicalAddress, udpPort)
	metadata := &C.Metadata{
		NetWork: C.UDP,
		Type:    C.TUN,
		DstIP:   logicalAddress,
		DstPort: udpPort,
	}
	ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
	packetConnection, err := proxy.ListenPacketContext(ctx, metadata)
	cancel()
	if err != nil {
		t.Fatalf("NAT64 UDP ListenPacketContext() error = %v", err)
	}
	defer packetConnection.Close()
	if err := packetConnection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetDeadline() error = %v", err)
	}
	payload := []byte("hako-controlled-nat64-udp")
	if _, err := packetConnection.WriteTo(payload, net.UDPAddrFromAddrPort(logicalUDPAddress)); err != nil {
		t.Fatalf("NAT64 UDP WriteTo() error = %v", err)
	}
	buffer := make([]byte, 64*1024)
	n, source, err := packetConnection.ReadFrom(buffer)
	if err != nil {
		t.Fatalf("NAT64 UDP ReadFrom() error = %v", err)
	}
	if !bytes.Equal(buffer[:n], payload) {
		t.Fatalf("NAT64 UDP response = %q, want %q", buffer[:n], payload)
	}
	if source.String() != net.UDPAddrFromAddrPort(logicalUDPAddress).String() {
		t.Fatalf("NAT64 UDP logical source = %s, want %s", source, logicalUDPAddress)
	}
	if count := udpSynthesis.Load(); count != 2 {
		t.Fatalf("UDP synthesis count = %d, want 2", count)
	}

	if snapshot := nat64DiagnosticsSnapshot(); snapshot.attempts != 3 || snapshot.applied != 3 || snapshot.failures != 0 {
		t.Fatalf("NAT64 success diagnostics = %#v", snapshot)
	}

	wantFailure := errors.New("controlled NAT64 synthesis failure")
	synthesizeIPv4Literal = func(string, netip.Addr) (netip.Addr, error) {
		return netip.Addr{}, wantFailure
	}
	ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
	_, err = proxy.URLTest(ctx, logicalTCPURL, nil)
	cancel()
	if !errors.Is(err, wantFailure) {
		t.Fatalf("NAT64 fail-closed error = %v, want %v", err, wantFailure)
	}
	if snapshot := nat64DiagnosticsSnapshot(); snapshot.attempts != 4 || snapshot.applied != 3 || snapshot.failures != 1 {
		t.Fatalf("NAT64 failure diagnostics = %#v", snapshot)
	}
}
