//go:build with_gvisor

package hako

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/adapter"
	C "github.com/TokenPLS/Hako/constant"
	"github.com/metacubex/tailscale-wireguard-go/tun"
	tailscaleNetstack "github.com/metacubex/tailscale-wireguard-go/tun/netstack"
	"github.com/metacubex/wireguard-go/conn"
	"github.com/metacubex/wireguard-go/device"
	wireguardTun "github.com/metacubex/wireguard-go/tun"
	D "github.com/miekg/dns"
	"golang.org/x/crypto/curve25519"
)

func TestControlledWireGuardInterop(t *testing.T) {
	const operationTimeout = 15 * time.Second

	serverPrivate, serverPublic := generateControlledWireGuardKeyPair(t)
	clientPrivate, clientPublic := generateControlledWireGuardKeyPair(t)
	peerAddress4 := netip.MustParseAddr("10.77.0.1")
	peerAddress6 := netip.MustParseAddr("fd00:77::1")
	var targetRequests atomic.Int32
	var dnsQueries atomic.Int32
	serverPort, tcpPort4, udpPort4, tcpPort6, udpPort6, dnsPort, peerDevice := startControlledWireGuardPeer(t, peerAddress4, peerAddress6, serverPrivate, clientPublic, &targetRequests, &dnsQueries)

	mapping := map[string]any{
		"name":                 "controlled-wireguard-outbound",
		"type":                 "wireguard",
		"server":               "127.0.0.1",
		"port":                 serverPort,
		"ip":                   "10.77.0.2",
		"ipv6":                 "fd00:77::2",
		"private-key":          base64.StdEncoding.EncodeToString(clientPrivate),
		"public-key":           base64.StdEncoding.EncodeToString(serverPublic),
		"persistent-keepalive": 1,
		"udp":                  true,
	}
	proxy, err := adapter.ParseProxy(mapping)
	if err != nil {
		t.Fatalf("ParseProxy() error = %v", err)
	}
	defer proxy.Close()

	wireTargetURL := "http://" + net.JoinHostPort(peerAddress4.String(), strconv.Itoa(int(tcpPort4)))
	// The first request also establishes the userspace WireGuard handshake.
	// Race instrumentation on a deliberately two-core release gate can push
	// that one-time setup beyond five seconds even though the peer is already
	// bound. Keep the wait bounded without weakening any subsequent data-plane
	// or invalid-key deadline.
	ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
	delay, err := proxy.URLTest(ctx, wireTargetURL, nil)
	cancel()
	if err != nil {
		peerState, _ := peerDevice.IpcGet()
		t.Fatalf("WireGuard URLTest() error = %v; peer state:\n%s", err, peerState)
	}
	if delay == 0 {
		t.Fatal("WireGuard URLTest() returned the failure sentinel delay")
	}
	wireTargetURL6 := "http://" + net.JoinHostPort(peerAddress6.String(), strconv.Itoa(int(tcpPort6)))
	ctx, cancel = context.WithTimeout(context.Background(), operationTimeout)
	delay, err = proxy.URLTest(ctx, wireTargetURL6, nil)
	cancel()
	if err != nil {
		peerState, _ := peerDevice.IpcGet()
		t.Fatalf("WireGuard IPv6 URLTest() error = %v; peer state:\n%s", err, peerState)
	}
	if delay == 0 {
		t.Fatal("WireGuard IPv6 URLTest() returned the failure sentinel delay")
	}
	if count := targetRequests.Load(); count != 2 {
		t.Fatalf("target request count = %d, want 2", count)
	}
	wireUDPAddrPort := netip.AddrPortFrom(peerAddress4, udpPort4)
	wireUDPAddress := net.UDPAddrFromAddrPort(wireUDPAddrPort)
	metadata := &C.Metadata{
		NetWork: C.UDP,
		Type:    C.TUN,
		DstIP:   wireUDPAddrPort.Addr(),
		DstPort: wireUDPAddrPort.Port(),
	}
	ctx, cancel = context.WithTimeout(context.Background(), operationTimeout)
	packetConnection, err := proxy.ListenPacketContext(ctx, metadata)
	cancel()
	if err != nil {
		t.Fatalf("ListenPacketContext() error = %v", err)
	}
	if err := packetConnection.SetDeadline(time.Now().Add(operationTimeout)); err != nil {
		t.Fatalf("SetDeadline() error = %v", err)
	}
	payload := []byte("hako-controlled-wireguard-udp")
	if _, err := packetConnection.WriteTo(payload, wireUDPAddress); err != nil {
		t.Fatalf("WriteTo() error = %v", err)
	}
	buffer := make([]byte, 64*1024)
	n, source, err := packetConnection.ReadFrom(buffer)
	if err != nil {
		t.Fatalf("ReadFrom() error = %v", err)
	}
	if !bytes.Equal(buffer[:n], payload) || source.String() != wireUDPAddress.String() {
		t.Fatalf("UDP response = (%q, %v), want (%q, %v)", buffer[:n], source, payload, wireUDPAddress)
	}
	_ = packetConnection.Close()

	wireUDPAddrPort6 := netip.AddrPortFrom(peerAddress6, udpPort6)
	wireUDPAddress6 := net.UDPAddrFromAddrPort(wireUDPAddrPort6)
	metadata6 := &C.Metadata{
		NetWork: C.UDP,
		Type:    C.TUN,
		DstIP:   wireUDPAddrPort6.Addr(),
		DstPort: wireUDPAddrPort6.Port(),
	}
	ctx, cancel = context.WithTimeout(context.Background(), operationTimeout)
	packetConnection6, err := proxy.ListenPacketContext(ctx, metadata6)
	cancel()
	if err != nil {
		t.Fatalf("ListenPacketContext(IPv6) error = %v", err)
	}
	defer packetConnection6.Close()
	if err := packetConnection6.SetDeadline(time.Now().Add(operationTimeout)); err != nil {
		t.Fatalf("SetDeadline(IPv6) error = %v", err)
	}
	payload6 := []byte("hako-controlled-wireguard-udp-ipv6")
	if _, err := packetConnection6.WriteTo(payload6, wireUDPAddress6); err != nil {
		t.Fatalf("WriteTo(IPv6) error = %v", err)
	}
	n, source, err = packetConnection6.ReadFrom(buffer)
	if err != nil {
		t.Fatalf("ReadFrom(IPv6) error = %v", err)
	}
	if !bytes.Equal(buffer[:n], payload6) || source.String() != wireUDPAddress6.String() {
		t.Fatalf("IPv6 UDP response = (%q, %v), want (%q, %v)", buffer[:n], source, payload6, wireUDPAddress6)
	}
	dnsAddress := netip.AddrPortFrom(peerAddress4, dnsPort)
	dnsMetadata := &C.Metadata{
		NetWork: C.UDP,
		Type:    C.TUN,
		DstIP:   dnsAddress.Addr(),
		DstPort: dnsAddress.Port(),
	}
	ctx, cancel = context.WithTimeout(context.Background(), operationTimeout)
	dnsConnection, err := proxy.ListenPacketContext(ctx, dnsMetadata)
	cancel()
	if err != nil {
		t.Fatalf("ListenPacketContext(DNS) error = %v", err)
	}
	defer dnsConnection.Close()
	if err := dnsConnection.SetDeadline(time.Now().Add(operationTimeout)); err != nil {
		t.Fatalf("SetDeadline(DNS) error = %v", err)
	}
	dnsQuery := new(D.Msg)
	dnsQuery.SetQuestion("controlled.wireguard.test.", D.TypeA)
	dnsPayload, err := dnsQuery.Pack()
	if err != nil {
		t.Fatalf("pack WireGuard DNS query: %v", err)
	}
	if _, err := dnsConnection.WriteTo(dnsPayload, net.UDPAddrFromAddrPort(dnsAddress)); err != nil {
		t.Fatalf("WriteTo(DNS) error = %v", err)
	}
	n, _, err = dnsConnection.ReadFrom(buffer)
	if err != nil {
		t.Fatalf("ReadFrom(DNS) error = %v", err)
	}
	dnsResponse := new(D.Msg)
	if err := dnsResponse.Unpack(buffer[:n]); err != nil {
		t.Fatalf("unpack WireGuard DNS response: %v", err)
	}
	if dnsResponse.Rcode != D.RcodeSuccess || len(dnsResponse.Answer) != 1 {
		t.Fatalf("WireGuard DNS response rcode=%s answers=%d", D.RcodeToString[dnsResponse.Rcode], len(dnsResponse.Answer))
	}
	if count := dnsQueries.Load(); count == 0 {
		t.Fatal("WireGuard DNS query did not reach the tunnel DNS server")
	}

	_, wrongPublic := generateControlledWireGuardKeyPair(t)
	failedMapping := cloneAnyTLSMapping(mapping)
	failedMapping["name"] = "controlled-wireguard-invalid-peer"
	failedMapping["public-key"] = base64.StdEncoding.EncodeToString(wrongPublic)
	failedProxy, err := adapter.ParseProxy(failedMapping)
	if err != nil {
		t.Fatalf("ParseProxy() invalid peer error = %v", err)
	}
	defer failedProxy.Close()
	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	_, err = failedProxy.URLTest(ctx, wireTargetURL, nil)
	cancel()
	if err == nil {
		t.Fatal("invalid WireGuard peer key unexpectedly succeeded")
	}
	if count := targetRequests.Load(); count != 2 {
		t.Fatalf("failed WireGuard attempt leaked to target; request count = %d", count)
	}
}

func generateControlledWireGuardKeyPair(t *testing.T) ([]byte, []byte) {
	t.Helper()
	privateKey := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(privateKey); err != nil {
		t.Fatalf("generate WireGuard private key: %v", err)
	}
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("derive WireGuard public key: %v", err)
	}
	return privateKey, publicKey
}

func startControlledWireGuardPeer(t *testing.T, peerAddress4 netip.Addr, peerAddress6 netip.Addr, privateKey []byte, clientPublicKey []byte, targetRequests *atomic.Int32, dnsQueries *atomic.Int32) (int, uint16, uint16, uint16, uint16, uint16, *device.Device) {
	t.Helper()
	tunDevice, peerNetwork, err := tailscaleNetstack.CreateNetTUN([]netip.Addr{peerAddress4, peerAddress6}, nil, 1408)
	if err != nil {
		t.Fatalf("create WireGuard peer netstack: %v", err)
	}
	adapter := &controlledWireGuardTUNAdapter{Device: tunDevice, events: make(chan wireguardTun.Event, 1)}
	adapter.events <- wireguardTun.EventUp
	t.Cleanup(func() { _ = adapter.Close() })

	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		targetRequests.Add(1)
		if request.Method != http.MethodHead {
			t.Errorf("target method = %s, want HEAD", request.Method)
		}
		writer.WriteHeader(http.StatusNoContent)
	})
	tcpListener4, err := peerNetwork.ListenTCPAddrPort(netip.AddrPortFrom(peerAddress4, 0))
	if err != nil {
		t.Fatalf("listen on WireGuard peer IPv4 TCP stack: %v", err)
	}
	t.Cleanup(func() { _ = tcpListener4.Close() })
	httpServer4 := &http.Server{ReadHeaderTimeout: 2 * time.Second, Handler: handler}
	go func() { _ = httpServer4.Serve(tcpListener4) }()
	t.Cleanup(func() { _ = httpServer4.Close() })
	tcpAddress4 := tcpListener4.Addr().(*net.TCPAddr).AddrPort()

	udpConnection4, err := peerNetwork.ListenUDPAddrPort(netip.AddrPortFrom(peerAddress4, 0))
	if err != nil {
		t.Fatalf("listen on WireGuard peer IPv4 UDP stack: %v", err)
	}
	t.Cleanup(func() { _ = udpConnection4.Close() })
	go serveControlledWireGuardUDPEcho(udpConnection4)
	udpAddress4 := udpConnection4.LocalAddr().(*net.UDPAddr).AddrPort()

	tcpListener6, err := peerNetwork.ListenTCPAddrPort(netip.AddrPortFrom(peerAddress6, 0))
	if err != nil {
		t.Fatalf("listen on WireGuard peer IPv6 TCP stack: %v", err)
	}
	t.Cleanup(func() { _ = tcpListener6.Close() })
	httpServer6 := &http.Server{ReadHeaderTimeout: 2 * time.Second, Handler: handler}
	go func() { _ = httpServer6.Serve(tcpListener6) }()
	t.Cleanup(func() { _ = httpServer6.Close() })
	tcpAddress6 := tcpListener6.Addr().(*net.TCPAddr).AddrPort()

	udpConnection6, err := peerNetwork.ListenUDPAddrPort(netip.AddrPortFrom(peerAddress6, 0))
	if err != nil {
		t.Fatalf("listen on WireGuard peer IPv6 UDP stack: %v", err)
	}
	t.Cleanup(func() { _ = udpConnection6.Close() })
	go serveControlledWireGuardUDPEcho(udpConnection6)
	udpAddress6 := udpConnection6.LocalAddr().(*net.UDPAddr).AddrPort()

	dnsConnection, err := peerNetwork.ListenUDPAddrPort(netip.AddrPortFrom(peerAddress4, 0))
	if err != nil {
		t.Fatalf("listen on WireGuard peer DNS stack: %v", err)
	}
	dnsServer := &D.Server{PacketConn: dnsConnection, Handler: D.HandlerFunc(func(writer D.ResponseWriter, request *D.Msg) {
		dnsQueries.Add(1)
		response := new(D.Msg)
		response.SetReply(request)
		if len(request.Question) == 1 && request.Question[0].Name == "controlled.wireguard.test." {
			switch request.Question[0].Qtype {
			case D.TypeA:
				response.Answer = []D.RR{&D.A{
					Hdr: D.RR_Header{Name: request.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60},
					A:   net.IP(peerAddress4.AsSlice()),
				}}
			case D.TypeAAAA:
				response.Answer = []D.RR{&D.AAAA{
					Hdr:  D.RR_Header{Name: request.Question[0].Name, Rrtype: D.TypeAAAA, Class: D.ClassINET, Ttl: 60},
					AAAA: net.IP(peerAddress6.AsSlice()),
				}}
			}
		} else {
			response.Rcode = D.RcodeNameError
		}
		_ = writer.WriteMsg(response)
	})}
	go func() { _ = dnsServer.ActivateAndServe() }()
	t.Cleanup(func() { _ = dnsServer.Shutdown() })
	dnsAddress := dnsConnection.LocalAddr().(*net.UDPAddr).AddrPort()

	logger := device.NewLogger(device.LogLevelSilent, "controlled-peer")
	peerDevice := device.NewDevice(adapter, conn.NewDefaultBind(), logger, 0)
	t.Cleanup(func() { peerDevice.Close() })
	configuration := "private_key=" + hex.EncodeToString(privateKey) + "\n" +
		"listen_port=0\n" +
		"public_key=" + hex.EncodeToString(clientPublicKey) + "\n" +
		"allowed_ip=10.77.0.2/32\n" +
		"allowed_ip=fd00:77::2/128\n"
	if err := peerDevice.IpcSet(configuration); err != nil {
		t.Fatalf("configure WireGuard peer: %v", err)
	}
	if err := peerDevice.Up(); err != nil {
		t.Fatalf("start WireGuard peer: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		state, err := peerDevice.IpcGet()
		if err != nil {
			t.Fatalf("read WireGuard peer state: %v", err)
		}
		for _, line := range strings.Split(state, "\n") {
			if strings.HasPrefix(line, "listen_port=") {
				port, err := strconv.Atoi(strings.TrimPrefix(line, "listen_port="))
				if err == nil && port > 0 {
					return port, tcpAddress4.Port(), udpAddress4.Port(), tcpAddress6.Port(), udpAddress6.Port(), dnsAddress.Port(), peerDevice
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("WireGuard peer did not bind a UDP port")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type controlledWireGuardTUNAdapter struct {
	tun.Device
	events    chan wireguardTun.Event
	closeOnce sync.Once
	closeErr  error
}

func (device *controlledWireGuardTUNAdapter) Events() <-chan wireguardTun.Event {
	return device.events
}

func (device *controlledWireGuardTUNAdapter) Close() error {
	device.closeOnce.Do(func() {
		close(device.events)
		device.closeErr = device.Device.Close()
	})
	return device.closeErr
}

func serveControlledWireGuardUDPEcho(connection net.PacketConn) {
	buffer := make([]byte, 64*1024)
	for {
		n, source, err := connection.ReadFrom(buffer)
		if err != nil {
			return
		}
		_, _ = connection.WriteTo(buffer[:n], source)
	}
}
