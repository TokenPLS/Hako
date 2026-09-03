package hako

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/adapter"
	C "github.com/TokenPLS/Hako/constant"
	IN "github.com/TokenPLS/Hako/listener/inbound"
)

func TestControlledMieruInterop(t *testing.T) {
	pinUnifiedDelayOff(t)
	for _, test := range []struct {
		name           string
		transport      string
		handshakeMode  string
		multiplexing   string
		trafficPattern string
	}{
		{name: "TCPStandard", transport: "TCP", handshakeMode: "HANDSHAKE_STANDARD", multiplexing: "MULTIPLEXING_LOW"},
		{name: "TCPZeroRTT", transport: "TCP", handshakeMode: "HANDSHAKE_NO_WAIT", multiplexing: "MULTIPLEXING_HIGH"},
		{name: "UDPStandard", transport: "UDP", handshakeMode: "HANDSHAKE_STANDARD", multiplexing: "MULTIPLEXING_OFF"},
		{name: "UDPZeroRTTTrafficPattern", transport: "UDP", handshakeMode: "HANDSHAKE_NO_WAIT", multiplexing: "MULTIPLEXING_MIDDLE", trafficPattern: "GgQIARAK"},
	} {
		t.Run(test.name, func(t *testing.T) {
			runControlledMieruVariant(t, test.transport, test.handshakeMode, test.multiplexing, test.trafficPattern, false)
		})
	}
}

func TestControlledMieruInvalidPasswordFailsClosed(t *testing.T) {
	pinUnifiedDelayOff(t)
	runControlledMieruVariant(t, "TCP", "HANDSHAKE_STANDARD", "MULTIPLEXING_LOW", "", true)
}

func runControlledMieruVariant(t *testing.T, transport string, handshakeMode string, multiplexing string, trafficPattern string, testInvalidPassword bool) {
	t.Helper()
	const username = "controlled-mieru-user"
	const password = "controlled-mieru-password"
	var (
		port         int
		stream       net.Listener
		packet       net.PacketConn
		listenConfig controlledMieruListenConfig
		err          error
	)
	if transport == "TCP" {
		stream, err = net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen for Mieru TCP: %v", err)
		}
		port = stream.Addr().(*net.TCPAddr).Port
		listenConfig.listen = func(context.Context, string, string) (net.Listener, error) {
			return stream, nil
		}
		listenConfig.listenPacket = func(context.Context, string, string) (net.PacketConn, error) {
			panic("unexpected Mieru packet listener for TCP transport")
		}
	} else {
		packet, err = net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen for Mieru UDP: %v", err)
		}
		port = packet.LocalAddr().(*net.UDPAddr).Port
		listenConfig.listen = func(context.Context, string, string) (net.Listener, error) {
			panic("unexpected Mieru stream listener for UDP transport")
		}
		listenConfig.listenPacket = func(context.Context, string, string) (net.PacketConn, error) {
			return packet, nil
		}
	}
	server, err := IN.NewMieru(&IN.MieruOption{
		BaseOption: IN.BaseOption{
			NameStr:            "controlled-mieru-inbound",
			Listen:             "127.0.0.1",
			Port:               strconv.Itoa(port),
			ListenConfigForAPI: listenConfig,
		},
		Transport:           transport,
		Users:               map[string]string{username: password},
		TrafficPattern:      trafficPattern,
		UserHintIsMandatory: true,
	})
	if err != nil {
		t.Fatalf("NewMieru() error = %v", err)
	}
	if err := server.Listen(&controlledReferenceTunnel{}); err != nil {
		t.Fatalf("Mieru Listen() error = %v", err)
	}
	defer server.Close()
	mapping := map[string]any{
		"name":            "controlled-mieru-outbound",
		"type":            "mieru",
		"server":          "127.0.0.1",
		"port":            port,
		"transport":       transport,
		"udp":             true,
		"username":        username,
		"password":        password,
		"handshake-mode":  handshakeMode,
		"multiplexing":    multiplexing,
		"traffic-pattern": trafficPattern,
	}
	proxy, err := adapter.ParseProxy(mapping)
	if err != nil {
		t.Fatalf("ParseProxy() error = %v", err)
	}
	defer proxy.Close()

	var targetRequests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		targetRequests.Add(1)
		if request.Method != http.MethodHead {
			t.Errorf("target method = %s, want HEAD", request.Method)
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	delay, err := proxy.URLTest(ctx, target.URL, nil)
	cancel()
	if err != nil {
		t.Fatalf("Mieru %s URLTest() error = %v", transport, err)
	}
	if delay == 0 {
		t.Fatalf("Mieru %s URLTest() returned the failure sentinel delay", transport)
	}
	if count := targetRequests.Load(); count != 1 {
		t.Fatalf("target request count = %d, want 1", count)
	}

	udpTarget, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen for UDP echo target: %v", err)
	}
	defer udpTarget.Close()
	go serveUDPEcho(udpTarget)
	udpAddress := udpTarget.LocalAddr().(*net.UDPAddr)
	udpAddrPort := udpAddress.AddrPort()
	metadata := &C.Metadata{
		NetWork: C.UDP,
		Type:    C.TUN,
		DstIP:   udpAddrPort.Addr(),
		DstPort: udpAddrPort.Port(),
	}
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	packetConnection, err := proxy.ListenPacketContext(ctx, metadata)
	cancel()
	if err != nil {
		t.Fatalf("ListenPacketContext() error = %v", err)
	}
	defer packetConnection.Close()
	payload := []byte("hako-controlled-mieru-udp-" + transport + "-" + handshakeMode)
	if _, err := packetConnection.WriteTo(payload, udpAddress); err != nil {
		t.Fatalf("WriteTo() error = %v", err)
	}
	buffer := make([]byte, 64*1024)
	if err := packetConnection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetDeadline() error = %v", err)
	}
	n, source, err := packetConnection.ReadFrom(buffer)
	if err != nil {
		t.Fatalf("ReadFrom() error = %v", err)
	}
	if !bytes.Equal(buffer[:n], payload) || source.String() != udpAddress.String() {
		t.Fatalf("UDP response = (%q, %v), want (%q, %v)", buffer[:n], source, payload, udpAddress)
	}

	if !testInvalidPassword {
		return
	}
	failedMapping := cloneAnyTLSMapping(mapping)
	failedMapping["name"] = "controlled-mieru-invalid-password"
	failedMapping["password"] = "wrong-password"
	failedProxy, err := adapter.ParseProxy(failedMapping)
	if err != nil {
		t.Fatalf("ParseProxy() invalid password error = %v", err)
	}
	defer failedProxy.Close()
	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	_, err = failedProxy.URLTest(ctx, target.URL, nil)
	cancel()
	if err == nil {
		t.Fatal("invalid Mieru password unexpectedly succeeded")
	}
	if count := targetRequests.Load(); count != 1 {
		t.Fatalf("failed attempt leaked to target; request count = %d", count)
	}
}

type controlledMieruListenConfig struct {
	listen       func(context.Context, string, string) (net.Listener, error)
	listenPacket func(context.Context, string, string) (net.PacketConn, error)
}

func (config controlledMieruListenConfig) Listen(ctx context.Context, network string, address string) (net.Listener, error) {
	return config.listen(ctx, network, address)
}

func (config controlledMieruListenConfig) ListenPacket(ctx context.Context, network string, address string) (net.PacketConn, error) {
	return config.listenPacket(ctx, network, address)
}
