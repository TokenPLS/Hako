package hako

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/adapter"
	"github.com/TokenPLS/Hako/component/auth"
	C "github.com/TokenPLS/Hako/constant"
	"github.com/TokenPLS/Hako/transport/socks5"
)

func TestControlledSOCKS5ConnectInterop(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodHead {
			t.Errorf("target method = %s, want HEAD", request.Method)
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(target.Close)

	const (
		username = "hako-user"
		password = "hako-password"
	)
	server, port := startSOCKS5ConnectServer(t, username, password)
	t.Cleanup(func() { _ = server.Close() })

	proxy, err := adapter.ParseProxy(map[string]any{
		"name":     "controlled-socks5",
		"type":     "socks5",
		"server":   "127.0.0.1",
		"port":     port,
		"username": username,
		"password": password,
	})
	if err != nil {
		t.Fatalf("ParseProxy() error = %v", err)
	}
	t.Cleanup(func() { _ = proxy.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	delay, err := proxy.URLTest(ctx, target.URL, nil)
	if err != nil {
		t.Fatalf("SOCKS5 CONNECT URLTest() error = %v", err)
	}
	if delay == 0 {
		t.Fatal("SOCKS5 CONNECT URLTest() returned the failure sentinel delay")
	}
}

func TestControlledSOCKS5ConnectRejectsInvalidCredentials(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(target.Close)

	server, port := startSOCKS5ConnectServer(t, "hako-user", "correct-password")
	t.Cleanup(func() { _ = server.Close() })

	proxy, err := adapter.ParseProxy(map[string]any{
		"name":     "controlled-socks5-invalid-auth",
		"type":     "socks5",
		"server":   "127.0.0.1",
		"port":     port,
		"username": "hako-user",
		"password": "wrong-password",
	})
	if err != nil {
		t.Fatalf("ParseProxy() error = %v", err)
	}
	t.Cleanup(func() { _ = proxy.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := proxy.URLTest(ctx, target.URL, nil); err == nil || !strings.Contains(err.Error(), "username/password") {
		t.Fatalf("invalid credentials error = %v, want authentication failure", err)
	}
}

func TestControlledSOCKS5UDPAssociateInterop(t *testing.T) {
	target, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen for UDP echo target: %v", err)
	}
	t.Cleanup(func() { _ = target.Close() })
	go serveUDPEcho(target)

	const (
		username = "hako-user"
		password = "hako-password"
	)
	server, port := startSOCKS5ConnectServer(t, username, password)
	t.Cleanup(func() { _ = server.Close() })

	proxy, err := adapter.ParseProxy(map[string]any{
		"name":     "controlled-socks5-udp",
		"type":     "socks5",
		"server":   "127.0.0.1",
		"port":     port,
		"username": username,
		"password": password,
		"udp":      true,
	})
	if err != nil {
		t.Fatalf("ParseProxy() error = %v", err)
	}
	t.Cleanup(func() { _ = proxy.Close() })

	targetAddress := target.LocalAddr().(*net.UDPAddr)
	metadata := &C.Metadata{
		NetWork: C.UDP,
		Type:    C.SOCKS5,
		DstIP:   netip.MustParseAddr("127.0.0.1"),
		DstPort: uint16(targetAddress.Port),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	packetConnection, err := proxy.ListenPacketContext(ctx, metadata)
	if err != nil {
		t.Fatalf("ListenPacketContext() error = %v", err)
	}
	defer packetConnection.Close()
	if err := packetConnection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetDeadline() error = %v", err)
	}

	payload := []byte("hako-controlled-socks5-udp")
	if _, err := packetConnection.WriteTo(payload, targetAddress); err != nil {
		t.Fatalf("WriteTo() error = %v", err)
	}
	buffer := make([]byte, 64*1024)
	n, source, err := packetConnection.ReadFrom(buffer)
	if err != nil {
		t.Fatalf("ReadFrom() error = %v", err)
	}
	if !bytes.Equal(buffer[:n], payload) {
		t.Fatalf("UDP echo payload = %q, want %q", buffer[:n], payload)
	}
	if source.String() != targetAddress.String() {
		t.Fatalf("UDP echo source = %s, want %s", source, targetAddress)
	}
}

type controlledSOCKS5Server struct {
	net.Listener
	udp *net.UDPConn
}

func (s *controlledSOCKS5Server) Close() error {
	_ = s.udp.Close()
	return s.Listener.Close()
}

func startSOCKS5ConnectServer(t *testing.T, username, password string) (*controlledSOCKS5Server, int) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for SOCKS5 proxy: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		_ = listener.Close()
		t.Fatalf("listen for SOCKS5 UDP relay: %v", err)
	}
	server := &controlledSOCKS5Server{Listener: listener, udp: udp}
	authenticator := auth.NewAuthenticator([]auth.AuthUser{{User: username, Pass: password}})

	go func() {
		for {
			connection, err := server.Accept()
			if err != nil {
				return
			}
			go serveSOCKS5Connect(connection, authenticator)
		}
	}()
	go serveSOCKS5UDPRelay(udp)
	return server, port
}

func serveSOCKS5Connect(client net.Conn, authenticator auth.Authenticator) {
	defer client.Close()
	address, command, _, err := socks5.ServerHandshake(client, authenticator)
	if err != nil {
		return
	}
	if command == socks5.CmdUDPAssociate {
		_, _ = io.Copy(io.Discard, client)
		return
	}
	if command != socks5.CmdConnect {
		return
	}
	upstream, err := net.DialTimeout("tcp", address.String(), 2*time.Second)
	if err != nil {
		return
	}
	defer upstream.Close()
	relayControlledTCP(client, upstream)
}

func serveSOCKS5UDPRelay(relay *net.UDPConn) {
	buffer := make([]byte, 64*1024)
	response := make([]byte, 64*1024)
	for {
		n, client, err := relay.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		destination, payload, err := socks5.DecodeUDPPacket(buffer[:n])
		if err != nil || destination.UDPAddr() == nil {
			continue
		}
		upstream, err := net.DialUDP("udp", nil, destination.UDPAddr())
		if err != nil {
			continue
		}
		_ = upstream.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err = upstream.Write(payload); err == nil {
			var source *net.UDPAddr
			if n, source, err = upstream.ReadFromUDP(response); err == nil {
				packet, encodeErr := socks5.EncodeUDPPacket(
					socks5.ParseAddrToSocksAddr(source),
					response[:n],
				)
				if encodeErr == nil {
					_, _ = relay.WriteToUDP(packet, client)
				}
			}
		}
		_ = upstream.Close()
	}
}

func serveUDPEcho(connection *net.UDPConn) {
	buffer := make([]byte, 64*1024)
	for {
		n, source, err := connection.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		_, _ = connection.WriteToUDP(buffer[:n], source)
	}
}
