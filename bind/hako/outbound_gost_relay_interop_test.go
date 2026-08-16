package hako

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/adapter"
	"github.com/TokenPLS/Hako/component/ca"
	C "github.com/TokenPLS/Hako/constant"
	"github.com/metacubex/tls"
)

func TestControlledGostRelayInterop(t *testing.T) {
	serverCertificate, serverPrivateKey, serverFingerprint, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatalf("generate gost relay certificate: %v", err)
	}
	clientCertificate, clientPrivateKey, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatalf("generate gost relay client certificate: %v", err)
	}
	const username = "controlled-gost-user"
	const password = "controlled-gost-password"
	serverAddress := startControlledGostRelayServer(t, serverCertificate, serverPrivateKey, clientCertificate, username, password, nil, nil)
	host, port, err := net.SplitHostPort(serverAddress)
	if err != nil {
		t.Fatalf("split gost relay address: %v", err)
	}
	mapping := map[string]any{
		"name":        "controlled-gost-relay",
		"type":        "gost-relay",
		"server":      host,
		"port":        port,
		"udp":         true,
		"tls":         true,
		"username":    username,
		"password":    password,
		"fingerprint": serverFingerprint,
		"certificate": clientCertificate,
		"private-key": clientPrivateKey,
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
		t.Fatalf("gost relay URLTest() error = %v", err)
	}
	if delay == 0 {
		t.Fatal("gost relay URLTest() returned the failure sentinel delay")
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
	if err := packetConnection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetDeadline() error = %v", err)
	}
	payload := []byte("hako-controlled-gost-relay-udp")
	if _, err := packetConnection.WriteTo(payload, udpAddress); err != nil {
		t.Fatalf("WriteTo() error = %v", err)
	}
	buffer := make([]byte, 64*1024)
	n, source, err := packetConnection.ReadFrom(buffer)
	if err != nil {
		t.Fatalf("ReadFrom() error = %v", err)
	}
	if !bytes.Equal(buffer[:n], payload) || source.String() != udpAddress.String() {
		t.Fatalf("UDP response = (%q, %v), want (%q, %v)", buffer[:n], source, payload, udpAddress)
	}

	_, _, wrongFingerprint, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatalf("generate wrong fingerprint: %v", err)
	}
	for _, failure := range []struct {
		name        string
		password    string
		fingerprint string
	}{
		{name: "InvalidPassword", password: "wrong-password", fingerprint: serverFingerprint},
		{name: "InvalidCertificate", password: password, fingerprint: wrongFingerprint},
	} {
		t.Run(failure.name, func(t *testing.T) {
			failedMapping := cloneAnyTLSMapping(mapping)
			failedMapping["name"] = "controlled-gost-relay-" + failure.name
			failedMapping["password"] = failure.password
			failedMapping["fingerprint"] = failure.fingerprint
			failedProxy, err := adapter.ParseProxy(failedMapping)
			if err != nil {
				t.Fatalf("ParseProxy() error = %v", err)
			}
			defer failedProxy.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_, err = failedProxy.URLTest(ctx, target.URL, nil)
			cancel()
			if err == nil {
				t.Fatal("invalid gost relay credentials unexpectedly succeeded")
			}
			if count := targetRequests.Load(); count != 1 {
				t.Fatalf("failed gost relay attempt leaked to target; request count = %d", count)
			}
		})
	}
}

func TestControlledGostRelayForwardInterop(t *testing.T) {
	serverCertificate, serverPrivateKey, serverFingerprint, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatalf("generate gost relay certificate: %v", err)
	}
	clientCertificate, clientPrivateKey, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatalf("generate gost relay client certificate: %v", err)
	}
	var targetRequests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		targetRequests.Add(1)
		if request.Method != http.MethodHead {
			t.Errorf("target method = %s, want HEAD", request.Method)
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	udpTarget, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen for UDP echo target: %v", err)
	}
	defer udpTarget.Close()
	go serveUDPEcho(udpTarget)

	const username = "controlled-gost-forward-user"
	const password = "controlled-gost-forward-password"
	var acceptedRequests atomic.Int32
	serverAddress := startControlledGostRelayServer(
		t,
		serverCertificate,
		serverPrivateKey,
		clientCertificate,
		username,
		password,
		&acceptedRequests,
		&controlledGostRelayForwardTargets{
			tcp: strings.TrimPrefix(target.URL, "http://"),
			udp: udpTarget.LocalAddr().String(),
		},
	)
	host, port, err := net.SplitHostPort(serverAddress)
	if err != nil {
		t.Fatalf("split gost relay address: %v", err)
	}
	proxy, err := adapter.ParseProxy(map[string]any{
		"name":        "controlled-gost-relay-forward",
		"type":        "gost-relay",
		"server":      host,
		"port":        port,
		"forward":     true,
		"udp":         true,
		"tls":         true,
		"username":    username,
		"password":    password,
		"fingerprint": serverFingerprint,
		"certificate": clientCertificate,
		"private-key": clientPrivateKey,
	})
	if err != nil {
		t.Fatalf("ParseProxy() error = %v", err)
	}
	defer proxy.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	delay, err := proxy.URLTest(ctx, target.URL, nil)
	cancel()
	if err != nil {
		t.Fatalf("gost relay forward URLTest() error = %v", err)
	}
	if delay == 0 {
		t.Fatal("gost relay forward URLTest() returned the failure sentinel delay")
	}
	if count := targetRequests.Load(); count != 1 {
		t.Fatalf("forward target request count = %d, want 1", count)
	}

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
		t.Fatalf("gost relay forward ListenPacketContext() error = %v", err)
	}
	defer packetConnection.Close()
	if err := packetConnection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetDeadline() error = %v", err)
	}
	payload := []byte("hako-controlled-gost-relay-forward-udp")
	if _, err := packetConnection.WriteTo(payload, udpAddress); err != nil {
		t.Fatalf("WriteTo() error = %v", err)
	}
	buffer := make([]byte, 64*1024)
	n, source, err := packetConnection.ReadFrom(buffer)
	if err != nil {
		t.Fatalf("ReadFrom() error = %v", err)
	}
	if !bytes.Equal(buffer[:n], payload) || source.String() != udpAddress.String() {
		t.Fatalf("UDP response = (%q, %v), want (%q, %v)", buffer[:n], source, payload, udpAddress)
	}
	if count := acceptedRequests.Load(); count != 2 {
		t.Fatalf("accepted forward relay requests = %d, want 2", count)
	}
}

type controlledGostRelayForwardTargets struct {
	tcp string
	udp string
}

func startControlledGostRelayServer(t *testing.T, certificate string, privateKey string, clientCertificate string, username string, password string, acceptedRequests *atomic.Int32, forwardTargets *controlledGostRelayForwardTargets) string {
	t.Helper()
	keyPair, err := tls.X509KeyPair([]byte(certificate), []byte(privateKey))
	if err != nil {
		t.Fatalf("parse gost relay certificate: %v", err)
	}
	clientCAs, err := ca.LoadCertificates(clientCertificate)
	if err != nil {
		t.Fatalf("load gost relay client CA: %v", err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for gost relay: %v", err)
	}
	listener = tls.NewListener(listener, &tls.Config{
		Certificates: []tls.Certificate{keyPair},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
	})
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go serveControlledGostRelayConnection(connection, username, password, acceptedRequests, forwardTargets)
		}
	}()
	return listener.Addr().String()
}

func serveControlledGostRelayConnection(connection net.Conn, username string, password string, acceptedRequests *atomic.Int32, forwardTargets *controlledGostRelayForwardTargets) {
	defer connection.Close()
	command, target, network, candidateUser, candidatePassword, err := readControlledGostRelayRequest(connection)
	if err != nil {
		return
	}
	if candidateUser != username || candidatePassword != password {
		_, _ = connection.Write([]byte{0x01, 0x02, 0x00, 0x00})
		return
	}
	if command&0x7f != 0x01 {
		_, _ = connection.Write([]byte{0x01, 0x01, 0x00, 0x00})
		return
	}
	if forwardTargets != nil {
		if target != "" {
			_, _ = connection.Write([]byte{0x01, 0x01, 0x00, 0x00})
			return
		}
		if command&0x80 != 0 || network == 0x0001 {
			target = forwardTargets.udp
		} else {
			target = forwardTargets.tcp
		}
	}
	if target == "" {
		_, _ = connection.Write([]byte{0x01, 0x01, 0x00, 0x00})
		return
	}
	if acceptedRequests != nil {
		acceptedRequests.Add(1)
	}
	if command&0x80 != 0 || network == 0x0001 {
		serveControlledGostRelayUDP(connection, target)
		return
	}
	upstream, err := net.DialTimeout("tcp", target, 2*time.Second)
	if err != nil {
		_, _ = connection.Write([]byte{0x01, 0x06, 0x00, 0x00})
		return
	}
	defer upstream.Close()
	if _, err := connection.Write([]byte{0x01, 0x00, 0x00, 0x00}); err != nil {
		return
	}
	relayControlledTCP(connection, upstream)
}

func readControlledGostRelayRequest(reader io.Reader) (byte, string, uint16, string, string, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return 0, "", 0, "", "", err
	}
	if header[0] != 0x01 {
		return 0, "", 0, "", "", fmt.Errorf("unsupported relay version")
	}
	payload := make([]byte, int(header[2])<<8|int(header[3]))
	if _, err := io.ReadFull(reader, payload); err != nil {
		return 0, "", 0, "", "", err
	}
	var target, username, password string
	var network uint16
	for len(payload) >= 3 {
		featureType := payload[0]
		length := int(payload[1])<<8 | int(payload[2])
		payload = payload[3:]
		if length > len(payload) {
			return 0, "", 0, "", "", fmt.Errorf("truncated relay feature")
		}
		feature := payload[:length]
		payload = payload[length:]
		switch featureType {
		case 0x01:
			if len(feature) < 2 || int(feature[0])+1 >= len(feature) {
				return 0, "", 0, "", "", fmt.Errorf("invalid relay auth")
			}
			usernameLength := int(feature[0])
			username = string(feature[1 : 1+usernameLength])
			passwordLength := int(feature[1+usernameLength])
			if 2+usernameLength+passwordLength != len(feature) {
				return 0, "", 0, "", "", fmt.Errorf("invalid relay password")
			}
			password = string(feature[2+usernameLength:])
		case 0x02:
			var err error
			target, err = decodeControlledGostRelayAddress(feature)
			if err != nil {
				return 0, "", 0, "", "", err
			}
		case 0x04:
			if len(feature) != 2 {
				return 0, "", 0, "", "", fmt.Errorf("invalid relay network")
			}
			network = binary.BigEndian.Uint16(feature)
		}
	}
	return header[1], target, network, username, password, nil
}

func decodeControlledGostRelayAddress(payload []byte) (string, error) {
	if len(payload) < 3 {
		return "", fmt.Errorf("short relay address")
	}
	var host string
	switch payload[0] {
	case 0x01:
		if len(payload) != 7 {
			return "", fmt.Errorf("invalid relay IPv4 address")
		}
		host = net.IP(payload[1:5]).String()
		payload = payload[5:]
	case 0x04:
		if len(payload) != 19 {
			return "", fmt.Errorf("invalid relay IPv6 address")
		}
		host = net.IP(payload[1:17]).String()
		payload = payload[17:]
	case 0x03:
		length := int(payload[1])
		if len(payload) != 2+length+2 {
			return "", fmt.Errorf("invalid relay domain address")
		}
		host = string(payload[2 : 2+length])
		payload = payload[2+length:]
	default:
		return "", fmt.Errorf("unknown relay address type")
	}
	return net.JoinHostPort(host, fmt.Sprint(binary.BigEndian.Uint16(payload))), nil
}

func serveControlledGostRelayUDP(connection net.Conn, target string) {
	upstream, err := net.Dial("udp", target)
	if err != nil {
		_, _ = connection.Write([]byte{0x01, 0x06, 0x00, 0x00})
		return
	}
	defer upstream.Close()
	if _, err := connection.Write([]byte{0x01, 0x00, 0x00, 0x00}); err != nil {
		return
	}
	var writeMutex sync.Mutex
	for {
		var header [2]byte
		if _, err := io.ReadFull(connection, header[:]); err != nil {
			return
		}
		packet := make([]byte, binary.BigEndian.Uint16(header[:]))
		if _, err := io.ReadFull(connection, packet); err != nil {
			return
		}
		if _, err := upstream.Write(packet); err != nil {
			return
		}
		response := make([]byte, 64*1024)
		n, err := upstream.Read(response)
		if err != nil {
			return
		}
		writeMutex.Lock()
		binary.BigEndian.PutUint16(header[:], uint16(n))
		_, headerErr := connection.Write(header[:])
		_, bodyErr := connection.Write(response[:n])
		writeMutex.Unlock()
		if headerErr != nil || bodyErr != nil {
			return
		}
	}
}
