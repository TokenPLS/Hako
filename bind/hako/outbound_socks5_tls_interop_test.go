package hako

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/adapter"
	"github.com/TokenPLS/Hako/component/auth"
	"github.com/TokenPLS/Hako/component/ca"
	C "github.com/TokenPLS/Hako/constant"
)

const socks5TLSHelperEnvironment = "HAKO_SOCKS5_TLS_INTEROP_HELPER"

func TestControlledSOCKS5TLSMTLSInterop(t *testing.T) {
	if os.Getenv(socks5TLSHelperEnvironment) == "1" {
		runControlledSOCKS5TLSMTLSHelper(t)
		return
	}
	command := exec.Command(os.Args[0], "-test.run=^TestControlledSOCKS5TLSMTLSInterop$")
	command.Env = append(os.Environ(), socks5TLSHelperEnvironment+"=1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("SOCKS5 TLS mTLS helper failed: %v\n%s", err, output)
	}
}

func runControlledSOCKS5TLSMTLSHelper(t *testing.T) {
	rootCertificate, rootKey, rootPEM := newControlledCertificateAuthority(t)
	serverCertificate, _, _ := newControlledLeafCertificate(
		t, rootCertificate, rootKey, "controlled-socks5-server", nil, []net.IP{net.IPv4(127, 0, 0, 1)}, x509.ExtKeyUsageServerAuth,
	)
	wrongServerCertificate, _, _ := newControlledLeafCertificate(
		t, rootCertificate, rootKey, "controlled-socks5-wrong-server", []string{"wrong.controlled.test"}, nil, x509.ExtKeyUsageServerAuth,
	)
	_, clientCertificatePEM, clientKeyPEM := newControlledLeafCertificate(
		t, rootCertificate, rootKey, "controlled-socks5-client", nil, nil, x509.ExtKeyUsageClientAuth,
	)
	if err := ca.AddCertificate(string(rootPEM)); err != nil {
		t.Fatalf("AddCertificate() error = %v", err)
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

	clientRoots := x509.NewCertPool()
	if !clientRoots.AppendCertsFromPEM(rootPEM) {
		t.Fatal("append client CA failed")
	}
	rawListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for SOCKS5 TLS proxy: %v", err)
	}
	port := rawListener.Addr().(*net.TCPAddr).Port
	udpRelay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		_ = rawListener.Close()
		t.Fatalf("listen for SOCKS5 UDP relay: %v", err)
	}
	tlsListener := tls.NewListener(rawListener, &tls.Config{
		Certificates: []tls.Certificate{serverCertificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientRoots,
		MinVersion:   tls.VersionTLS12,
	})
	server := &controlledSOCKS5Server{Listener: tlsListener, udp: udpRelay}
	defer server.Close()
	const (
		username = "hako-socks5-mtls-user"
		password = "hako-socks5-mtls-password"
	)
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
	go serveSOCKS5UDPRelay(udpRelay)

	proxy, err := adapter.ParseProxy(map[string]any{
		"name":        "controlled-socks5-tls-mtls",
		"type":        "socks5",
		"server":      "127.0.0.1",
		"port":        port,
		"username":    username,
		"password":    password,
		"tls":         true,
		"udp":         true,
		"certificate": string(clientCertificatePEM),
		"private-key": string(clientKeyPEM),
	})
	if err != nil {
		t.Fatalf("ParseProxy() error = %v", err)
	}
	defer proxy.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	delay, err := proxy.URLTest(ctx, target.URL, nil)
	cancel()
	if err != nil {
		t.Fatalf("SOCKS5 TLS mTLS URLTest() error = %v", err)
	}
	if delay == 0 {
		t.Fatal("SOCKS5 TLS mTLS URLTest() returned the failure sentinel delay")
	}
	if count := targetRequests.Load(); count != 1 {
		t.Fatalf("target request count = %d, want 1", count)
	}

	udpAddress := udpTarget.LocalAddr().(*net.UDPAddr)
	udpAddrPort := udpAddress.AddrPort()
	metadata := &C.Metadata{
		NetWork: C.UDP,
		Type:    C.TUN,
		DstIP:   udpAddrPort.Addr(),
		DstPort: udpAddrPort.Port(),
	}
	ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
	packetConnection, err := proxy.ListenPacketContext(ctx, metadata)
	cancel()
	if err != nil {
		t.Fatalf("TLS UDP ASSOCIATE error = %v", err)
	}
	defer packetConnection.Close()
	if err := packetConnection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetDeadline() error = %v", err)
	}
	payload := []byte("hako-controlled-socks5-tls-udp")
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

	wrongRawListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for wrong-certificate SOCKS5 proxy: %v", err)
	}
	wrongTLSListener := tls.NewListener(wrongRawListener, &tls.Config{
		Certificates: []tls.Certificate{wrongServerCertificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientRoots,
		MinVersion:   tls.VersionTLS12,
	})
	defer wrongTLSListener.Close()
	go func() {
		for {
			connection, err := wrongTLSListener.Accept()
			if err != nil {
				return
			}
			go func() {
				tlsConnection := connection.(*tls.Conn)
				if tlsConnection.Handshake() != nil {
					_ = tlsConnection.Close()
					return
				}
				serveSOCKS5Connect(tlsConnection, authenticator)
			}()
		}
	}()
	wrongHostProxy, err := adapter.ParseProxy(map[string]any{
		"name":        "controlled-socks5-wrong-host",
		"type":        "socks5",
		"server":      "127.0.0.1",
		"port":        wrongRawListener.Addr().(*net.TCPAddr).Port,
		"username":    username,
		"password":    password,
		"tls":         true,
		"certificate": string(clientCertificatePEM),
		"private-key": string(clientKeyPEM),
	})
	if err != nil {
		t.Fatalf("ParseProxy(wrong host) error = %v", err)
	}
	defer wrongHostProxy.Close()
	ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
	_, err = wrongHostProxy.URLTest(ctx, target.URL, nil)
	cancel()
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "certificate") {
		t.Fatalf("wrong-host error = %v, want certificate validation failure", err)
	}
	if count := targetRequests.Load(); count != 1 {
		t.Fatalf("wrong-host attempt leaked to target; request count = %d", count)
	}
}
