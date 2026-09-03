//go:build with_gvisor

package hako

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	stdhttp "net/http"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	connectip "github.com/metacubex/connect-ip-go"
	http "github.com/metacubex/http"
	"github.com/TokenPLS/Hako/adapter"
	C "github.com/TokenPLS/Hako/constant"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/quic-go/quicvarint"
	"github.com/metacubex/tailscale-wireguard-go/tun"
	tailscaleNetstack "github.com/metacubex/tailscale-wireguard-go/tun/netstack"
	tls "github.com/metacubex/tls"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"
)

func TestControlledMASQUEH3Interop(t *testing.T) {
	serverCertificate, _, serverPublicKey := newControlledMASQUEIdentity(t, "localhost")
	_, clientPrivateKey, _ := newControlledMASQUEIdentity(t, "client.controlled.test")
	peerAddress := netip.MustParseAddr("10.88.0.1")
	peerAddress6 := netip.MustParseAddr("fd00:88::1")
	var targetRequests atomic.Int32
	peer := startControlledMASQUEPeer(t, &targetRequests, peerAddress, peerAddress6)
	serverPort := startControlledMASQUEServer(t, serverCertificate, peer.tun, []netip.Prefix{
		netip.MustParsePrefix("10.88.0.2/32"),
		netip.MustParsePrefix("fd00:88::2/128"),
	})

	privateKeyDER, err := x509.MarshalECPrivateKey(clientPrivateKey)
	if err != nil {
		t.Fatalf("marshal MASQUE client private key: %v", err)
	}
	publicKeyDER, err := x509.MarshalPKIXPublicKey(serverPublicKey)
	if err != nil {
		t.Fatalf("marshal MASQUE server public key: %v", err)
	}
	mapping := map[string]any{
		"name":              "controlled-masque-h3-outbound",
		"type":              "masque",
		"server":            "127.0.0.1",
		"port":              serverPort,
		"private-key":       base64.StdEncoding.EncodeToString(privateKeyDER),
		"public-key":        base64.StdEncoding.EncodeToString(publicKeyDER),
		"ip":                "10.88.0.2",
		"ipv6":              "fd00:88::2",
		"uri":               fmt.Sprintf("https://localhost:%d/connect-ip", serverPort),
		"sni":               "localhost",
		"udp":               true,
		"handshake-timeout": 10,
	}
	proxy, err := adapter.ParseProxy(mapping)
	if err != nil {
		t.Fatalf("ParseProxy() error = %v", err)
	}
	defer proxy.Close()

	wireTargetURL := "http://" + net.JoinHostPort(peerAddress.String(), strconv.Itoa(int(peer.tcpPorts[peerAddress])))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	delay, err := proxy.URLTest(ctx, wireTargetURL, nil)
	cancel()
	if err != nil {
		t.Fatalf("MASQUE H3 URLTest() error = %v", err)
	}
	if delay == 0 {
		t.Fatal("MASQUE H3 URLTest() returned the failure sentinel delay")
	}
	wireTargetURL6 := "http://" + net.JoinHostPort(peerAddress6.String(), strconv.Itoa(int(peer.tcpPorts[peerAddress6])))
	ctx, cancel = context.WithTimeout(context.Background(), 15*time.Second)
	delay, err = proxy.URLTest(ctx, wireTargetURL6, nil)
	cancel()
	if err != nil {
		t.Fatalf("MASQUE H3 IPv6 URLTest() error = %v", err)
	}
	if delay == 0 {
		t.Fatal("MASQUE H3 IPv6 URLTest() returned the failure sentinel delay")
	}
	if count := targetRequests.Load(); count != 2 {
		t.Fatalf("target request count = %d, want 2", count)
	}

	wireUDPAddrPort := netip.AddrPortFrom(peerAddress, peer.udpPorts[peerAddress])
	wireUDPAddress := net.UDPAddrFromAddrPort(wireUDPAddrPort)
	metadata := &C.Metadata{
		NetWork: C.UDP,
		Type:    C.TUN,
		DstIP:   wireUDPAddrPort.Addr(),
		DstPort: wireUDPAddrPort.Port(),
	}
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	packetConnection, err := proxy.ListenPacketContext(ctx, metadata)
	cancel()
	if err != nil {
		t.Fatalf("ListenPacketContext() error = %v", err)
	}
	if err := packetConnection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetDeadline() error = %v", err)
	}
	payload := []byte("hako-controlled-masque-h3-udp")
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

	wireUDPAddrPort6 := netip.AddrPortFrom(peerAddress6, peer.udpPorts[peerAddress6])
	wireUDPAddress6 := net.UDPAddrFromAddrPort(wireUDPAddrPort6)
	metadata6 := &C.Metadata{
		NetWork: C.UDP,
		Type:    C.TUN,
		DstIP:   wireUDPAddrPort6.Addr(),
		DstPort: wireUDPAddrPort6.Port(),
	}
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	packetConnection6, err := proxy.ListenPacketContext(ctx, metadata6)
	cancel()
	if err != nil {
		t.Fatalf("ListenPacketContext(IPv6) error = %v", err)
	}
	defer packetConnection6.Close()
	if err := packetConnection6.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetDeadline(IPv6) error = %v", err)
	}
	payload6 := []byte("hako-controlled-masque-h3-udp-ipv6")
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

	_, _, wrongPublicKey := newControlledMASQUEIdentity(t, "wrong.controlled.test")
	wrongPublicKeyDER, err := x509.MarshalPKIXPublicKey(wrongPublicKey)
	if err != nil {
		t.Fatalf("marshal wrong MASQUE public key: %v", err)
	}
	failedMapping := cloneAnyTLSMapping(mapping)
	failedMapping["name"] = "controlled-masque-invalid-peer"
	failedMapping["public-key"] = base64.StdEncoding.EncodeToString(wrongPublicKeyDER)
	failedProxy, err := adapter.ParseProxy(failedMapping)
	if err != nil {
		t.Fatalf("ParseProxy() invalid peer error = %v", err)
	}
	defer failedProxy.Close()
	ctx, cancel = context.WithTimeout(context.Background(), 4*time.Second)
	_, err = failedProxy.URLTest(ctx, wireTargetURL, nil)
	cancel()
	if err == nil {
		t.Fatal("invalid MASQUE peer key unexpectedly succeeded")
	}
	if count := targetRequests.Load(); count != 2 {
		t.Fatalf("failed MASQUE attempt leaked to target; request count = %d", count)
	}
}

func TestControlledMASQUEH2Interop(t *testing.T) {
	serverCertificate, serverPrivateKey, serverPublicKey := newControlledMASQUEIdentity(t, "localhost")
	_, clientPrivateKey, _ := newControlledMASQUEIdentity(t, "client.controlled.test")
	peerAddress := netip.MustParseAddr("10.89.0.1")
	var targetRequests atomic.Int32
	peer := startControlledMASQUEPeer(t, &targetRequests, peerAddress)
	serverPort := startControlledMASQUEH2Server(t, stdtls.Certificate{
		Certificate: serverCertificate.Certificate,
		PrivateKey:  serverPrivateKey,
		Leaf:        serverCertificate.Leaf,
	}, peer.tun)

	privateKeyDER, err := x509.MarshalECPrivateKey(clientPrivateKey)
	if err != nil {
		t.Fatalf("marshal MASQUE H2 client private key: %v", err)
	}
	publicKeyDER, err := x509.MarshalPKIXPublicKey(serverPublicKey)
	if err != nil {
		t.Fatalf("marshal MASQUE H2 server public key: %v", err)
	}
	mapping := map[string]any{
		"name":              "controlled-masque-h2-outbound",
		"type":              "masque",
		"server":            "127.0.0.1",
		"port":              serverPort,
		"private-key":       base64.StdEncoding.EncodeToString(privateKeyDER),
		"public-key":        base64.StdEncoding.EncodeToString(publicKeyDER),
		"ip":                "10.89.0.2",
		"uri":               fmt.Sprintf("https://localhost:%d/connect-ip", serverPort),
		"sni":               "localhost",
		"network":           "h2",
		"udp":               true,
		"handshake-timeout": 10,
	}
	proxy, err := adapter.ParseProxy(mapping)
	if err != nil {
		t.Fatalf("ParseProxy() error = %v", err)
	}
	defer proxy.Close()

	wireTargetURL := "http://" + net.JoinHostPort(peerAddress.String(), strconv.Itoa(int(peer.tcpPorts[peerAddress])))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	delay, err := proxy.URLTest(ctx, wireTargetURL, nil)
	cancel()
	if err != nil {
		t.Fatalf("MASQUE H2 URLTest() error = %v", err)
	}
	if delay == 0 {
		t.Fatal("MASQUE H2 URLTest() returned the failure sentinel delay")
	}
	if count := targetRequests.Load(); count != 1 {
		t.Fatalf("target request count = %d, want 1", count)
	}

	wireUDPAddrPort := netip.AddrPortFrom(peerAddress, peer.udpPorts[peerAddress])
	wireUDPAddress := net.UDPAddrFromAddrPort(wireUDPAddrPort)
	metadata := &C.Metadata{
		NetWork: C.UDP,
		Type:    C.TUN,
		DstIP:   wireUDPAddrPort.Addr(),
		DstPort: wireUDPAddrPort.Port(),
	}
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	packetConnection, err := proxy.ListenPacketContext(ctx, metadata)
	cancel()
	if err != nil {
		t.Fatalf("ListenPacketContext() error = %v", err)
	}
	defer packetConnection.Close()
	if err := packetConnection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetDeadline() error = %v", err)
	}
	payload := []byte("hako-controlled-masque-h2-udp")
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

	_, _, wrongPublicKey := newControlledMASQUEIdentity(t, "wrong.controlled.test")
	wrongPublicKeyDER, err := x509.MarshalPKIXPublicKey(wrongPublicKey)
	if err != nil {
		t.Fatalf("marshal wrong MASQUE H2 public key: %v", err)
	}
	failedMapping := cloneAnyTLSMapping(mapping)
	failedMapping["name"] = "controlled-masque-h2-invalid-peer"
	failedMapping["public-key"] = base64.StdEncoding.EncodeToString(wrongPublicKeyDER)
	failedProxy, err := adapter.ParseProxy(failedMapping)
	if err != nil {
		t.Fatalf("ParseProxy() invalid H2 peer error = %v", err)
	}
	defer failedProxy.Close()
	ctx, cancel = context.WithTimeout(context.Background(), 4*time.Second)
	_, err = failedProxy.URLTest(ctx, wireTargetURL, nil)
	cancel()
	if err == nil {
		t.Fatal("invalid MASQUE H2 peer key unexpectedly succeeded")
	}
	if count := targetRequests.Load(); count != 1 {
		t.Fatalf("failed MASQUE H2 attempt leaked to target; request count = %d", count)
	}
}

func TestControlledMASQUEH3L4ProxyInterop(t *testing.T) {
	serverCertificate, _, serverPublicKey := newControlledMASQUEIdentity(t, "localhost")
	_, clientPrivateKey, _ := newControlledMASQUEIdentity(t, "client.controlled.test")
	var targetRequests atomic.Int32
	target := stdhttp.Server{ReadHeaderTimeout: 2 * time.Second, Handler: stdhttp.HandlerFunc(func(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
		targetRequests.Add(1)
		if request.Method != stdhttp.MethodHead {
			t.Errorf("target method = %s, want HEAD", request.Method)
		}
		writer.WriteHeader(stdhttp.StatusNoContent)
	})}
	targetListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for MASQUE L4 target: %v", err)
	}
	go func() { _ = target.Serve(targetListener) }()
	t.Cleanup(func() {
		_ = target.Close()
		_ = targetListener.Close()
	})
	serverPort := startControlledMASQUEH3L4Server(t, serverCertificate, targetListener.Addr().String())

	privateKeyDER, err := x509.MarshalECPrivateKey(clientPrivateKey)
	if err != nil {
		t.Fatalf("marshal MASQUE L4 client private key: %v", err)
	}
	publicKeyDER, err := x509.MarshalPKIXPublicKey(serverPublicKey)
	if err != nil {
		t.Fatalf("marshal MASQUE L4 server public key: %v", err)
	}
	mapping := map[string]any{
		"name":              "controlled-masque-h3-l4-outbound",
		"type":              "masque",
		"server":            "127.0.0.1",
		"port":              serverPort,
		"private-key":       base64.StdEncoding.EncodeToString(privateKeyDER),
		"public-key":        base64.StdEncoding.EncodeToString(publicKeyDER),
		"sni":               "localhost",
		"network":           "h3-l4proxy",
		"udp":               true,
		"handshake-timeout": 10,
	}
	proxy, err := adapter.ParseProxy(mapping)
	if err != nil {
		t.Fatalf("ParseProxy() error = %v", err)
	}
	defer proxy.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	delay, err := proxy.URLTest(ctx, "http://"+targetListener.Addr().String(), nil)
	cancel()
	if err != nil {
		t.Fatalf("MASQUE H3 L4 URLTest() error = %v", err)
	}
	if delay == 0 {
		t.Fatal("MASQUE H3 L4 URLTest() returned the failure sentinel delay")
	}
	if count := targetRequests.Load(); count != 1 {
		t.Fatalf("target request count = %d, want 1", count)
	}

	metadata := &C.Metadata{
		NetWork: C.UDP,
		Type:    C.TUN,
		DstIP:   netip.MustParseAddr("127.0.0.1"),
		DstPort: 9,
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	_, err = proxy.ListenPacketContext(ctx, metadata)
	cancel()
	if err == nil {
		t.Fatal("MASQUE H3 L4 proxy unexpectedly accepted UDP")
	}

	_, _, wrongPublicKey := newControlledMASQUEIdentity(t, "wrong.controlled.test")
	wrongPublicKeyDER, err := x509.MarshalPKIXPublicKey(wrongPublicKey)
	if err != nil {
		t.Fatalf("marshal wrong MASQUE L4 public key: %v", err)
	}
	failedMapping := cloneAnyTLSMapping(mapping)
	failedMapping["name"] = "controlled-masque-h3-l4-invalid-peer"
	failedMapping["public-key"] = base64.StdEncoding.EncodeToString(wrongPublicKeyDER)
	failedProxy, err := adapter.ParseProxy(failedMapping)
	if err != nil {
		t.Fatalf("ParseProxy() invalid L4 peer error = %v", err)
	}
	defer failedProxy.Close()
	ctx, cancel = context.WithTimeout(context.Background(), 4*time.Second)
	_, err = failedProxy.URLTest(ctx, "http://"+targetListener.Addr().String(), nil)
	cancel()
	if err == nil {
		t.Fatal("invalid MASQUE H3 L4 peer key unexpectedly succeeded")
	}
	if count := targetRequests.Load(); count != 1 {
		t.Fatalf("failed MASQUE H3 L4 attempt leaked to target; request count = %d", count)
	}
}

func newControlledMASQUEIdentity(t *testing.T, commonName string) (tls.Certificate, *ecdsa.PrivateKey, *ecdsa.PublicKey) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate MASQUE %s key: %v", commonName, err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 120)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		t.Fatalf("generate MASQUE %s serial: %v", commonName, err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{commonName},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create MASQUE %s certificate: %v", commonName, err)
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		t.Fatalf("parse MASQUE %s certificate: %v", commonName, err)
	}
	return tls.Certificate{
		Certificate: [][]byte{certificateDER},
		PrivateKey:  privateKey,
		Leaf:        certificate,
	}, privateKey, &privateKey.PublicKey
}

type controlledMASQUEPeer struct {
	tun      tun.Device
	tcpPorts map[netip.Addr]uint16
	udpPorts map[netip.Addr]uint16
}

func startControlledMASQUEPeer(t *testing.T, targetRequests *atomic.Int32, peerAddresses ...netip.Addr) controlledMASQUEPeer {
	t.Helper()
	peerTUN, peerNetwork, err := tailscaleNetstack.CreateNetTUN(peerAddresses, nil, 1280)
	if err != nil {
		t.Fatalf("create MASQUE peer netstack: %v", err)
	}
	t.Cleanup(func() { _ = peerTUN.Close() })
	peer := controlledMASQUEPeer{
		tun:      peerTUN,
		tcpPorts: make(map[netip.Addr]uint16, len(peerAddresses)),
		udpPorts: make(map[netip.Addr]uint16, len(peerAddresses)),
	}
	handler := stdhttp.HandlerFunc(func(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
		targetRequests.Add(1)
		if request.Method != stdhttp.MethodHead {
			t.Errorf("target method = %s, want HEAD", request.Method)
		}
		writer.WriteHeader(stdhttp.StatusNoContent)
	})
	for _, peerAddress := range peerAddresses {
		tcpListener, err := peerNetwork.ListenTCPAddrPort(netip.AddrPortFrom(peerAddress, 0))
		if err != nil {
			t.Fatalf("listen on MASQUE peer %s TCP stack: %v", peerAddress, err)
		}
		t.Cleanup(func() { _ = tcpListener.Close() })
		httpServer := &stdhttp.Server{ReadHeaderTimeout: 2 * time.Second, Handler: handler}
		go func() { _ = httpServer.Serve(tcpListener) }()
		t.Cleanup(func() { _ = httpServer.Close() })
		peer.tcpPorts[peerAddress] = tcpListener.Addr().(*net.TCPAddr).AddrPort().Port()

		udpConnection, err := peerNetwork.ListenUDPAddrPort(netip.AddrPortFrom(peerAddress, 0))
		if err != nil {
			t.Fatalf("listen on MASQUE peer %s UDP stack: %v", peerAddress, err)
		}
		t.Cleanup(func() { _ = udpConnection.Close() })
		go serveControlledWireGuardUDPEcho(udpConnection)
		peer.udpPorts[peerAddress] = udpConnection.LocalAddr().(*net.UDPAddr).AddrPort().Port()
	}
	return peer
}

func startControlledMASQUEServer(t *testing.T, certificate tls.Certificate, peerTUN tun.Device, clientPrefixes []netip.Prefix) int {
	t.Helper()
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen for MASQUE HTTP/3 server: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	serverErrors := make(chan error, 8)
	serverURI := fmt.Sprintf("https://localhost:%d/connect-ip", listener.LocalAddr().(*net.UDPAddr).Port)
	template := uritemplate.MustNew(serverURI)
	mux := http.NewServeMux()
	mux.HandleFunc("/connect-ip", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodConnect || request.Proto != "cf-connect-ip" {
			writer.WriteHeader(http.StatusBadRequest)
			select {
			case serverErrors <- fmt.Errorf("unexpected MASQUE request: method=%s protocol=%s", request.Method, request.Proto):
			default:
			}
			return
		}
		standardRequest := request.Clone(request.Context())
		standardRequest.Proto = "connect-ip"
		parsedRequest, err := connectip.ParseRequest(standardRequest, template)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			select {
			case serverErrors <- err:
			default:
			}
			return
		}
		proxyConnection, err := (&connectip.Proxy{}).Proxy(writer, parsedRequest)
		if err != nil {
			select {
			case serverErrors <- err:
			default:
			}
			return
		}
		setupContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := proxyConnection.AssignAddresses(setupContext, clientPrefixes); err != nil {
			select {
			case serverErrors <- err:
			default:
			}
			return
		}
		if err := proxyConnection.AdvertiseRoute(setupContext, []connectip.IPRoute{{
			StartIP: netip.IPv4Unspecified(),
			EndIP:   netip.MustParseAddr("255.255.255.255"),
		}, {
			StartIP: netip.IPv6Unspecified(),
			EndIP:   netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
		}}); err != nil {
			select {
			case serverErrors <- err:
			default:
			}
			return
		}
		bridgeControlledMASQUE(proxyConnection, peerTUN, serverErrors)
	})
	server := &http3.Server{
		Handler:         mux,
		EnableDatagrams: true,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate},
			NextProtos:   []string{http3.NextProtoH3},
		},
	}
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			select {
			case serverErrors <- err:
			default:
			}
		}
	}()
	t.Cleanup(func() {
		_ = server.Close()
		select {
		case err := <-serverErrors:
			if err != nil {
				t.Errorf("controlled MASQUE server error: %v", err)
			}
		default:
		}
	})
	return listener.LocalAddr().(*net.UDPAddr).Port
}

func startControlledMASQUEH2Server(t *testing.T, certificate stdtls.Certificate, peerTUN tun.Device) int {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for MASQUE HTTP/2 server: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	serverErrors := make(chan error, 8)
	handler := stdhttp.HandlerFunc(func(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
		if request.Method != stdhttp.MethodConnect || request.Header.Get("cf-connect-proto") != "cf-connect-ip" {
			writer.WriteHeader(stdhttp.StatusBadRequest)
			select {
			case serverErrors <- fmt.Errorf("unexpected MASQUE H2 request: method=%s cf-connect-proto=%q", request.Method, request.Header.Get("cf-connect-proto")):
			default:
			}
			return
		}
		writer.WriteHeader(stdhttp.StatusOK)
		if flusher, ok := writer.(stdhttp.Flusher); ok {
			flusher.Flush()
		}
		bridgeControlledMASQUEH2(request.Body, writer, peerTUN, serverErrors)
	})
	tlsConfig := &stdtls.Config{
		Certificates: []stdtls.Certificate{certificate},
		NextProtos:   []string{"h2"},
		MinVersion:   stdtls.VersionTLS13,
	}
	h2Server := &http2.Server{}
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					select {
					case serverErrors <- err:
					default:
					}
				}
				return
			}
			go func(connection net.Conn) {
				tlsConnection := stdtls.Server(connection, tlsConfig)
				handshakeContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := tlsConnection.HandshakeContext(handshakeContext); err != nil {
					_ = connection.Close()
					return
				}
				h2Server.ServeConn(tlsConnection, &http2.ServeConnOpts{Handler: handler})
			}(connection)
		}
	}()
	t.Cleanup(func() {
		select {
		case err := <-serverErrors:
			if err != nil {
				t.Errorf("controlled MASQUE H2 server error: %v", err)
			}
		default:
		}
	})
	return listener.Addr().(*net.TCPAddr).Port
}

func startControlledMASQUEH3L4Server(t *testing.T, certificate tls.Certificate, targetAddress string) int {
	t.Helper()
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen for MASQUE H3 L4 server: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	serverErrors := make(chan error, 8)
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodConnect || request.Host != targetAddress {
			writer.WriteHeader(http.StatusForbidden)
			select {
			case serverErrors <- fmt.Errorf("unexpected MASQUE H3 L4 request: method=%s target=%q", request.Method, request.Host):
			default:
			}
			return
		}
		target, err := net.DialTimeout("tcp", targetAddress, 2*time.Second)
		if err != nil {
			writer.WriteHeader(http.StatusBadGateway)
			select {
			case serverErrors <- err:
			default:
			}
			return
		}
		defer target.Close()
		writer.WriteHeader(http.StatusOK)
		streamer, ok := writer.(http3.HTTPStreamer)
		if !ok {
			select {
			case serverErrors <- errors.New("MASQUE H3 response writer does not expose HTTP stream"):
			default:
			}
			return
		}
		stream := streamer.HTTPStream()
		done := make(chan struct{}, 2)
		go func() {
			_, _ = io.Copy(target, stream)
			done <- struct{}{}
		}()
		go func() {
			_, _ = io.Copy(stream, target)
			done <- struct{}{}
		}()
		<-done
	})
	server := &http3.Server{
		Handler:         handler,
		EnableDatagrams: true,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate},
			NextProtos:   []string{http3.NextProtoH3},
		},
	}
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			select {
			case serverErrors <- err:
			default:
			}
		}
	}()
	t.Cleanup(func() {
		_ = server.Close()
		select {
		case err := <-serverErrors:
			if err != nil {
				t.Errorf("controlled MASQUE H3 L4 server error: %v", err)
			}
		default:
		}
	})
	return listener.LocalAddr().(*net.UDPAddr).Port
}

func bridgeControlledMASQUEH2(requestBody io.Reader, writer stdhttp.ResponseWriter, peerTUN tun.Device, serverErrors chan<- error) {
	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		reader := quicvarint.NewReader(requestBody)
		for {
			capsuleType, err := quicvarint.Read(reader)
			if err != nil {
				return
			}
			payloadLength, err := quicvarint.Read(reader)
			if err != nil {
				return
			}
			if payloadLength > 64*1024 {
				select {
				case serverErrors <- fmt.Errorf("MASQUE H2 capsule too large: %d", payloadLength):
				default:
				}
				return
			}
			packet := make([]byte, int(payloadLength))
			if _, err := io.ReadFull(reader, packet); err != nil {
				return
			}
			if capsuleType != 0 {
				continue
			}
			if _, err := peerTUN.Write([][]byte{packet}, 0); err != nil {
				return
			}
		}
	}()

	buffer := make([]byte, 64*1024)
	buffers := [][]byte{buffer}
	sizes := []int{0}
	for {
		if _, err := peerTUN.Read(buffers, sizes, 0); err != nil {
			return
		}
		frame := quicvarint.Append(nil, 0)
		frame = quicvarint.Append(frame, uint64(sizes[0]))
		frame = append(frame, buffer[:sizes[0]]...)
		if _, err := writer.Write(frame); err != nil {
			return
		}
		if flusher, ok := writer.(stdhttp.Flusher); ok {
			flusher.Flush()
		}
		select {
		case <-requestDone:
			return
		default:
		}
	}
}

func bridgeControlledMASQUE(connection *connectip.Conn, peerTUN tun.Device, serverErrors chan<- error) {
	go func() {
		for {
			packet, err := connection.ReadPacket()
			if err != nil {
				return
			}
			if _, err := peerTUN.Write([][]byte{packet}, 0); err != nil {
				select {
				case serverErrors <- err:
				default:
				}
				return
			}
		}
	}()
	go func() {
		buffer := make([]byte, 64*1024)
		buffers := [][]byte{buffer}
		sizes := []int{0}
		for {
			if _, err := peerTUN.Read(buffers, sizes, 0); err != nil {
				return
			}
			if _, err := connection.WritePacket(buffer[:sizes[0]]); err != nil {
				return
			}
		}
	}()
}
