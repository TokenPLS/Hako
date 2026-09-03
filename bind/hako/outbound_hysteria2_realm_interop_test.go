package hako

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/adapter"
	"github.com/TokenPLS/Hako/component/ca"
	C "github.com/TokenPLS/Hako/constant"
	IN "github.com/TokenPLS/Hako/listener/inbound"
)

func TestControlledHysteria2RealmInterop(t *testing.T) {
	pinUnifiedDelayOff(t)
	stunAddress, stunRequests := startControlledRealmSTUNServer(t)
	realmCertificate, realmPrivateKey, realmFingerprint, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatalf("generate Realm server certificate: %v", err)
	}
	realmClientCertificate, realmClientPrivateKey, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatalf("generate Realm client certificate: %v", err)
	}
	realmServer, err := IN.NewHysteria2RealmServer(&IN.Hysteria2RealmServerOption{
		BaseOption: IN.BaseOption{
			NameStr: "controlled-hysteria2-realm-server",
			Listen:  "127.0.0.1",
			Port:    "0",
		},
		Token:            "controlled-realm-token",
		MaxRealms:        4,
		MaxRealmsPerIP:   4,
		RealmNamePattern: `^[a-z0-9-]+$`,
		Certificate:      realmCertificate,
		PrivateKey:       realmPrivateKey,
		ClientAuthCert:   realmClientCertificate,
	})
	if err != nil {
		t.Fatalf("NewHysteria2RealmServer() error = %v", err)
	}
	if err := realmServer.Listen(&controlledReferenceTunnel{}); err != nil {
		t.Fatalf("Realm Listen() error = %v", err)
	}
	defer realmServer.Close()
	realmAddress, err := netip.ParseAddrPort(realmServer.Address())
	if err != nil {
		t.Fatalf("parse Realm address %q: %v", realmServer.Address(), err)
	}
	realmURL := "https://" + realmAddress.String()

	hy2Certificate, hy2PrivateKey, hy2Fingerprint, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatalf("generate Hysteria2 certificate: %v", err)
	}
	const password = "controlled-hysteria2-realm-password"
	const realmID = "controlled-realm"
	hy2Server, err := IN.NewHysteria2(&IN.Hysteria2Option{
		BaseOption: IN.BaseOption{
			NameStr: "controlled-hysteria2-realm-inbound",
			Listen:  "127.0.0.1",
			Port:    "0",
		},
		Users:       map[string]string{"controlled": password},
		Certificate: hy2Certificate,
		PrivateKey:  hy2PrivateKey,
		RealmOpts: IN.Hysteria2RealmOption{
			Enable:      true,
			ServerURL:   realmURL,
			Token:       "controlled-realm-token",
			RealmID:     realmID,
			STUNServers: []string{stunAddress},
			Fingerprint: realmFingerprint,
			Certificate: realmClientCertificate,
			PrivateKey:  realmClientPrivateKey,
		},
	})
	if err != nil {
		t.Fatalf("NewHysteria2() Realm error = %v", err)
	}
	if err := hy2Server.Listen(&controlledReferenceTunnel{}); err != nil {
		t.Fatalf("Hysteria2 Realm Listen() error = %v", err)
	}
	defer hy2Server.Close()

	unreachablePort := reserveControlledTCPPort(t)
	mapping := map[string]any{
		"name":        "controlled-hysteria2-realm-outbound",
		"type":        "hysteria2",
		"server":      "127.0.0.1",
		"port":        unreachablePort,
		"password":    password,
		"fingerprint": hy2Fingerprint,
		"realm-opts": map[string]any{
			"enable":       true,
			"server-url":   realmURL,
			"token":        "controlled-realm-token",
			"realm-id":     realmID,
			"stun-servers": []string{stunAddress},
			"fingerprint":  realmFingerprint,
			"certificate":  realmClientCertificate,
			"private-key":  realmClientPrivateKey,
		},
	}
	proxy, err := adapter.ParseProxy(mapping)
	if err != nil {
		t.Fatalf("ParseProxy() Realm error = %v", err)
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
	var delay uint16
	deadline := time.Now().Add(10 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		delay, err = proxy.URLTest(ctx, target.URL, nil)
		cancel()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Hysteria2 Realm URLTest() error = %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if delay == 0 {
		t.Fatal("Hysteria2 Realm URLTest() returned the failure sentinel delay")
	}
	if count := targetRequests.Load(); count != 1 {
		t.Fatalf("target request count = %d, want 1", count)
	}
	if stunRequests.Load() < 2 {
		t.Fatalf("controlled STUN requests = %d, want requests from both Realm peers", stunRequests.Load())
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	packetConnection, err := proxy.ListenPacketContext(ctx, metadata)
	cancel()
	if err != nil {
		t.Fatalf("ListenPacketContext() error = %v", err)
	}
	defer packetConnection.Close()
	payload := []byte("hako-controlled-hysteria2-realm-udp")
	if _, err := packetConnection.WriteTo(payload, udpAddress); err != nil {
		t.Fatalf("WriteTo() error = %v", err)
	}
	buffer := make([]byte, 64*1024)
	type packetResult struct {
		n      int
		source net.Addr
		err    error
	}
	result := make(chan packetResult, 1)
	go func() {
		n, source, err := packetConnection.ReadFrom(buffer)
		result <- packetResult{n: n, source: source, err: err}
	}()
	var n int
	var source net.Addr
	select {
	case response := <-result:
		if response.err != nil {
			t.Fatalf("ReadFrom() error = %v", response.err)
		}
		n, source = response.n, response.source
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Hysteria2 Realm UDP response")
	}
	if !bytes.Equal(buffer[:n], payload) || source.String() != udpAddress.String() {
		t.Fatalf("UDP response = (%q, %v), want (%q, %v)", buffer[:n], source, payload, udpAddress)
	}

	failedMapping := cloneAnyTLSMapping(mapping)
	failedMapping["name"] = "controlled-hysteria2-realm-invalid-token"
	failedRealmOptions := cloneAnyTLSMapping(mapping["realm-opts"].(map[string]any))
	failedRealmOptions["token"] = "wrong-token"
	failedMapping["realm-opts"] = failedRealmOptions
	failedProxy, err := adapter.ParseProxy(failedMapping)
	if err != nil {
		t.Fatalf("ParseProxy() invalid Realm token error = %v", err)
	}
	defer failedProxy.Close()
	ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
	_, err = failedProxy.URLTest(ctx, target.URL, nil)
	cancel()
	if err == nil {
		t.Fatal("invalid Hysteria2 Realm token unexpectedly succeeded")
	}
	if count := targetRequests.Load(); count != 1 {
		t.Fatalf("failed Realm attempt leaked to target; request count = %d", count)
	}
}

func startControlledRealmSTUNServer(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen for controlled STUN: %v", err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	var requests atomic.Int32
	go func() {
		buffer := make([]byte, 1500)
		for {
			n, remote, err := connection.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			if n < 20 || binary.BigEndian.Uint32(buffer[4:8]) != 0x2112a442 {
				continue
			}
			requests.Add(1)
			response := make([]byte, 32)
			binary.BigEndian.PutUint16(response[0:2], 0x0101)
			binary.BigEndian.PutUint16(response[2:4], 12)
			binary.BigEndian.PutUint32(response[4:8], 0x2112a442)
			copy(response[8:20], buffer[8:20])
			binary.BigEndian.PutUint16(response[20:22], 0x0020)
			binary.BigEndian.PutUint16(response[22:24], 8)
			response[25] = 0x01
			binary.BigEndian.PutUint16(response[26:28], uint16(remote.Port)^0x2112)
			address := remote.IP.To4()
			binary.BigEndian.PutUint32(response[28:32], binary.BigEndian.Uint32(address)^0x2112a442)
			_, _ = connection.WriteToUDP(response, remote)
		}
	}()
	return connection.LocalAddr().String(), &requests
}
