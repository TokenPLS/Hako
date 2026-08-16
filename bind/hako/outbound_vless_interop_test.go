package hako

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/adapter"
	"github.com/TokenPLS/Hako/common/utils"
	"github.com/TokenPLS/Hako/component/ca"
	C "github.com/TokenPLS/Hako/constant"
	IN "github.com/TokenPLS/Hako/listener/inbound"
	"github.com/TokenPLS/Hako/transport/vless/encryption"
)

func TestControlledVLESSInterop(t *testing.T) {
	serverCertificate, serverPrivateKey, serverFingerprint, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatalf("generate server certificate: %v", err)
	}
	clientCertificate, clientPrivateKey, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatalf("generate client certificate: %v", err)
	}
	seedBase64, clientBase64, _, err := encryption.GenMLKEM768("")
	if err != nil {
		t.Fatalf("generate ML-KEM key material: %v", err)
	}
	privateKeyBase64, passwordBase64, _, err := encryption.GenX25519("")
	if err != nil {
		t.Fatalf("generate X25519 key material: %v", err)
	}
	decryption := "mlkem768x25519plus.native.600s." + privateKeyBase64 + "." + seedBase64
	encryptionValue := "mlkem768x25519plus.native.0rtt." + passwordBase64 + "." + clientBase64
	uuid := utils.NewUUIDV4().String()

	for _, test := range []struct {
		name        string
		network     string
		tls         bool
		flow        string
		wsPath      string
		grpcService string
		httpUpgrade bool
		decryption  string
		encryption  string
	}{
		{name: "TCP"},
		{name: "TLSMTLSVision", tls: true, flow: "xtls-rprx-vision"},
		{name: "WebSocketHTTPUpgrade", network: "ws", wsPath: "/controlled-vless", httpUpgrade: true},
		{name: "GRPCTLS", network: "grpc", tls: true, grpcService: "ControlledVLESS"},
		{name: "NativeEncryption", decryption: decryption, encryption: encryptionValue},
	} {
		t.Run(test.name, func(t *testing.T) {
			runControlledVLESSVariant(
				t,
				uuid,
				test.network,
				test.tls,
				test.flow,
				test.wsPath,
				test.grpcService,
				test.httpUpgrade,
				test.decryption,
				test.encryption,
				serverCertificate,
				serverPrivateKey,
				serverFingerprint,
				clientCertificate,
				clientPrivateKey,
			)
		})
	}
}

func runControlledVLESSVariant(
	t *testing.T,
	uuid string,
	network string,
	useTLS bool,
	flow string,
	wsPath string,
	grpcService string,
	httpUpgrade bool,
	decryption string,
	encryptionValue string,
	serverCertificate string,
	serverPrivateKey string,
	serverFingerprint string,
	clientCertificate string,
	clientPrivateKey string,
) {
	t.Helper()
	inboundOptions := &IN.VlessOption{
		BaseOption: IN.BaseOption{
			NameStr: "controlled-vless-inbound",
			Listen:  "127.0.0.1",
			Port:    "0",
		},
		Users:           []IN.VlessUser{{Username: "controlled", UUID: uuid, Flow: "xtls-rprx-vision"}},
		Decryption:      decryption,
		WsPath:          wsPath,
		GrpcServiceName: grpcService,
		AllowInsecure:   !useTLS && decryption == "",
	}
	if useTLS {
		inboundOptions.Certificate = serverCertificate
		inboundOptions.PrivateKey = serverPrivateKey
		inboundOptions.ClientAuthCert = clientCertificate
	}
	server, err := IN.NewVless(inboundOptions)
	if err != nil {
		t.Fatalf("NewVless() error = %v", err)
	}
	if err := server.Listen(&controlledReferenceTunnel{}); err != nil {
		t.Fatalf("VLESS Listen() error = %v", err)
	}
	defer server.Close()
	serverAddress, err := netip.ParseAddrPort(server.Address())
	if err != nil {
		t.Fatalf("parse VLESS address %q: %v", server.Address(), err)
	}
	mapping := map[string]any{
		"name":       "controlled-vless-outbound",
		"type":       "vless",
		"server":     serverAddress.Addr().String(),
		"port":       serverAddress.Port(),
		"uuid":       uuid,
		"flow":       flow,
		"udp":        true,
		"encryption": encryptionValue,
	}
	if network != "" {
		mapping["network"] = network
	}
	if wsPath != "" {
		mapping["ws-opts"] = map[string]any{
			"path":                         wsPath,
			"v2ray-http-upgrade":           httpUpgrade,
			"v2ray-http-upgrade-fast-open": httpUpgrade,
		}
	}
	if grpcService != "" {
		mapping["grpc-opts"] = map[string]any{"grpc-service-name": grpcService}
	}
	if useTLS {
		mapping["tls"] = true
		mapping["fingerprint"] = serverFingerprint
		mapping["certificate"] = clientCertificate
		mapping["private-key"] = clientPrivateKey
	}
	proxy, err := adapter.ParseProxy(mapping)
	if err != nil {
		t.Fatalf("ParseProxy() error = %v", err)
	}
	defer proxy.Close()

	target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
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
		t.Fatalf("VLESS URLTest() error = %v", err)
	}
	if delay == 0 {
		t.Fatal("VLESS URLTest() returned the failure sentinel delay")
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
	payload := []byte("hako-controlled-vless-udp-" + network + flow)
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
}
