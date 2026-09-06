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
)

func TestControlledVMessInterop(t *testing.T) {
	serverCertificate, serverPrivateKey, serverFingerprint, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatalf("generate server certificate: %v", err)
	}
	clientCertificate, clientPrivateKey, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatalf("generate client certificate: %v", err)
	}
	uuid := utils.NewUUIDV4().String()

	for _, test := range []struct {
		name        string
		network     string
		tls         bool
		wsPath      string
		grpcService string
		httpUpgrade bool
		mkcpSeed    string
		mkcpHeader  string
	}{
		{name: "TCP"},
		{name: "TLSMTLS", tls: true},
		{name: "WebSocketHTTPUpgrade", network: "ws", wsPath: "/controlled-vmess", httpUpgrade: true},
		{name: "GRPCTLS", network: "grpc", tls: true, grpcService: "ControlledVMess"},
		{name: "MKCPSeedWireGuard", network: "mkcp", mkcpSeed: "controlled-vmess-mkcp", mkcpHeader: "wireguard"},
	} {
		t.Run(test.name, func(t *testing.T) {
			runControlledVMessVariant(
				t,
				uuid,
				test.network,
				test.tls,
				test.wsPath,
				test.grpcService,
				test.httpUpgrade,
				test.mkcpSeed,
				test.mkcpHeader,
				serverCertificate,
				serverPrivateKey,
				serverFingerprint,
				clientCertificate,
				clientPrivateKey,
			)
		})
	}
}

func runControlledVMessVariant(
	t *testing.T,
	uuid string,
	network string,
	useTLS bool,
	wsPath string,
	grpcService string,
	httpUpgrade bool,
	mkcpSeed string,
	mkcpHeader string,
	serverCertificate string,
	serverPrivateKey string,
	serverFingerprint string,
	clientCertificate string,
	clientPrivateKey string,
) {
	t.Helper()
	inboundOptions := &IN.VmessOption{
		BaseOption: IN.BaseOption{
			NameStr: "controlled-vmess-inbound",
			Listen:  "127.0.0.1",
			Port:    "0",
		},
		Users:           []IN.VmessUser{{Username: "controlled", UUID: uuid, AlterID: 0}},
		WsPath:          wsPath,
		GrpcServiceName: grpcService,
	}
	if network == "mkcp" {
		inboundOptions.MKCPConfig = IN.MKCPConfig{
			Enable: true,
			Seed:   mkcpSeed,
			Header: mkcpHeader,
		}
	}
	if useTLS {
		inboundOptions.Certificate = serverCertificate
		inboundOptions.PrivateKey = serverPrivateKey
		inboundOptions.ClientAuthCert = clientCertificate
	}
	server, err := IN.NewVmess(inboundOptions)
	if err != nil {
		t.Fatalf("NewVmess() error = %v", err)
	}
	if err := server.Listen(&controlledReferenceTunnel{}); err != nil {
		t.Fatalf("VMess Listen() error = %v", err)
	}
	defer server.Close()
	serverAddress, err := netip.ParseAddrPort(server.Address())
	if err != nil {
		t.Fatalf("parse VMess address %q: %v", server.Address(), err)
	}
	mapping := map[string]any{
		"name":    "controlled-vmess-outbound",
		"type":    "vmess",
		"server":  serverAddress.Addr().String(),
		"port":    serverAddress.Port(),
		"uuid":    uuid,
		"alterId": 0,
		"cipher":  "auto",
		"udp":     true,
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
	if network == "mkcp" {
		mapping["mkcp-opts"] = map[string]any{"seed": mkcpSeed, "header": mkcpHeader}
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
		t.Fatalf("VMess URLTest() error = %v", err)
	}
	if delay == 0 {
		t.Fatal("VMess URLTest() returned the failure sentinel delay")
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
	payload := []byte("hako-controlled-vmess-udp-" + network)
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
