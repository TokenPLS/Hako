package hako

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/adapter"
	"github.com/TokenPLS/Hako/common/utils"
	C "github.com/TokenPLS/Hako/constant"
	IN "github.com/TokenPLS/Hako/listener/inbound"
)

func TestControlledRealityInterop(t *testing.T) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Reality X25519 key: %v", err)
	}
	privateKeyBase64 := base64.RawURLEncoding.EncodeToString(privateKey.Bytes())
	publicKeyBase64 := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes())
	const shortID = "10f897e26c4b9478"
	const serverName = "controlled-reality.example"
	var camouflageConnections atomic.Int32
	camouflage := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	camouflage.EnableHTTP2 = true
	camouflage.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			camouflageConnections.Add(1)
		}
	}
	camouflage.StartTLS()
	defer camouflage.Close()

	for _, test := range []struct {
		name     string
		protocol string
		network  string
		flow     string
		hybrid   bool
	}{
		{name: "VLESS", protocol: "vless"},
		{name: "VLESSVision", protocol: "vless", flow: "xtls-rprx-vision"},
		{name: "VLESSHybrid", protocol: "vless", hybrid: true},
		{name: "VLESSGRPCHybrid", protocol: "vless", network: "grpc", hybrid: true},
		{name: "VMess", protocol: "vmess"},
		{name: "VMessGRPC", protocol: "vmess", network: "grpc"},
		{name: "Trojan", protocol: "trojan"},
		{name: "TrojanGRPC", protocol: "trojan", network: "grpc"},
	} {
		t.Run(test.name, func(t *testing.T) {
			runControlledRealityVariant(
				t,
				test.protocol,
				test.network,
				test.flow,
				test.hybrid,
				camouflage.Listener.Addr().String(),
				serverName,
				privateKeyBase64,
				publicKeyBase64,
				shortID,
			)
		})
	}
	if camouflageConnections.Load() == 0 {
		t.Fatal("Reality never connected to the controlled TLS camouflage target")
	}
}

func runControlledRealityVariant(
	t *testing.T,
	protocol string,
	network string,
	flow string,
	hybrid bool,
	camouflageAddress string,
	serverName string,
	privateKey string,
	publicKey string,
	shortID string,
) {
	t.Helper()
	uuid := utils.NewUUIDV4().String()
	const password = "controlled-reality-trojan-password"
	const grpcService = "ControlledReality"
	realityConfig := IN.RealityConfig{
		Dest:        camouflageAddress,
		PrivateKey:  privateKey,
		ShortID:     []string{shortID},
		ServerNames: []string{serverName},
	}
	baseOption := IN.BaseOption{
		NameStr: "controlled-reality-inbound",
		Listen:  "127.0.0.1",
		Port:    "0",
	}
	var server C.InboundListener
	var err error
	switch protocol {
	case "vless":
		service := ""
		if network == "grpc" {
			service = grpcService
		}
		server, err = IN.NewVless(&IN.VlessOption{
			BaseOption:      baseOption,
			Users:           []IN.VlessUser{{Username: "controlled", UUID: uuid, Flow: "xtls-rprx-vision"}},
			GrpcServiceName: service,
			RealityConfig:   realityConfig,
		})
	case "vmess":
		service := ""
		if network == "grpc" {
			service = grpcService
		}
		server, err = IN.NewVmess(&IN.VmessOption{
			BaseOption:      baseOption,
			Users:           []IN.VmessUser{{Username: "controlled", UUID: uuid}},
			GrpcServiceName: service,
			RealityConfig:   realityConfig,
		})
	case "trojan":
		service := ""
		if network == "grpc" {
			service = grpcService
		}
		server, err = IN.NewTrojan(&IN.TrojanOption{
			BaseOption:      baseOption,
			Users:           []IN.TrojanUser{{Username: "controlled", Password: password}},
			GrpcServiceName: service,
			RealityConfig:   realityConfig,
		})
	default:
		t.Fatalf("unknown Reality protocol %q", protocol)
	}
	if err != nil {
		t.Fatalf("create %s Reality inbound: %v", protocol, err)
	}
	if err := server.Listen(&controlledReferenceTunnel{}); err != nil {
		t.Fatalf("%s Reality Listen() error = %v", protocol, err)
	}
	defer server.Close()
	serverAddress, err := netip.ParseAddrPort(server.Address())
	if err != nil {
		t.Fatalf("parse %s Reality address %q: %v", protocol, server.Address(), err)
	}
	mapping := map[string]any{
		"name":               "controlled-" + protocol + "-reality-outbound",
		"type":               protocol,
		"server":             serverAddress.Addr().String(),
		"port":               serverAddress.Port(),
		"udp":                true,
		"network":            network,
		"client-fingerprint": "chrome",
		"reality-opts": map[string]any{
			"public-key":             publicKey,
			"short-id":               shortID,
			"support-x25519mlkem768": hybrid,
		},
	}
	switch protocol {
	case "vless":
		mapping["uuid"] = uuid
		mapping["tls"] = true
		mapping["servername"] = serverName
		mapping["flow"] = flow
	case "vmess":
		mapping["uuid"] = uuid
		mapping["alterId"] = 0
		mapping["cipher"] = "auto"
		mapping["tls"] = true
		mapping["servername"] = serverName
	case "trojan":
		mapping["password"] = password
		mapping["sni"] = serverName
	}
	if network == "grpc" {
		mapping["grpc-opts"] = map[string]any{"grpc-service-name": grpcService}
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
		t.Fatalf("%s Reality URLTest() error = %v", protocol, err)
	}
	if delay == 0 {
		t.Fatalf("%s Reality URLTest() returned the failure sentinel delay", protocol)
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
	payload := []byte("hako-controlled-" + protocol + "-reality-udp-" + network + flow)
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

	if protocol == "vless" && network == "" && flow == "" && !hybrid {
		failedMapping := cloneAnyTLSMapping(mapping)
		failedMapping["name"] = "controlled-vless-reality-invalid-short-id"
		failedMapping["reality-opts"] = map[string]any{
			"public-key": publicKey,
			"short-id":   "0000000000000000",
		}
		failedProxy, err := adapter.ParseProxy(failedMapping)
		if err != nil {
			t.Fatalf("ParseProxy() invalid short ID error = %v", err)
		}
		defer failedProxy.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, err = failedProxy.URLTest(ctx, target.URL, nil)
		cancel()
		if err == nil {
			t.Fatal("invalid Reality short ID unexpectedly succeeded")
		}
		if count := targetRequests.Load(); count != 1 {
			t.Fatalf("failed Reality attempt leaked to target; request count = %d", count)
		}
	}
}
