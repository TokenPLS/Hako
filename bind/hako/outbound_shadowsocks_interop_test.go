package hako

import (
	"bytes"
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/adapter"
	C "github.com/TokenPLS/Hako/constant"
	IN "github.com/TokenPLS/Hako/listener/inbound"
)

func TestControlledShadowsocksInterop(t *testing.T) {
	password2022 := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	for _, test := range []struct {
		name          string
		cipher        string
		password      string
		udp           bool
		simpleObfs    IN.SimpleObfs
		plugin        string
		pluginOptions map[string]any
	}{
		{
			name:     "AEAD",
			cipher:   "aes-128-gcm",
			password: "controlled-aead-password",
			udp:      true,
		},
		{
			name:     "2022",
			cipher:   "2022-blake3-aes-128-gcm",
			password: password2022,
			udp:      true,
		},
		{
			name:       "SimpleObfsHTTP",
			cipher:     "aes-128-gcm",
			password:   "controlled-plugin-password",
			simpleObfs: IN.SimpleObfs{Enable: true, Mode: "http"},
			plugin:     "obfs",
			pluginOptions: map[string]any{
				"mode": "http",
				"host": "controlled.test",
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			runControlledShadowsocksVariant(t, test.cipher, test.password, test.udp, test.simpleObfs, test.plugin, test.pluginOptions)
		})
	}
}

func runControlledShadowsocksVariant(
	t *testing.T,
	cipher string,
	password string,
	testUDP bool,
	simpleObfs IN.SimpleObfs,
	plugin string,
	pluginOptions map[string]any,
) {
	t.Helper()
	tunnel := &controlledReferenceTunnel{}
	port := reserveControlledTCPPort(t)
	inbound, err := IN.NewShadowSocks(&IN.ShadowSocksOption{
		BaseOption: IN.BaseOption{
			NameStr: "controlled-shadowsocks-inbound",
			Listen:  "127.0.0.1",
			Port:    strconv.Itoa(port),
		},
		Password:   password,
		Cipher:     cipher,
		UDP:        testUDP,
		SimpleObfs: simpleObfs,
	})
	if err != nil {
		t.Fatalf("NewShadowSocks() error = %v", err)
	}
	if err := inbound.Listen(tunnel); err != nil {
		t.Fatalf("Shadowsocks Listen() error = %v", err)
	}
	defer inbound.Close()

	mapping := map[string]any{
		"name":     "controlled-shadowsocks-outbound",
		"type":     "ss",
		"server":   "127.0.0.1",
		"port":     port,
		"password": password,
		"cipher":   cipher,
		"udp":      testUDP,
	}
	if plugin != "" {
		mapping["plugin"] = plugin
		mapping["plugin-opts"] = pluginOptions
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
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	delay, err := proxy.URLTest(ctx, target.URL, nil)
	cancel()
	if err != nil {
		t.Fatalf("Shadowsocks URLTest() error = %v", err)
	}
	if delay == 0 {
		t.Fatal("Shadowsocks URLTest() returned the failure sentinel delay")
	}

	if !testUDP {
		return
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
	ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
	packetConnection, err := proxy.ListenPacketContext(ctx, metadata)
	cancel()
	if err != nil {
		t.Fatalf("ListenPacketContext() error = %v", err)
	}
	defer packetConnection.Close()
	if err := packetConnection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetDeadline() error = %v", err)
	}
	payload := []byte("hako-controlled-shadowsocks-udp-" + cipher)
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

type controlledReferenceTunnel struct{}

func (*controlledReferenceTunnel) HandleTCPConn(client net.Conn, metadata *C.Metadata) {
	defer client.Close()
	upstream, err := net.DialTimeout("tcp", metadata.RemoteAddress(), 2*time.Second)
	if err != nil {
		return
	}
	defer upstream.Close()
	relayControlledTCP(client, upstream)
}

func (*controlledReferenceTunnel) HandleUDPPacket(packet C.UDPPacket, metadata *C.Metadata) {
	payload := bytes.Clone(packet.Data())
	go func() {
		defer packet.Drop()
		upstream, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(metadata.AddrPort()))
		if err != nil {
			return
		}
		defer upstream.Close()
		_ = upstream.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := upstream.Write(payload); err != nil {
			return
		}
		response := make([]byte, 64*1024)
		n, source, err := upstream.ReadFromUDP(response)
		if err != nil {
			return
		}
		_, _ = packet.WriteBack(response[:n], source)
	}()
}

func (*controlledReferenceTunnel) NatTable() C.NatTable {
	return nil
}

func reserveControlledTCPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve controlled port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatalf("release controlled port: %v", err)
	}
	return port
}
