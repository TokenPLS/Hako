package hako

import (
	"bytes"
	"context"
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

func TestControlledSnellInterop(t *testing.T) {
	for _, test := range []struct {
		name     string
		version  int
		udp      bool
		obfsMode string
	}{
		{name: "v1", version: 1},
		{name: "v2", version: 2},
		{name: "v3", version: 3, udp: true},
		{name: "v4", version: 4, udp: true},
		{name: "v5", version: 5, udp: true},
		{name: "v5-http-obfs", version: 5, udp: true, obfsMode: "http"},
		{name: "v5-tls-obfs", version: 5, udp: true, obfsMode: "tls"},
	} {
		t.Run(test.name, func(t *testing.T) {
			runControlledSnellVariant(t, test.version, test.udp, test.obfsMode)
		})
	}
}

func runControlledSnellVariant(t *testing.T, version int, testUDP bool, obfsMode string) {
	t.Helper()
	port := reserveControlledTCPPort(t)
	const psk = "controlled-snell-psk"
	server, err := IN.NewSnell(&IN.SnellOption{
		BaseOption: IN.BaseOption{
			NameStr: "controlled-snell-inbound",
			Listen:  "127.0.0.1",
			Port:    strconv.Itoa(port),
		},
		Psk:     psk,
		Version: version,
		UDP:     testUDP,
		ObfsOpts: IN.SnellObfsOption{
			Mode: obfsMode,
			Host: "controlled.test",
		},
	})
	if err != nil {
		t.Fatalf("NewSnell() error = %v", err)
	}
	if err := server.Listen(&controlledReferenceTunnel{}); err != nil {
		t.Fatalf("Snell Listen() error = %v", err)
	}
	defer server.Close()
	mapping := map[string]any{
		"name":    "controlled-snell-outbound",
		"type":    "snell",
		"server":  "127.0.0.1",
		"port":    port,
		"psk":     psk,
		"version": version,
		"udp":     testUDP,
	}
	if obfsMode != "" {
		mapping["obfs-opts"] = map[string]any{
			"mode": obfsMode,
			"host": "controlled.test",
		}
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
		t.Fatalf("Snell URLTest() error = %v", err)
	}
	if delay == 0 {
		t.Fatal("Snell URLTest() returned the failure sentinel delay")
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
	payload := []byte("hako-controlled-snell-udp-v" + strconv.Itoa(version) + "-" + obfsMode)
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
