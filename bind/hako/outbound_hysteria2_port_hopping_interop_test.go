package hako

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/adapter"
	"github.com/TokenPLS/Hako/component/ca"
	C "github.com/TokenPLS/Hako/constant"
)

func TestControlledHysteria2SingBoxPortHoppingInterop(t *testing.T) {
	referenceBinary := os.Getenv(singBoxReferenceBinaryEnvironment)
	if referenceBinary == "" {
		t.Skip(singBoxReferenceBinaryEnvironment + " is not set")
	}
	verifySingBoxReferenceBinary(t, referenceBinary)

	certificate, privateKey, fingerprint, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatalf("generate port-hopping Hysteria2 certificate: %v", err)
	}
	temporaryDirectory := t.TempDir()
	certificatePath := filepath.Join(temporaryDirectory, "server.pem")
	privateKeyPath := filepath.Join(temporaryDirectory, "server.key")
	if err := os.WriteFile(certificatePath, []byte(certificate), 0o600); err != nil {
		t.Fatalf("write port-hopping Hysteria2 certificate: %v", err)
	}
	if err := os.WriteFile(privateKeyPath, []byte(privateKey), 0o600); err != nil {
		t.Fatalf("write port-hopping Hysteria2 private key: %v", err)
	}
	const password = "controlled-hysteria2-port-hopping-password"
	backendPort := reserveControlledUDPPort(t)
	serverConfig, err := json.Marshal(map[string]any{
		"log": map[string]any{"level": "info", "timestamp": false},
		"inbounds": []map[string]any{{
			"type":        "hysteria2",
			"tag":         "controlled-hysteria2-port-hopping-in",
			"listen":      "127.0.0.1",
			"listen_port": backendPort,
			"up_mbps":     100,
			"down_mbps":   100,
			"users":       []map[string]any{{"name": "controlled", "password": password}},
			"tls": map[string]any{
				"enabled":          true,
				"server_name":      "controlled-hysteria2-hop.example",
				"certificate_path": certificatePath,
				"key_path":         privateKeyPath,
			},
		}},
		"outbounds": []map[string]any{{"type": "direct", "tag": "direct"}},
		"route":     map[string]any{"final": "direct"},
	})
	if err != nil {
		t.Fatalf("marshal port-hopping sing-box Hysteria2 config: %v", err)
	}
	configPath := filepath.Join(temporaryDirectory, "server.json")
	if err := os.WriteFile(configPath, serverConfig, 0o600); err != nil {
		t.Fatalf("write port-hopping sing-box Hysteria2 config: %v", err)
	}
	serverLogs := startControlledSingBoxReference(t, referenceBinary, configPath)

	hits := newControlledUDPForwarderHits()
	backendAddress := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: backendPort}
	const forwarderCount = 16
	forwarderPorts := make([]string, 0, forwarderCount)
	for index := 0; index < forwarderCount; index++ {
		port := startControlledUDPForwarder(t, backendAddress, hits)
		forwarderPorts = append(forwarderPorts, strconv.Itoa(port))
	}
	mapping := map[string]any{
		"name":         "controlled-hysteria2-sing-box-port-hopping",
		"type":         "hysteria2",
		"server":       "127.0.0.1",
		"port":         forwarderPorts[0],
		"ports":        strings.Join(forwarderPorts, ","),
		"hop-interval": "5",
		"password":     password,
		"sni":          "controlled-hysteria2-hop.example",
		"fingerprint":  fingerprint,
		"up":           "100 Mbps",
		"down":         "100 Mbps",
	}
	proxy, err := adapter.ParseProxy(mapping)
	if err != nil {
		t.Fatalf("ParseProxy() port-hopping error = %v", err)
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
	deadline := time.Now().Add(21 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		delay, err := proxy.URLTest(ctx, target.URL, nil)
		cancel()
		if err != nil {
			t.Fatalf("Hysteria2 port-hopping URLTest() error = %v\nsing-box logs:\n%s", err, serverLogs.String())
		}
		if delay == 0 {
			t.Fatal("Hysteria2 port-hopping URLTest() returned the failure sentinel delay")
		}
		if hits.UniqueCount() >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Hysteria2 did not move across two controlled ports; hits = %v\nsing-box logs:\n%s", hits.Ports(), serverLogs.String())
		}
		time.Sleep(250 * time.Millisecond)
	}
	if count := targetRequests.Load(); count < 2 {
		t.Fatalf("Hysteria2 port-hopping target request count = %d, want at least 2", count)
	}

	udpTarget, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen for post-hop UDP echo target: %v", err)
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
		t.Fatalf("Hysteria2 post-hop UDP session failed: %v\nsing-box logs:\n%s", err, serverLogs.String())
	}
	payload := []byte("hako-controlled-hysteria2-port-hopping-udp")
	if _, err := packetConnection.WriteTo(payload, udpAddress); err != nil {
		_ = packetConnection.Close()
		t.Fatalf("Hysteria2 post-hop UDP write failed: %v", err)
	}
	buffer := make([]byte, 64*1024)
	type packetResult struct {
		count  int
		source net.Addr
		err    error
	}
	result := make(chan packetResult, 1)
	go func() {
		count, source, err := packetConnection.ReadFrom(buffer)
		result <- packetResult{count: count, source: source, err: err}
	}()
	select {
	case response := <-result:
		closeError := packetConnection.Close()
		if response.err != nil {
			t.Fatalf("Hysteria2 post-hop UDP read failed: %v\nsing-box logs:\n%s", response.err, serverLogs.String())
		}
		if closeError != nil {
			t.Fatalf("Hysteria2 post-hop UDP close failed: %v", closeError)
		}
		if !bytes.Equal(buffer[:response.count], payload) || response.source.String() != udpAddress.String() {
			t.Fatal("Hysteria2 post-hop UDP response did not match the request")
		}
	case <-time.After(5 * time.Second):
		_ = packetConnection.Close()
		t.Fatalf("Hysteria2 post-hop UDP read timed out\nsing-box logs:\n%s", serverLogs.String())
	}
}

type controlledUDPForwarderHits struct {
	sync.Mutex
	ports map[int]int
}

func newControlledUDPForwarderHits() *controlledUDPForwarderHits {
	return &controlledUDPForwarderHits{ports: make(map[int]int)}
}

func (h *controlledUDPForwarderHits) Record(port int) {
	h.Lock()
	h.ports[port]++
	h.Unlock()
}

func (h *controlledUDPForwarderHits) UniqueCount() int {
	h.Lock()
	defer h.Unlock()
	return len(h.ports)
}

func (h *controlledUDPForwarderHits) Ports() []int {
	h.Lock()
	defer h.Unlock()
	ports := make([]int, 0, len(h.ports))
	for port := range h.ports {
		ports = append(ports, port)
	}
	return ports
}

type controlledUDPForwarder struct {
	front   *net.UDPConn
	backend *net.UDPConn
	port    int
	hits    *controlledUDPForwarderHits

	clientMutex sync.RWMutex
	client      *net.UDPAddr
	waitGroup   sync.WaitGroup
}

func startControlledUDPForwarder(t *testing.T, backendAddress *net.UDPAddr, hits *controlledUDPForwarderHits) int {
	t.Helper()
	front, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen for controlled UDP forwarder: %v", err)
	}
	backend, err := net.DialUDP("udp4", nil, backendAddress)
	if err != nil {
		_ = front.Close()
		t.Fatalf("dial controlled UDP forwarder backend: %v", err)
	}
	forwarder := &controlledUDPForwarder{
		front:   front,
		backend: backend,
		port:    front.LocalAddr().(*net.UDPAddr).Port,
		hits:    hits,
	}
	forwarder.waitGroup.Add(2)
	go forwarder.forwardToBackend()
	go forwarder.forwardToClient()
	t.Cleanup(func() {
		_ = forwarder.front.Close()
		_ = forwarder.backend.Close()
		forwarder.waitGroup.Wait()
	})
	return forwarder.port
}

func (f *controlledUDPForwarder) forwardToBackend() {
	defer f.waitGroup.Done()
	buffer := make([]byte, 64*1024)
	for {
		count, client, err := f.front.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		clientCopy := *client
		f.clientMutex.Lock()
		f.client = &clientCopy
		f.clientMutex.Unlock()
		f.hits.Record(f.port)
		if _, err := f.backend.Write(buffer[:count]); err != nil {
			return
		}
	}
}

func (f *controlledUDPForwarder) forwardToClient() {
	defer f.waitGroup.Done()
	buffer := make([]byte, 64*1024)
	for {
		count, err := f.backend.Read(buffer)
		if err != nil {
			return
		}
		f.clientMutex.RLock()
		client := f.client
		f.clientMutex.RUnlock()
		if client == nil {
			continue
		}
		if _, err := f.front.WriteToUDP(buffer[:count], client); err != nil {
			return
		}
	}
}
