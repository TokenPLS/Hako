package hako

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/adapter"
	C "github.com/TokenPLS/Hako/constant"
	IN "github.com/TokenPLS/Hako/listener/inbound"
	"github.com/TokenPLS/Hako/transport/sudoku"
)

func TestControlledSudokuInterop(t *testing.T) {
	privateKey, publicKey, err := sudoku.GenKeyPair()
	if err != nil {
		t.Fatalf("GenKeyPair() error = %v", err)
	}
	paddingMin, paddingMax := 17, 97
	for _, test := range []struct {
		name       string
		serverKey  string
		clientKey  string
		tableType  string
		paddingMin *int
		paddingMax *int
	}{
		{
			name:      "SymmetricAEAD",
			serverKey: "controlled-sudoku-symmetric-key",
			clientKey: "controlled-sudoku-symmetric-key",
		},
		{
			name:      "Ed25519KeyPair",
			serverKey: publicKey,
			clientKey: privateKey,
		},
		{
			name:       "EntropyPadding",
			serverKey:  "controlled-sudoku-padding-key",
			clientKey:  "controlled-sudoku-padding-key",
			tableType:  "prefer_entropy",
			paddingMin: &paddingMin,
			paddingMax: &paddingMax,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			runControlledSudokuVariant(
				t,
				test.serverKey,
				test.clientKey,
				test.tableType,
				test.paddingMin,
				test.paddingMax,
			)
		})
	}
}

func runControlledSudokuVariant(
	t *testing.T,
	serverKey string,
	clientKey string,
	tableType string,
	paddingMin *int,
	paddingMax *int,
) {
	t.Helper()
	port := reserveControlledTCPPort(t)
	server, err := IN.NewSudoku(&IN.SudokuOption{
		BaseOption: IN.BaseOption{
			NameStr: "controlled-sudoku-inbound",
			Listen:  "127.0.0.1",
			Port:    strconv.Itoa(port),
		},
		Key:        serverKey,
		TableType:  tableType,
		PaddingMin: paddingMin,
		PaddingMax: paddingMax,
	})
	if err != nil {
		t.Fatalf("NewSudoku() error = %v", err)
	}
	if err := server.Listen(&controlledReferenceTunnel{}); err != nil {
		t.Fatalf("Sudoku Listen() error = %v", err)
	}
	defer server.Close()
	mapping := map[string]any{
		"name":       "controlled-sudoku-outbound",
		"type":       "sudoku",
		"server":     "127.0.0.1",
		"port":       port,
		"key":        clientKey,
		"table-type": tableType,
	}
	if paddingMin != nil {
		mapping["padding-min"] = *paddingMin
	}
	if paddingMax != nil {
		mapping["padding-max"] = *paddingMax
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
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	delay, err := proxy.URLTest(ctx, target.URL, nil)
	cancel()
	if err != nil {
		t.Fatalf("Sudoku URLTest() error = %v", err)
	}
	if delay == 0 {
		t.Fatal("Sudoku URLTest() returned the failure sentinel delay")
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
	payload := []byte("hako-controlled-sudoku-udp-" + tableType)
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

	failedMapping := cloneAnyTLSMapping(mapping)
	failedMapping["name"] = "controlled-sudoku-invalid-key"
	failedMapping["key"] = "controlled-sudoku-wrong-key"
	failedProxy, err := adapter.ParseProxy(failedMapping)
	if err != nil {
		t.Fatalf("ParseProxy() invalid key error = %v", err)
	}
	defer failedProxy.Close()
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	_, err = failedProxy.URLTest(ctx, target.URL, nil)
	cancel()
	if err == nil {
		t.Fatal("invalid Sudoku key unexpectedly succeeded")
	}
	if count := targetRequests.Load(); count != 1 {
		t.Fatalf("failed Sudoku attempt leaked to target; request count = %d", count)
	}
}
