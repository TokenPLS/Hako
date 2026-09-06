package hako

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	C "github.com/TokenPLS/Hako/constant"
	"github.com/TokenPLS/Hako/hub/executor"
	"github.com/TokenPLS/Hako/tunnel"
)

const rematchHelperEnvironment = "HAKO_REMATCH_INTEROP_HELPER"

func TestControlledRematchRoutesToSelectedOutbound(t *testing.T) {
	runRematchHelper(t, "success")
}

func TestControlledRematchCycleFailsClosed(t *testing.T) {
	runRematchHelper(t, "cycle")
}

func TestControlledRematchHelperProcess(t *testing.T) {
	mode := os.Getenv(rematchHelperEnvironment)
	if mode == "" {
		t.Skip("subprocess helper")
	}

	options := testOptions(t)
	options.DisablePersistentCache = true
	if err := Setup(options); err != nil {
		t.Fatalf("Setup() error = %v", err)
	}

	targetReached := make(chan struct{}, 1)
	target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		targetReached <- struct{}{}
		writer.Header().Set("X-Hako-Rematch", "selected-direct")
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()

	var proxyYAML, ruleYAML string
	switch mode {
	case "success":
		proxyYAML = `
  - name: rematch-entry
    type: rematch
    target-rematch-name: selected-direct
`
		ruleYAML = `
  - REMATCH-NAME,selected-direct,DIRECT
  - MATCH,rematch-entry
`
	case "cycle":
		proxyYAML = `
  - name: rematch-a
    type: rematch
    target-rematch-name: lane-b
  - name: rematch-b
    type: rematch
    target-rematch-name: lane-a
`
		ruleYAML = `
  - REMATCH-NAME,lane-a,rematch-a
  - REMATCH-NAME,lane-b,rematch-b
  - MATCH,rematch-a
`
	default:
		t.Fatalf("unknown helper mode %q", mode)
	}

	configYAML := "mode: rule\nipv6: false\nproxies:" + proxyYAML + "rules:" + ruleYAML
	configuration, err := executor.ParseWithBytes([]byte(configYAML))
	if err != nil {
		t.Fatalf("ParseWithBytes() error = %v\n%s", err, configYAML)
	}
	executor.ApplyConfig(configuration, true)

	targetAddress := strings.TrimPrefix(target.URL, "http://")
	host, port, err := net.SplitHostPort(targetAddress)
	if err != nil {
		t.Fatalf("SplitHostPort() error = %v", err)
	}
	destinationIP, err := netip.ParseAddr(host)
	if err != nil {
		t.Fatalf("ParseAddr() error = %v", err)
	}
	var destinationPort uint16
	if _, err := fmt.Sscanf(port, "%d", &destinationPort); err != nil {
		t.Fatalf("parse target port: %v", err)
	}

	client, core := net.Pipe()
	defer client.Close()
	metadata := &C.Metadata{
		NetWork: C.TCP,
		Type:    C.TUN,
		SrcIP:   netip.MustParseAddr("192.0.2.2"),
		SrcPort: 49152,
		DstIP:   destinationIP,
		DstPort: destinationPort,
	}
	go tunnel.Tunnel.HandleTCPConn(core, metadata)

	if err := client.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetDeadline() error = %v", err)
	}
	if _, err := fmt.Fprintf(client, "GET / HTTP/1.1\r\nHost: controlled-rematch\r\nConnection: close\r\n\r\n"); err != nil {
		// Cycle detection only needs the connection metadata, so the Core may
		// fail closed before net.Pipe delivers the synthetic HTTP request.
		// That early close is the desired outcome for the cycle case.
		if mode != "cycle" || (!errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, net.ErrClosed)) {
			t.Fatalf("write request: %v", err)
		}
		select {
		case <-targetReached:
			t.Fatal("rematch cycle leaked a request to the target")
		case <-time.After(50 * time.Millisecond):
		}
		return
	}

	reader := bufio.NewReader(client)
	if mode == "success" {
		response, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatalf("ReadResponse() error = %v", err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			t.Fatalf("response status = %d, want %d", response.StatusCode, http.StatusNoContent)
		}
		if value := response.Header.Get("X-Hako-Rematch"); value != "selected-direct" {
			t.Fatalf("response marker = %q, want selected-direct", value)
		}
		select {
		case <-targetReached:
		case <-time.After(time.Second):
			t.Fatal("selected DIRECT target was not reached")
		}
		return
	}

	if _, err := reader.ReadByte(); err == nil {
		t.Fatal("rematch cycle unexpectedly returned target data")
	} else if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("cycle read error = %v, want closed connection", err)
	}
	select {
	case <-targetReached:
		t.Fatal("rematch cycle leaked a request to the target")
	case <-time.After(50 * time.Millisecond):
	}
}

func runRematchHelper(t *testing.T, mode string) {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestControlledRematchHelperProcess$")
	command.Env = append(os.Environ(), rematchHelperEnvironment+"="+mode)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("%s helper failed: %v\n%s", mode, err, output)
	}
}
