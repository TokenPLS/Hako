package hako

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	C "github.com/TokenPLS/Hako/constant"
	"github.com/TokenPLS/Hako/hub/executor"
	D "github.com/miekg/dns"
)

const dnsHelperEnvironment = "HAKO_DNS_INTEROP_HELPER"

func TestControlledDNSOutboundUDPInterop(t *testing.T) {
	runDNSHelper(t, "udp")
}

func TestControlledDNSOutboundTCPInterop(t *testing.T) {
	runDNSHelper(t, "tcp")
}

func TestControlledDNSOutboundHelperProcess(t *testing.T) {
	transport := os.Getenv(dnsHelperEnvironment)
	if transport == "" {
		t.Skip("subprocess helper")
	}

	options := testOptions(t)
	options.DisablePersistentCache = true
	if err := Setup(options); err != nil {
		t.Fatalf("Setup() error = %v", err)
	}

	server, address, observed := startControlledDNSServer(t, transport)
	defer func() { _ = server.Shutdown() }()
	upstream := address
	if transport == "tcp" {
		upstream = "tcp://" + address
	}
	configYAML := fmt.Sprintf(`
mode: rule
ipv6: true
dns:
  enable: true
  ipv6: true
  listen: ""
  enhanced-mode: redir-host
  default-nameserver:
    - %s
  nameserver:
    - %s
proxies:
  - name: controlled-dns
    type: dns
rules:
  - MATCH,DIRECT
`, address, upstream)
	configuration, err := executor.ParseWithBytes([]byte(configYAML))
	if err != nil {
		t.Fatalf("ParseWithBytes() error = %v\n%s", err, configYAML)
	}
	executor.ApplyConfig(configuration, true)
	proxy := configuration.Proxies["controlled-dns"]
	if proxy == nil {
		t.Fatal("controlled-dns proxy is missing after parse")
	}

	metadata := &C.Metadata{
		NetWork: C.UDP,
		Type:    C.TUN,
		SrcIP:   netip.MustParseAddr("192.0.2.2"),
		SrcPort: 49153,
		DstIP:   netip.MustParseAddr("192.0.2.53"),
		DstPort: 53,
	}
	for _, test := range []struct {
		name  string
		qtype uint16
		rcode int
	}{
		{name: "a.controlled.test.", qtype: D.TypeA, rcode: D.RcodeSuccess},
		{name: "aaaa.controlled.test.", qtype: D.TypeAAAA, rcode: D.RcodeSuccess},
		{name: "servfail.controlled.test.", qtype: D.TypeA, rcode: D.RcodeServerFailure},
	} {
		query := new(D.Msg)
		query.SetQuestion(test.name, test.qtype)
		var response *D.Msg
		if transport == "udp" {
			response = exchangeDNSOverPacketOutbound(t, proxy, metadata, query)
		} else {
			response = exchangeDNSOverStreamOutbound(t, proxy, metadata, query)
		}
		if response.Rcode != test.rcode {
			t.Fatalf("%s rcode = %s, want %s", test.name, D.RcodeToString[response.Rcode], D.RcodeToString[test.rcode])
		}
		if test.rcode == D.RcodeSuccess && len(response.Answer) != 1 {
			t.Fatalf("%s answer count = %d, want 1", test.name, len(response.Answer))
		}
		select {
		case network := <-observed:
			if !strings.HasPrefix(network, transport) {
				t.Fatalf("%s upstream transport = %q, want %s", test.name, network, transport)
			}
		case <-time.After(time.Second):
			t.Fatalf("%s query did not reach the controlled DNS server", test.name)
		}
	}
}

func startControlledDNSServer(t *testing.T, transport string) (*D.Server, string, <-chan string) {
	t.Helper()
	observed := make(chan string, 8)
	handler := D.HandlerFunc(func(writer D.ResponseWriter, request *D.Msg) {
		observed <- writer.RemoteAddr().Network()
		response := new(D.Msg)
		response.SetReply(request)
		question := request.Question[0]
		switch {
		case question.Name == "servfail.controlled.test.":
			response.Rcode = D.RcodeServerFailure
		case question.Qtype == D.TypeA:
			response.Answer = []D.RR{&D.A{
				Hdr: D.RR_Header{Name: question.Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60},
				A:   net.IPv4(192, 0, 2, 10),
			}}
		case question.Qtype == D.TypeAAAA:
			response.Answer = []D.RR{&D.AAAA{
				Hdr:  D.RR_Header{Name: question.Name, Rrtype: D.TypeAAAA, Class: D.ClassINET, Ttl: 60},
				AAAA: net.ParseIP("2001:db8::10"),
			}}
		default:
			response.Rcode = D.RcodeNameError
		}
		if err := writer.WriteMsg(response); err != nil {
			t.Errorf("controlled DNS response error = %v", err)
		}
	})

	switch transport {
	case "udp":
		connection, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("ListenPacket() error = %v", err)
		}
		server := &D.Server{PacketConn: connection, Handler: handler}
		go func() { _ = server.ActivateAndServe() }()
		return server, connection.LocalAddr().String(), observed
	case "tcp":
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("Listen() error = %v", err)
		}
		server := &D.Server{Listener: listener, Handler: handler}
		go func() { _ = server.ActivateAndServe() }()
		return server, listener.Addr().String(), observed
	default:
		t.Fatalf("unknown DNS transport %q", transport)
		return nil, "", nil
	}
}

func exchangeDNSOverPacketOutbound(t *testing.T, proxy C.Proxy, metadata *C.Metadata, query *D.Msg) *D.Msg {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	connection, err := proxy.ListenPacketContext(ctx, metadata.Clone())
	if err != nil {
		t.Fatalf("ListenPacketContext() error = %v", err)
	}
	defer connection.Close()
	payload, err := query.Pack()
	if err != nil {
		t.Fatalf("query Pack() error = %v", err)
	}
	address := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 53), Port: 53}
	if _, err := connection.WriteTo(payload, address); err != nil {
		t.Fatalf("DNS outbound WriteTo() error = %v", err)
	}
	buffer := make([]byte, 2048)
	n, _, err := connection.ReadFrom(buffer)
	if err != nil {
		t.Fatalf("DNS outbound ReadFrom() error = %v", err)
	}
	response := new(D.Msg)
	if err := response.Unpack(buffer[:n]); err != nil {
		t.Fatalf("response Unpack() error = %v", err)
	}
	return response
}

func exchangeDNSOverStreamOutbound(t *testing.T, proxy C.Proxy, metadata *C.Metadata, query *D.Msg) *D.Msg {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	connection, err := proxy.DialContext(ctx, metadata.Clone())
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetDeadline() error = %v", err)
	}
	payload, err := query.Pack()
	if err != nil {
		t.Fatalf("query Pack() error = %v", err)
	}
	frame := make([]byte, len(payload)+2)
	binary.BigEndian.PutUint16(frame, uint16(len(payload)))
	copy(frame[2:], payload)
	if _, err := connection.Write(frame); err != nil {
		t.Fatalf("DNS stream Write() error = %v", err)
	}
	var length uint16
	if err := binary.Read(connection, binary.BigEndian, &length); err != nil {
		t.Fatalf("DNS stream read length error = %v", err)
	}
	responsePayload := make([]byte, length)
	if _, err := io.ReadFull(connection, responsePayload); err != nil {
		t.Fatalf("DNS stream read payload error = %v", err)
	}
	response := new(D.Msg)
	if err := response.Unpack(responsePayload); err != nil {
		t.Fatalf("response Unpack() error = %v", err)
	}
	return response
}

func runDNSHelper(t *testing.T, transport string) {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestControlledDNSOutboundHelperProcess$")
	command.Env = append(os.Environ(), dnsHelperEnvironment+"="+transport)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("%s helper failed: %v\n%s", transport, err, output)
	}
}
