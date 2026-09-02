//go:build linux

package hako

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	neturl "net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/adapter"
	C "github.com/TokenPLS/Hako/constant"
	D "github.com/miekg/dns"
)

const (
	openVPNReferenceEnvironment = "HAKO_OPENVPN_REFERENCE_BIN"
	openVPNReferenceRepository  = "https://github.com/OpenVPN/openvpn.git"
	openVPNReferenceCommit      = "b25bb2a8bda814edab39b4246d4e296330a7a29e"
	openVPNReferenceVersion     = "2.7.5"
)

type openVPNReferencePKI struct {
	caPEM        []byte
	serverCert   []byte
	serverKey    []byte
	clientCert   []byte
	clientKey    []byte
	foreignCAPEM []byte
}

type synchronizedOpenVPNLog struct {
	mutex sync.Mutex
	data  bytes.Buffer
}

func (l *synchronizedOpenVPNLog) Write(data []byte) (int, error) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	return l.data.Write(data)
}

func (l *synchronizedOpenVPNLog) contains(fragment string) bool {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	return strings.Contains(l.data.String(), fragment)
}

func (l *synchronizedOpenVPNLog) category() string {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	content := strings.ToLower(l.data.String())
	if strings.Contains(content, "options error") {
		for _, option := range []string{
			"remote-cert-tls", "server-ipv6", "verify-client-cert", "topology",
			"data-ciphers-fallback", "data-ciphers", "cipher", "ecdh-curve", "dh",
			"tls-version-min", "tls-server", "mode", "proto", "dev-type", "dev",
		} {
			if strings.Contains(content, option) {
				return "options-" + option
			}
		}
	}
	for _, candidate := range []struct {
		fragment string
		category string
	}{
		{"initialization sequence completed", "ready"},
		{"certificate verify failed", "certificate"},
		{"tls error", "tls"},
		{"unrecognized option", "option-unrecognized"},
		{"missing or extra parameter", "option-arity"},
		{"network/netmask combination is invalid", "network-invalid"},
		{"options error", "options"},
		{"cannot ioctl tunsetiff", "tun-permission"},
		{"cannot open tun/tap", "tun-unavailable"},
		{"exiting due to fatal error", "fatal"},
	} {
		if strings.Contains(content, candidate.fragment) {
			return candidate.category
		}
	}
	return "none"
}

func TestOpenVPNOfficialReferenceInterop(t *testing.T) {
	reference := os.Getenv(openVPNReferenceEnvironment)
	if reference == "" {
		t.Skip(openVPNReferenceEnvironment + " is not set")
	}
	if os.Geteuid() != 0 {
		t.Fatal("OpenVPN reference interop requires an isolated root Linux lab")
	}
	verifyOpenVPNReference(t, reference)
	pki := generateOpenVPNReferencePKI(t)

	tests := []struct {
		name        string
		clientProto string
		serverProto string
		device      string
		ipv4        string
		ipv6        string
	}{
		{name: "udp-transport", clientProto: "udp", serverProto: "udp", device: "hkovpn0", ipv4: "10.231.10.1", ipv6: "fd42:484b:4f01:10::1"},
		{name: "tcp-transport", clientProto: "tcp", serverProto: "tcp-server", device: "hkovpn1", ipv4: "10.231.11.1", ipv6: "fd42:484b:4f01:11::1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			port := reserveOpenVPNReferencePort(t, test.clientProto)
			log := startOpenVPNReference(t, reference, pki, test.serverProto, test.device, port, test.ipv4, test.ipv6)
			targets := startOpenVPNReferenceTargets(t, test.ipv4, test.ipv6)
			mapping := openVPNReferenceMapping(pki.caPEM, pki.clientCert, pki.clientKey, test.clientProto, port, "")
			proxy, err := adapter.ParseProxy(mapping)
			if err != nil {
				t.Fatalf("OpenVPN construct failed: %s", externalInteropErrorCategory(err))
			}
			t.Cleanup(func() { _ = proxy.Close() })
			assertOpenVPNReferenceTCP(t, proxy, targets.ipv4TCPURL, log)
			assertOpenVPNReferenceUDP(t, proxy, targets.ipv4UDPAddress)
			assertOpenVPNReferenceTCP(t, proxy, targets.ipv6TCPURL, log)
			assertOpenVPNReferenceUDP(t, proxy, targets.ipv6UDPAddress)
			if err := proxy.Close(); err != nil {
				t.Fatalf("OpenVPN data-plane session close failed: %s", externalInteropErrorCategory(err))
			}

			dnsMapping := openVPNReferenceMapping(pki.caPEM, pki.clientCert, pki.clientKey, test.clientProto, port, targets.dnsAddress)
			dnsProxy, err := adapter.ParseProxy(dnsMapping)
			if err != nil {
				t.Fatalf("OpenVPN DNS variant construct failed: %s", externalInteropErrorCategory(err))
			}
			t.Cleanup(func() { _ = dnsProxy.Close() })
			assertOpenVPNReferenceTCP(t, dnsProxy, targets.hostnameTCPURL, log)
			if err := dnsProxy.Close(); err != nil {
				t.Fatalf("OpenVPN DNS session close failed: %s", externalInteropErrorCategory(err))
			}
			if targets.tcpRequests.Load() < 2 || targets.udpRequests.Load() < 2 {
				t.Fatal("OpenVPN reference targets did not observe both address families and transports")
			}
			if targets.dnsRequests.Load() == 0 {
				t.Fatal("OpenVPN tunnel DNS server did not receive the hostname query")
			}

			beforeFailure := targets.tcpRequests.Load()
			invalid := openVPNReferenceMapping(pki.foreignCAPEM, pki.clientCert, pki.clientKey, test.clientProto, port, "")
			assertOpenVPNReferenceFailure(t, invalid, targets.ipv4TCPURL)
			if targets.tcpRequests.Load() != beforeFailure {
				t.Fatal("OpenVPN rejected certificate changed the target request count")
			}
		})
	}
}

func verifyOpenVPNReference(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&0o111 == 0 {
		t.Fatal("OpenVPN reference is not an executable regular file")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, _ := exec.CommandContext(ctx, path, "--version").CombinedOutput()
	if len(output) == 0 || len(output) > 1<<20 ||
		!bytes.Contains(output, []byte("OpenVPN "+openVPNReferenceVersion)) ||
		!bytes.Contains(output, []byte(openVPNReferenceCommit[:12])) {
		t.Fatal("OpenVPN reference version does not match the pinned source")
	}
}

func openVPNReferenceMapping(ca, cert, key []byte, proto string, port int, dnsAddress string) map[string]any {
	mapping := map[string]any{
		"name":              "controlled-openvpn-client",
		"type":              "openvpn",
		"server":            "127.0.0.1",
		"port":              port,
		"proto":             proto,
		"dev":               "tun",
		"cipher":            "AES-128-GCM",
		"auth":              "SHA256",
		"ca":                string(ca),
		"cert":              string(cert),
		"key":               string(key),
		"handshake-timeout": 15,
		"ping":              5,
		"ping-restart":      30,
		"mtu":               1400,
		"udp":               true,
	}
	if dnsAddress != "" {
		mapping["remote-dns-resolve"] = true
		mapping["dns"] = []string{"udp://" + dnsAddress}
	}
	return mapping
}

func startOpenVPNReference(t *testing.T, reference string, pki openVPNReferencePKI, proto, device string, port int, ipv4, ipv6 string) *synchronizedOpenVPNLog {
	t.Helper()
	directory := t.TempDir()
	writeOpenVPNReferenceFile(t, directory, "ca.pem", pki.caPEM)
	writeOpenVPNReferenceFile(t, directory, "server.pem", pki.serverCert)
	writeOpenVPNReferenceFile(t, directory, "server.key", pki.serverKey)
	ipv4Address := netip.MustParseAddr(ipv4)
	ipv4Network := netip.PrefixFrom(ipv4Address, 24).Masked().Addr()
	ipv6Network := netip.PrefixFrom(netip.MustParseAddr(ipv6), 64).Masked()
	config := fmt.Sprintf(`mode server
tls-server
dev %s
dev-type tun
topology subnet
proto %s
local 127.0.0.1
port %d
ca %s
cert %s
key %s
dh none
ecdh-curve prime256v1
verify-client-cert require
remote-cert-tls client
server %s 255.255.255.0
server-ipv6 %s
cipher AES-128-GCM
data-ciphers AES-128-GCM
data-ciphers-fallback AES-128-GCM
auth SHA256
tls-version-min 1.2
keepalive 5 30
persist-key
persist-tun
verb 4
`, device, proto, port,
		filepath.Join(directory, "ca.pem"), filepath.Join(directory, "server.pem"), filepath.Join(directory, "server.key"),
		ipv4Network.String(), ipv6Network.String())
	configPath := writeOpenVPNReferenceFile(t, directory, "server.conf", []byte(config))

	processContext, cancel := context.WithCancel(context.Background())
	log := &synchronizedOpenVPNLog{}
	command := exec.CommandContext(processContext, reference, "--config", configPath)
	command.Stdout = log
	command.Stderr = log
	if err := command.Start(); err != nil {
		cancel()
		t.Fatal("OpenVPN reference could not start")
	}
	processDone := make(chan struct{})
	go func() {
		_ = command.Wait()
		close(processDone)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-processDone:
		case <-time.After(5 * time.Second):
			if command.Process != nil {
				_ = command.Process.Kill()
			}
			<-processDone
		}
	})

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-processDone:
			t.Fatalf("OpenVPN reference exited before becoming ready: %s", log.category())
		default:
		}
		if log.contains("Initialization Sequence Completed") {
			return log
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("OpenVPN reference readiness timed out: %s", log.category())
	return log
}

func writeOpenVPNReferenceFile(t *testing.T, directory, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal("OpenVPN reference file creation failed")
	}
	return path
}

func reserveOpenVPNReferencePort(t *testing.T, proto string) int {
	t.Helper()
	if proto == "udp" {
		connection, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal("OpenVPN UDP port reservation failed")
		}
		port := connection.LocalAddr().(*net.UDPAddr).Port
		_ = connection.Close()
		return port
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal("OpenVPN TCP port reservation failed")
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	return port
}

type openVPNReferenceTargets struct {
	ipv4TCPURL     string
	ipv6TCPURL     string
	hostnameTCPURL string
	ipv4UDPAddress string
	ipv6UDPAddress string
	dnsAddress     string
	tcpRequests    *atomic.Int64
	udpRequests    *atomic.Int64
	dnsRequests    *atomic.Int64
}

func startOpenVPNReferenceTargets(t *testing.T, ipv4, ipv6 string) openVPNReferenceTargets {
	t.Helper()
	tcpRequests := &atomic.Int64{}
	udpRequests := &atomic.Int64{}
	dnsRequests := &atomic.Int64{}
	startHTTP := func(network, address string) string {
		listener, err := net.Listen(network, net.JoinHostPort(address, "0"))
		if err != nil {
			t.Fatalf("OpenVPN %s TCP target listen failed", network)
		}
		server := &http.Server{
			ReadHeaderTimeout: 5 * time.Second,
			Handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				tcpRequests.Add(1)
				writer.WriteHeader(http.StatusNoContent)
			}),
		}
		go func() { _ = server.Serve(listener) }()
		t.Cleanup(func() { _ = server.Close() })
		return "http://" + listener.Addr().String() + "/generate_204"
	}
	startUDP := func(network, address string) string {
		connection, err := net.ListenPacket(network, net.JoinHostPort(address, "0"))
		if err != nil {
			t.Fatalf("OpenVPN %s UDP target listen failed", network)
		}
		go func() {
			buffer := make([]byte, 64*1024)
			for {
				count, remote, err := connection.ReadFrom(buffer)
				if err != nil {
					return
				}
				udpRequests.Add(1)
				_, _ = connection.WriteTo(buffer[:count], remote)
			}
		}()
		t.Cleanup(func() { _ = connection.Close() })
		return connection.LocalAddr().String()
	}
	dnsConnection, err := net.ListenPacket("udp4", net.JoinHostPort(ipv4, "0"))
	if err != nil {
		t.Fatal("OpenVPN tunnel DNS target listen failed")
	}
	dnsServer := &D.Server{
		PacketConn: dnsConnection,
		Handler: D.HandlerFunc(func(writer D.ResponseWriter, query *D.Msg) {
			response := new(D.Msg)
			response.SetReply(query)
			for _, question := range query.Question {
				if question.Qtype == D.TypeA && strings.EqualFold(question.Name, "openvpn.reference.test.") {
					response.Answer = append(response.Answer, &D.A{
						Hdr: D.RR_Header{Name: question.Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 30},
						A:   net.ParseIP(ipv4).To4(),
					})
				}
			}
			dnsRequests.Add(1)
			_ = writer.WriteMsg(response)
		}),
	}
	go func() { _ = dnsServer.ActivateAndServe() }()
	t.Cleanup(func() { _ = dnsServer.Shutdown() })
	ipv4TCPURL := startHTTP("tcp4", ipv4)
	parsedIPv4TCPURL, err := neturl.Parse(ipv4TCPURL)
	if err != nil {
		t.Fatal("OpenVPN IPv4 TCP target URL parsing failed")
	}
	_, tcpPort, err := net.SplitHostPort(parsedIPv4TCPURL.Host)
	if err != nil {
		t.Fatal("OpenVPN IPv4 TCP target address parsing failed")
	}
	return openVPNReferenceTargets{
		ipv4TCPURL:     ipv4TCPURL,
		ipv6TCPURL:     startHTTP("tcp6", ipv6),
		hostnameTCPURL: "http://openvpn.reference.test:" + tcpPort + "/generate_204",
		ipv4UDPAddress: startUDP("udp4", ipv4),
		ipv6UDPAddress: startUDP("udp6", ipv6),
		dnsAddress:     dnsConnection.LocalAddr().String(),
		tcpRequests:    tcpRequests,
		udpRequests:    udpRequests,
		dnsRequests:    dnsRequests,
	}
}

func assertOpenVPNReferenceTCP(t *testing.T, proxy C.Proxy, targetURL string, referenceLog *synchronizedOpenVPNLog) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	delay, err := proxy.URLTest(ctx, targetURL, nil)
	cancel()
	if err != nil {
		t.Fatalf("OpenVPN TCP interop failed: %s (reference=%s)", externalInteropErrorCategory(err), referenceLog.category())
	}
	if delay == 0 {
		t.Fatal("OpenVPN TCP interop returned the failure sentinel delay")
	}
}

func assertOpenVPNReferenceUDP(t *testing.T, proxy C.Proxy, targetAddress string) {
	t.Helper()
	udpAddress, err := net.ResolveUDPAddr("udp", targetAddress)
	if err != nil {
		t.Fatal("OpenVPN UDP target resolution failed")
	}
	address, ok := netip.AddrFromSlice(udpAddress.IP)
	if !ok {
		t.Fatal("OpenVPN UDP target address was invalid")
	}
	metadata := &C.Metadata{NetWork: C.UDP, Type: C.TUN, DstIP: address.Unmap(), DstPort: uint16(udpAddress.Port)}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	packetConnection, err := proxy.ListenPacketContext(ctx, metadata)
	cancel()
	if err != nil {
		t.Fatalf("OpenVPN UDP session failed: %s", externalInteropErrorCategory(err))
	}
	defer packetConnection.Close()
	if err := packetConnection.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		t.Fatalf("OpenVPN UDP deadline failed: %s", externalInteropErrorCategory(err))
	}
	payload := []byte("hako-openvpn-reference")
	if _, err := packetConnection.WriteTo(payload, udpAddress); err != nil {
		t.Fatalf("OpenVPN UDP write failed: %s", externalInteropErrorCategory(err))
	}
	buffer := make([]byte, 64*1024)
	count, source, err := packetConnection.ReadFrom(buffer)
	if err != nil {
		t.Fatalf("OpenVPN UDP read failed: %s", externalInteropErrorCategory(err))
	}
	if !bytes.Equal(buffer[:count], payload) || source.String() != udpAddress.String() {
		t.Fatal("OpenVPN UDP echo response did not match the request")
	}
}

func assertOpenVPNReferenceFailure(t *testing.T, mapping map[string]any, targetURL string) {
	t.Helper()
	proxy, err := adapter.ParseProxy(mapping)
	if err != nil {
		t.Fatalf("OpenVPN failure variant construct failed: %s", externalInteropErrorCategory(err))
	}
	defer proxy.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	_, err = proxy.URLTest(ctx, targetURL, nil)
	cancel()
	if err == nil {
		t.Fatal("OpenVPN invalid certificate unexpectedly succeeded")
	}
}

func generateOpenVPNReferencePKI(t *testing.T) openVPNReferencePKI {
	t.Helper()
	now := time.Now()
	serial := int64(1)
	newKey := func() *ecdsa.PrivateKey {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal("OpenVPN test key generation failed")
		}
		return key
	}
	encodeKey := func(key *ecdsa.PrivateKey) []byte {
		encoded, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			t.Fatal("OpenVPN test key encoding failed")
		}
		return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: encoded})
	}
	createCA := func(commonName string) ([]byte, *x509.Certificate, *ecdsa.PrivateKey) {
		key := newKey()
		template := &x509.Certificate{
			SerialNumber:          big.NewInt(serial),
			Subject:               pkix.Name{CommonName: commonName},
			NotBefore:             now.Add(-time.Hour),
			NotAfter:              now.Add(24 * time.Hour),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
		serial++
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			t.Fatal("OpenVPN test CA generation failed")
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal("OpenVPN test CA parsing failed")
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), certificate, key
	}
	createLeaf := func(commonName string, usage x509.ExtKeyUsage, ca *x509.Certificate, caKey *ecdsa.PrivateKey) ([]byte, []byte) {
		key := newKey()
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: commonName},
			NotBefore:    now.Add(-time.Hour),
			NotAfter:     now.Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		}
		serial++
		der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal("OpenVPN test certificate generation failed")
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), encodeKey(key)
	}
	caPEM, ca, caKey := createCA("hako-openvpn-ca")
	serverCert, serverKey := createLeaf("hako-openvpn-server", x509.ExtKeyUsageServerAuth, ca, caKey)
	clientCert, clientKey := createLeaf("hako-openvpn-client", x509.ExtKeyUsageClientAuth, ca, caKey)
	foreignCAPEM, _, _ := createCA("hako-openvpn-foreign-ca")
	return openVPNReferencePKI{
		caPEM:        caPEM,
		serverCert:   serverCert,
		serverKey:    serverKey,
		clientCert:   clientCert,
		clientKey:    clientKey,
		foreignCAPEM: foreignCAPEM,
	}
}
