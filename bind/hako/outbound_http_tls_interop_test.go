package hako

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/adapter"
	"github.com/TokenPLS/Hako/component/ca"
)

const httpTLSHelperEnvironment = "HAKO_HTTP_TLS_INTEROP_HELPER"

func TestControlledHTTPSConnectMTLSInterop(t *testing.T) {
	if os.Getenv(httpTLSHelperEnvironment) == "1" {
		runControlledHTTPSConnectMTLSHelper(t)
		return
	}
	command := exec.Command(os.Args[0], "-test.run=^TestControlledHTTPSConnectMTLSInterop$")
	command.Env = append(os.Environ(), httpTLSHelperEnvironment+"=1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("HTTPS CONNECT mTLS helper failed: %v\n%s", err, output)
	}
}

func runControlledHTTPSConnectMTLSHelper(t *testing.T) {
	rootCertificate, rootKey, rootPEM := newControlledCertificateAuthority(t)
	proxyCertificate, _, _ := newControlledLeafCertificate(
		t, rootCertificate, rootKey, "controlled-proxy", []string{"proxy.controlled.test"}, nil, x509.ExtKeyUsageServerAuth,
	)
	_, clientCertificatePEM, clientKeyPEM := newControlledLeafCertificate(
		t, rootCertificate, rootKey, "controlled-client", nil, nil, x509.ExtKeyUsageClientAuth,
	)
	targetCertificate, _, _ := newControlledLeafCertificate(
		t, rootCertificate, rootKey, "controlled-target", nil, []net.IP{net.IPv4(127, 0, 0, 1)}, x509.ExtKeyUsageServerAuth,
	)
	if err := ca.AddCertificate(string(rootPEM)); err != nil {
		t.Fatalf("AddCertificate() error = %v", err)
	}

	var targetRequests atomic.Int32
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		targetRequests.Add(1)
		if request.Method != http.MethodHead {
			t.Errorf("target method = %s, want HEAD", request.Method)
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	target.TLS = &tls.Config{
		Certificates: []tls.Certificate{targetCertificate},
		MinVersion:   tls.VersionTLS12,
	}
	target.StartTLS()
	defer target.Close()

	clientRoots := x509.NewCertPool()
	if !clientRoots.AppendCertsFromPEM(rootPEM) {
		t.Fatal("append client CA failed")
	}
	rawListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for HTTPS CONNECT proxy: %v", err)
	}
	proxyListener := tls.NewListener(rawListener, &tls.Config{
		Certificates: []tls.Certificate{proxyCertificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientRoots,
		MinVersion:   tls.VersionTLS12,
	})
	defer proxyListener.Close()
	const (
		username = "hako-mtls-user"
		password = "hako-mtls-password"
	)
	wantAuthorization := "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
	go func() {
		for {
			connection, err := proxyListener.Accept()
			if err != nil {
				return
			}
			go serveHTTPConnect(connection, wantAuthorization)
		}
	}()
	port := rawListener.Addr().(*net.TCPAddr).Port

	proxy, err := adapter.ParseProxy(map[string]any{
		"name":        "controlled-https-mtls",
		"type":        "http",
		"server":      "127.0.0.1",
		"port":        port,
		"username":    username,
		"password":    password,
		"tls":         true,
		"sni":         "proxy.controlled.test",
		"certificate": string(clientCertificatePEM),
		"private-key": string(clientKeyPEM),
	})
	if err != nil {
		t.Fatalf("ParseProxy() error = %v", err)
	}
	defer proxy.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	delay, err := proxy.URLTest(ctx, target.URL, nil)
	cancel()
	if err != nil {
		t.Fatalf("HTTPS CONNECT mTLS URLTest() error = %v", err)
	}
	if delay == 0 {
		t.Fatal("HTTPS CONNECT mTLS URLTest() returned the failure sentinel delay")
	}
	if count := targetRequests.Load(); count != 1 {
		t.Fatalf("target request count = %d, want 1", count)
	}

	wrongSNIProxy, err := adapter.ParseProxy(map[string]any{
		"name":        "controlled-https-wrong-sni",
		"type":        "http",
		"server":      "127.0.0.1",
		"port":        port,
		"username":    username,
		"password":    password,
		"tls":         true,
		"sni":         "wrong.controlled.test",
		"certificate": string(clientCertificatePEM),
		"private-key": string(clientKeyPEM),
	})
	if err != nil {
		t.Fatalf("ParseProxy(wrong SNI) error = %v", err)
	}
	defer wrongSNIProxy.Close()
	ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
	_, err = wrongSNIProxy.URLTest(ctx, target.URL, nil)
	cancel()
	if err == nil {
		t.Fatal("wrong-SNI HTTPS proxy unexpectedly passed certificate validation")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "certificate") {
		t.Fatalf("wrong-SNI error = %v, want certificate validation failure", err)
	}
	if count := targetRequests.Load(); count != 1 {
		t.Fatalf("wrong-SNI attempt leaked to target; request count = %d", count)
	}
}

func newControlledCertificateAuthority(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Hako Controlled Test CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}
	return certificate, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func newControlledLeafCertificate(
	t *testing.T,
	issuer *x509.Certificate,
	issuerKey *ecdsa.PrivateKey,
	commonName string,
	dnsNames []string,
	ipAddresses []net.IP,
	usage x509.ExtKeyUsage,
) (tls.Certificate, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate %s key: %v", commonName, err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 120)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		t.Fatalf("generate %s serial: %v", commonName, err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		DNSNames:     dnsNames,
		IPAddresses:  ipAddresses,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("create %s certificate: %v", commonName, err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal %s key: %v", commonName, err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		t.Fatalf("load %s key pair: %v", commonName, err)
	}
	return certificate, certificatePEM, keyPEM
}
