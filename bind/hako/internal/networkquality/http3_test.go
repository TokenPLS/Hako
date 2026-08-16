//go:build with_quic

package networkquality

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	stdHTTP "net/http"
	"net/http/httptest"
	stdTrace "net/http/httptrace"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	metaHTTP "github.com/metacubex/http"
	"github.com/metacubex/quic-go/http3"
	N "github.com/metacubex/sing/common/network"
	metaTLS "github.com/metacubex/tls"
)

func TestHTTP3FactoryUsesUDPConnectEndpointTLSAndCounters(t *testing.T) {
	certificate, roots := newHTTP3TestCertificate(t)
	packetConnection, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packetConnection.Close()

	server := &http3.Server{
		TLSConfig: &metaTLS.Config{Certificates: []metaTLS.Certificate{certificate}},
		Handler: metaHTTP.HandlerFunc(func(writer metaHTTP.ResponseWriter, request *metaHTTP.Request) {
			if !strings.HasPrefix(request.Host, "localhost") {
				t.Errorf("request host = %q", request.Host)
			}
			writer.Header().Set("Content-Encoding", "")
			_, _ = io.WriteString(writer, "hako-http3")
		}),
	}
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve(packetConnection) }()
	t.Cleanup(func() {
		_ = server.Close()
		select {
		case <-serverDone:
		case <-time.After(time.Second):
			t.Error("HTTP/3 server did not stop")
		}
	})

	factory, err := newHTTP3MeasurementClientFactory(nil, &metaTLS.Config{RootCAs: roots})
	if err != nil {
		t.Fatal(err)
	}
	var readBytes atomic.Int64
	var writtenBytes atomic.Int64
	client, err := factory(
		packetConnection.LocalAddr().String(),
		true,
		true,
		[]N.CountFunc{func(count int64) { readBytes.Add(count) }},
		[]N.CountFunc{func(count int64) { writtenBytes.Add(count) }},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer closeMeasurementClient(client)

	var gotConnectionCount atomic.Int32
	var reusedConnectionCount atomic.Int32
	var wroteRequestCount atomic.Int32
	var firstByteCount atomic.Int32
	for requestIndex := 0; requestIndex < 2; requestIndex++ {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		trace := &stdTrace.ClientTrace{
			GotConn: func(info stdTrace.GotConnInfo) {
				gotConnectionCount.Add(1)
				if info.Reused {
					reusedConnectionCount.Add(1)
				}
			},
			WroteRequest:         func(stdTrace.WroteRequestInfo) { wroteRequestCount.Add(1) },
			GotFirstResponseByte: func() { firstByteCount.Add(1) },
		}
		request, err := stdHTTP.NewRequestWithContext(
			stdTrace.WithClientTrace(ctx, trace),
			stdHTTP.MethodGet,
			"https://localhost:443/probe",
			nil,
		)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		response, err := client.Do(request)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		payload, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		if response.ProtoMajor != 3 || string(payload) != "hako-http3" {
			t.Fatalf("response proto=%s payload=%q", response.Proto, payload)
		}
	}
	if readBytes.Load() <= 0 || writtenBytes.Load() <= 0 {
		t.Fatalf("QUIC counters read=%d written=%d", readBytes.Load(), writtenBytes.Load())
	}
	if gotConnectionCount.Load() != 2 || reusedConnectionCount.Load() != 1 ||
		wroteRequestCount.Load() != 2 || firstByteCount.Load() != 2 {
		t.Fatalf(
			"trace got=%d reused=%d wrote=%d first=%d",
			gotConnectionCount.Load(),
			reusedConnectionCount.Load(),
			wroteRequestCount.Load(),
			firstByteCount.Load(),
		)
	}
}

func TestHTTP3FactoryDistinguishesUnavailableFromCancellation(t *testing.T) {
	packetConnection, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packetConnection.Close()
	factory, err := newHTTP3MeasurementClientFactory(nil, &metaTLS.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	client, err := factory(packetConnection.LocalAddr().String(), true, true, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer closeMeasurementClient(client)

	timedContext, timedCancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer timedCancel()
	timedRequest, err := stdHTTP.NewRequestWithContext(
		timedContext,
		stdHTTP.MethodGet,
		"https://localhost:443/probe",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Do(timedRequest)
	if err == nil || !strings.Contains(err.Error(), "HTTP/3 network quality unavailable") {
		t.Fatalf("unavailable error = %v", err)
	}

	cancelledContext, cancel := context.WithCancel(context.Background())
	cancel()
	cancelledRequest, err := stdHTTP.NewRequestWithContext(
		cancelledContext,
		stdHTTP.MethodGet,
		"https://localhost:443/probe",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Do(cancelledRequest)
	if !errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("cancellation error = %v", err)
	}
}

func TestNetworkQualityRunCompletesOverHTTP3(t *testing.T) {
	previousSettings := settings
	settings.idleProbeCount = 1
	settings.stabilityInterval = 100 * time.Millisecond
	settings.sampleInterval = 20 * time.Millisecond
	settings.progressInterval = 50 * time.Millisecond
	settings.maxProbesPerSecond = 20
	settings.initialConnections = 1
	settings.maxConnections = 2
	settings.movingAvgDistance = 2
	t.Cleanup(func() { settings = previousSettings })

	certificate, roots := newHTTP3TestCertificate(t)
	packetConnection, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packetConnection.Close()
	server := &http3.Server{
		TLSConfig: &metaTLS.Config{Certificates: []metaTLS.Certificate{certificate}},
		Handler: metaHTTP.HandlerFunc(func(writer metaHTTP.ResponseWriter, request *metaHTTP.Request) {
			switch request.URL.Path {
			case "/small":
				_, _ = writer.Write(bytes.Repeat([]byte("s"), 4_096))
			case "/large":
				chunk := bytes.Repeat([]byte("d"), 32*1_024)
				for request.Context().Err() == nil {
					if _, writeError := writer.Write(chunk); writeError != nil {
						return
					}
				}
			case "/upload":
				writer.WriteHeader(metaHTTP.StatusOK)
				if flusher, ok := writer.(metaHTTP.Flusher); ok {
					flusher.Flush()
				}
				_, _ = io.Copy(io.Discard, request.Body)
			default:
				metaHTTP.NotFound(writer, request)
			}
		}),
	}
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve(packetConnection) }()
	t.Cleanup(func() {
		_ = server.Close()
		select {
		case <-serverDone:
		case <-time.After(time.Second):
			t.Error("HTTP/3 server did not stop")
		}
	})

	measurementHost := "https://localhost:443"
	configServer := httptest.NewServer(stdHTTP.HandlerFunc(func(writer stdHTTP.ResponseWriter, _ *stdHTTP.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(writer, `{
			"version":1,
			"test_endpoint":%q,
			"urls":{
				"small_https_download_url":%q,
				"large_https_download_url":%q,
				"https_upload_url":%q
			}
		}`, packetConnection.LocalAddr().String(), measurementHost+"/small", measurementHost+"/large", measurementHost+"/upload")
	}))
	defer configServer.Close()
	factory, err := newHTTP3MeasurementClientFactory(nil, &metaTLS.Config{RootCAs: roots})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var finalProgress Progress
	result, err := Run(Options{
		ConfigURL:            configServer.URL,
		HTTPClient:           configServer.Client(),
		NewMeasurementClient: factory,
		Serial:               true,
		MaxRuntime:           800 * time.Millisecond,
		Context:              ctx,
		OnProgress:           func(progress Progress) { finalProgress = progress },
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.DownloadCapacity <= 0 || result.UploadCapacity <= 0 || finalProgress.Phase != PhaseDone {
		t.Fatalf("result=%+v progress=%+v", result, finalProgress)
	}
}

func newHTTP3TestCertificate(t *testing.T) (metaTLS.Certificate, *x509.CertPool) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate := metaTLS.Certificate{Certificate: [][]byte{certificateDER}, PrivateKey: privateKey}
	roots := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(parsed)
	return certificate, roots
}
