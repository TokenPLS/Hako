package hako

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/adapter"
)

func TestControlledHTTPConnectInterop(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodHead {
			t.Errorf("target method = %s, want HEAD", request.Method)
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(target.Close)

	const (
		username = "hako-user"
		password = "hako-password"
	)
	server, port := startHTTPConnectServer(t, username, password)
	defer server.Close()

	proxy, err := adapter.ParseProxy(map[string]any{
		"name":     "controlled-http",
		"type":     "http",
		"server":   "127.0.0.1",
		"port":     port,
		"username": username,
		"password": password,
	})
	if err != nil {
		t.Fatalf("ParseProxy() error = %v", err)
	}
	t.Cleanup(func() { _ = proxy.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	delay, err := proxy.URLTest(ctx, target.URL, nil)
	if err != nil {
		t.Fatalf("HTTP CONNECT URLTest() error = %v", err)
	}
	if delay == 0 {
		t.Fatal("HTTP CONNECT URLTest() returned the failure sentinel delay")
	}
}

func TestControlledHTTPConnectRejectsInvalidCredentials(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(target.Close)

	server, port := startHTTPConnectServer(t, "hako-user", "correct-password")
	defer server.Close()

	proxy, err := adapter.ParseProxy(map[string]any{
		"name":     "controlled-http-invalid-auth",
		"type":     "http",
		"server":   "127.0.0.1",
		"port":     port,
		"username": "hako-user",
		"password": "wrong-password",
	})
	if err != nil {
		t.Fatalf("ParseProxy() error = %v", err)
	}
	t.Cleanup(func() { _ = proxy.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := proxy.URLTest(ctx, target.URL, nil); err == nil || !strings.Contains(err.Error(), "auth") {
		t.Fatalf("invalid credentials error = %v, want authentication failure", err)
	}
}

func startHTTPConnectServer(t *testing.T, username, password string) (net.Listener, int) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for HTTP CONNECT proxy: %v", err)
	}
	wantAuthorization := "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))

	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go serveHTTPConnect(connection, wantAuthorization)
		}
	}()
	return listener, listener.Addr().(*net.TCPAddr).Port
}

func serveHTTPConnect(client net.Conn, wantAuthorization string) {
	defer client.Close()
	request, err := http.ReadRequest(bufio.NewReader(client))
	if err != nil {
		return
	}
	_ = request.Body.Close()
	if request.Method != http.MethodConnect {
		_, _ = io.WriteString(client, "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
		return
	}
	if request.Header.Get("Proxy-Authorization") != wantAuthorization {
		_, _ = io.WriteString(client, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
		return
	}

	upstream, err := net.DialTimeout("tcp", request.Host, 2*time.Second)
	if err != nil {
		_, _ = io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer upstream.Close()
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}

	relayControlledTCP(client, upstream)
}

func relayControlledTCP(client, upstream net.Conn) {
	copyDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(upstream, client)
		if tcp, ok := upstream.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		close(copyDone)
	}()
	_, _ = io.Copy(client, upstream)
	<-copyDone
}
