package hako

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/adapter"
	"github.com/metacubex/ssh"
)

func TestControlledSSHInterop(t *testing.T) {
	_, hostPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate SSH host key: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPrivateKey)
	if err != nil {
		t.Fatalf("create SSH host signer: %v", err)
	}
	clientPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate SSH client key: %v", err)
	}
	clientSigner, err := ssh.NewSignerFromKey(clientPrivateKey)
	if err != nil {
		t.Fatalf("create SSH client signer: %v", err)
	}
	const username = "controlled-ssh-user"
	const password = "controlled-ssh-password"
	serverAddress := startControlledSSHServer(t, hostSigner, clientSigner.PublicKey(), username, password)
	hostKey := string(ssh.MarshalAuthorizedKey(hostSigner.PublicKey()))
	privateKeyBlock, err := ssh.MarshalPrivateKeyWithPassphrase(clientPrivateKey, "controlled-hako", []byte("controlled-key-passphrase"))
	if err != nil {
		t.Fatalf("marshal encrypted SSH private key: %v", err)
	}
	privateKey := string(pem.EncodeToMemory(privateKeyBlock))

	var targetRequests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		targetRequests.Add(1)
		if request.Method != http.MethodHead {
			t.Errorf("target method = %s, want HEAD", request.Method)
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	host, port, err := net.SplitHostPort(serverAddress)
	if err != nil {
		t.Fatalf("split SSH server address: %v", err)
	}
	baseMapping := map[string]any{
		"type":                "ssh",
		"server":              host,
		"port":                port,
		"username":            username,
		"host-key":            []string{hostKey},
		"host-key-algorithms": []string{hostSigner.PublicKey().Type()},
	}
	for _, variant := range []struct {
		name       string
		credential map[string]any
	}{
		{name: "Password", credential: map[string]any{"password": password}},
		{name: "EncryptedPrivateKey", credential: map[string]any{
			"private-key":            privateKey,
			"private-key-passphrase": "controlled-key-passphrase",
		}},
	} {
		t.Run(variant.name, func(t *testing.T) {
			mapping := cloneAnyTLSMapping(baseMapping)
			mapping["name"] = "controlled-ssh-" + variant.name
			for key, value := range variant.credential {
				mapping[key] = value
			}
			proxy, err := adapter.ParseProxy(mapping)
			if err != nil {
				t.Fatalf("ParseProxy() error = %v", err)
			}
			defer proxy.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			delay, err := proxy.URLTest(ctx, target.URL, nil)
			cancel()
			if err != nil {
				t.Fatalf("SSH URLTest() error = %v", err)
			}
			if delay == 0 {
				t.Fatal("SSH URLTest() returned the failure sentinel delay")
			}
		})
	}
	if count := targetRequests.Load(); count != 2 {
		t.Fatalf("target request count = %d, want 2", count)
	}

	_, wrongHostPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate wrong SSH host key: %v", err)
	}
	wrongHostSigner, err := ssh.NewSignerFromKey(wrongHostPrivateKey)
	if err != nil {
		t.Fatalf("create wrong SSH host signer: %v", err)
	}
	for _, failure := range []struct {
		name     string
		password string
		hostKey  string
	}{
		{name: "InvalidPassword", password: "wrong-password", hostKey: hostKey},
		{name: "InvalidHostKey", password: password, hostKey: string(ssh.MarshalAuthorizedKey(wrongHostSigner.PublicKey()))},
	} {
		t.Run(failure.name, func(t *testing.T) {
			mapping := cloneAnyTLSMapping(baseMapping)
			mapping["name"] = "controlled-ssh-" + failure.name
			mapping["password"] = failure.password
			mapping["host-key"] = []string{failure.hostKey}
			proxy, err := adapter.ParseProxy(mapping)
			if err != nil {
				t.Fatalf("ParseProxy() error = %v", err)
			}
			defer proxy.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_, err = proxy.URLTest(ctx, target.URL, nil)
			cancel()
			if err == nil {
				t.Fatal("invalid SSH credentials unexpectedly succeeded")
			}
			if count := targetRequests.Load(); count != 2 {
				t.Fatalf("failed SSH attempt leaked to target; request count = %d", count)
			}
		})
	}
}

func startControlledSSHServer(t *testing.T, hostSigner ssh.Signer, clientKey ssh.PublicKey, username string, password string) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for SSH server: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	config := &ssh.ServerConfig{
		PasswordCallback: func(metadata ssh.ConnMetadata, candidate []byte) (*ssh.Permissions, error) {
			if metadata.User() == username && bytes.Equal(candidate, []byte(password)) {
				return nil, nil
			}
			return nil, fmt.Errorf("invalid SSH password")
		},
		PublicKeyCallback: func(metadata ssh.ConnMetadata, candidate ssh.PublicKey) (*ssh.Permissions, error) {
			if metadata.User() == username && bytes.Equal(candidate.Marshal(), clientKey.Marshal()) {
				return nil, nil
			}
			return nil, fmt.Errorf("invalid SSH public key")
		},
	}
	config.AddHostKey(hostSigner)
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go serveControlledSSHConnection(connection, config)
		}
	}()
	return listener.Addr().String()
}

func serveControlledSSHConnection(connection net.Conn, config *ssh.ServerConfig) {
	defer connection.Close()
	_, channels, requests, err := ssh.NewServerConn(connection, config)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(requests)
	for channelRequest := range channels {
		if channelRequest.ChannelType() != "direct-tcpip" {
			_ = channelRequest.Reject(ssh.UnknownChannelType, "unsupported channel")
			continue
		}
		var request struct {
			DestinationHost string
			DestinationPort uint32
			OriginHost      string
			OriginPort      uint32
		}
		if err := ssh.Unmarshal(channelRequest.ExtraData(), &request); err != nil {
			_ = channelRequest.Reject(ssh.ConnectionFailed, "invalid direct-tcpip request")
			continue
		}
		upstream, err := net.DialTimeout("tcp", net.JoinHostPort(request.DestinationHost, fmt.Sprint(request.DestinationPort)), 2*time.Second)
		if err != nil {
			_ = channelRequest.Reject(ssh.ConnectionFailed, err.Error())
			continue
		}
		channel, channelRequests, err := channelRequest.Accept()
		if err != nil {
			_ = upstream.Close()
			continue
		}
		go ssh.DiscardRequests(channelRequests)
		go func() {
			defer channel.Close()
			defer upstream.Close()
			done := make(chan struct{})
			go func() {
				_, _ = io.Copy(upstream, channel)
				if tcp, ok := upstream.(*net.TCPConn); ok {
					_ = tcp.CloseWrite()
				}
				close(done)
			}()
			_, _ = io.Copy(channel, upstream)
			<-done
		}()
	}
}
