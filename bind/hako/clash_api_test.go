package hako

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// shortSocketDirectory is a base path a Unix socket actually fits in. t.TempDir() interpolates
// the test's name, and Darwin's sockaddr_un.sun_path holds 103 bytes -- a descriptive test name
// pushes the socket past it, bind() fails EINVAL, and the failure reads like the product not
// creating a socket rather than the test not being able to name one.
func shortSocketDirectory(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "hako-clash-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return directory
}

func shortClashSocketPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(shortSocketDirectory(t), clashAPISocketName)
}

func TestClashAPIUnixLifecycle(t *testing.T) {
	path := shortClashSocketPath(t)
	if err := startControlPlane(nil, path); err != nil {
		t.Fatalf("startClashAPI: %v", err)
	}
	t.Cleanup(func() { stopClashAPI(path) })

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial native controller: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if _, err = fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("write request: %v", err)
	}
	status, err := bufio.NewReader(conn).ReadString('\n')
	_ = conn.Close()
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if !strings.Contains(status, " 200 ") {
		t.Fatalf("unexpected native controller status %q", status)
	}

	stopClashAPI(path)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("socket remains after stop: %v", err)
	}
	if conn, err := net.Dial("unix", path); err == nil {
		_ = conn.Close()
		t.Fatal("native controller still accepts connections after stop")
	}
}

func TestSetupOwnsClashAPIPath(t *testing.T) {
	options := testOptions(t)
	if err := Setup(options); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	want := filepath.Join(options.BasePath, clashAPISocketName)
	if got := ClashAPIPath(); got != want {
		t.Fatalf("ClashAPIPath() = %q, want %q", got, want)
	}
}

func TestNonNetworkExtensionStartKeepsClashAPIOff(t *testing.T) {
	options := testOptions(t)
	if err := Setup(options); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	service, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	t.Cleanup(func() { _ = service.Close() })
	if err := service.Start(helloYAML); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if service.clashAPIPath != "" {
		t.Fatalf("non-NE service started Clash API at %q", service.clashAPIPath)
	}
	if _, err := os.Stat(ClashAPIPath()); !os.IsNotExist(err) {
		t.Fatalf("non-NE socket exists: %v", err)
	}
}
