package inbound

import (
	"context"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
)

// The two injection points below exist for the Apple Network Extension: the
// kernel gives a provider process's sockets an interface scope, so an inbound
// listener left alone never receives loopback traffic (T-M2 family; the
// System-stack NAT listener learned the same lesson in sing-tun's bindif
// file). The hooks default to nil and must change nothing until installed.

func TestDefaultListenerHookSeesListenerSocket(t *testing.T) {
	var mu sync.Mutex
	var networks, addresses []string
	DefaultListenerHook = func(network, address string, _ syscall.RawConn) error {
		mu.Lock()
		defer mu.Unlock()
		networks = append(networks, network)
		addresses = append(addresses, address)
		return nil
	}
	defer func() { DefaultListenerHook = nil }()

	lc := NewListenConfig()
	listener, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer listener.Close()

	mu.Lock()
	defer mu.Unlock()
	if len(networks) != 1 {
		t.Fatalf("hook ran %d times, want 1 (networks %v)", len(networks), networks)
	}
	if !strings.HasPrefix(networks[0], "tcp") {
		t.Errorf("hook network = %q, want tcp*", networks[0])
	}
	if !strings.Contains(addresses[0], "127.0.0.1") {
		t.Errorf("hook address = %q, want a 127.0.0.1 form", addresses[0])
	}
}

func TestDefaultListenerHookErrorFailsListen(t *testing.T) {
	DefaultListenerHook = func(network, address string, _ syscall.RawConn) error {
		return syscall.EADDRNOTAVAIL
	}
	defer func() { DefaultListenerHook = nil }()

	lc := NewListenConfig()
	listener, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err == nil {
		listener.Close()
		t.Fatal("Listen succeeded although the listener hook refused the socket; a listener that is up but unhooked is the silent-dead state the hook exists to end")
	}
}

func TestDefaultListenerHookRunsForListenPacket(t *testing.T) {
	var mu sync.Mutex
	ran := 0
	DefaultListenerHook = func(network, address string, _ syscall.RawConn) error {
		mu.Lock()
		defer mu.Unlock()
		ran++
		return nil
	}
	defer func() { DefaultListenerHook = nil }()

	lc := NewListenConfig()
	conn, err := lc.ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer conn.Close()

	mu.Lock()
	defer mu.Unlock()
	if ran != 1 {
		t.Fatalf("hook ran %d times for ListenPacket, want 1", ran)
	}
}

func TestDefaultListenerWrapperWrapsAndRelistens(t *testing.T) {
	hookAddresses := make([]string, 0, 2)
	var mu sync.Mutex
	DefaultListenerHook = func(network, address string, _ syscall.RawConn) error {
		mu.Lock()
		defer mu.Unlock()
		hookAddresses = append(hookAddresses, address)
		return nil
	}
	defer func() { DefaultListenerHook = nil }()

	var companion net.Listener
	DefaultListenerWrapper = func(network, address string, primary net.Listener, relisten func(context.Context, string, string) (net.Listener, error)) (net.Listener, error) {
		second, err := relisten(context.Background(), "tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		companion = second
		return primary, nil
	}
	defer func() { DefaultListenerWrapper = nil }()

	lc := NewListenConfig()
	listener, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer listener.Close()
	if companion == nil {
		t.Fatal("wrapper did not run")
	}
	defer companion.Close()

	// The companion listener must be built by the same configuration path as
	// the primary, or a socket option applied through the hook would silently
	// miss every companion.
	mu.Lock()
	defer mu.Unlock()
	if len(hookAddresses) != 2 {
		t.Fatalf("listener hook ran %d times, want 2 (primary + relisten companion): %v", len(hookAddresses), hookAddresses)
	}
}

func TestDefaultListenerWrapperReplacesReturnedListener(t *testing.T) {
	primaryClosed := false
	DefaultListenerWrapper = func(network, address string, primary net.Listener, relisten func(context.Context, string, string) (net.Listener, error)) (net.Listener, error) {
		primary.Close()
		primaryClosed = true
		return nil, syscall.EADDRNOTAVAIL
	}
	defer func() { DefaultListenerWrapper = nil }()

	lc := NewListenConfig()
	listener, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err == nil {
		listener.Close()
		t.Fatal("Listen succeeded although the wrapper failed; the wrapper's verdict must be the caller's verdict")
	}
	if !primaryClosed {
		t.Fatal("test invariant: wrapper should have closed the primary before failing")
	}
}
