//go:build darwin

package hako

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/adapter/inbound"
	"golang.org/x/sys/unix"
)

func installScopeHooksForTest(t *testing.T) {
	t.Helper()
	installListenerScopeHooks(true)
	t.Cleanup(func() { installListenerScopeHooks(false) })
}

func requireLoopbackIndex(t *testing.T) int {
	t.Helper()
	index, err := loopbackInterfaceIndex()
	if err != nil {
		t.Fatalf("loopbackInterfaceIndex: %v", err)
	}
	if index <= 0 {
		t.Fatalf("loopback interface index = %d, want > 0", index)
	}
	return index
}

func boundInterfaceOf(t *testing.T, raw syscall.RawConn, v6 bool) int {
	t.Helper()
	var value int
	var opErr error
	if controlErr := raw.Control(func(fd uintptr) {
		if v6 {
			value, opErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF)
		} else {
			value, opErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF)
		}
	}); controlErr != nil {
		t.Fatalf("raw control: %v", controlErr)
	}
	if opErr != nil {
		t.Fatalf("getsockopt bound-if: %v", opErr)
	}
	return value
}

func tcpListenerRaw(t *testing.T, listener net.Listener) syscall.RawConn {
	t.Helper()
	tcp, ok := listener.(*net.TCPListener)
	if !ok {
		t.Fatalf("listener is %T, want *net.TCPListener", listener)
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	return raw
}

func dialAndAccept(t *testing.T, listener net.Listener, address string) {
	t.Helper()
	type acceptResult struct {
		conn net.Conn
		err  error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		conn, err := listener.Accept()
		accepted <- acceptResult{conn, err}
	}()
	client, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", address, err)
	}
	defer client.Close()
	select {
	case result := <-accepted:
		if result.err != nil {
			t.Fatalf("accept after dialing %s: %v", address, result.err)
		}
		result.conn.Close()
	case <-time.After(2 * time.Second):
		t.Fatalf("no accept within 2s after dialing %s", address)
	}
}

func TestListenerScopeHooksInstallToggle(t *testing.T) {
	installListenerScopeHooks(true)
	t.Cleanup(func() { installListenerScopeHooks(false) })
	if inbound.DefaultListenerHook == nil {
		t.Fatal("under NE the listener hook must be installed")
	}
	if inbound.DefaultListenerWrapper == nil {
		t.Fatal("under NE the listener wrapper must be installed")
	}
	installListenerScopeHooks(false)
	if inbound.DefaultListenerHook != nil {
		t.Fatal("outside NE the listener hook must be cleared")
	}
	if inbound.DefaultListenerWrapper != nil {
		t.Fatal("outside NE the listener wrapper must be cleared")
	}
}

func TestListenerScopeBindsLoopbackListenerToLoopbackInterface(t *testing.T) {
	installScopeHooksForTest(t)
	loopback := requireLoopbackIndex(t)

	lc := inbound.NewListenConfig()
	listener, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer listener.Close()

	if got := boundInterfaceOf(t, tcpListenerRaw(t, listener), false); got != loopback {
		t.Fatalf("IP_BOUND_IF = %d, want loopback index %d", got, loopback)
	}
	// The bind must not cost the listener its reachability on the interface
	// loopback traffic actually arrives on.
	dialAndAccept(t, listener, listener.Addr().String())
}

func TestListenerScopeBindsV6LoopbackListenerToLoopbackInterface(t *testing.T) {
	installScopeHooksForTest(t)
	loopback := requireLoopbackIndex(t)

	lc := inbound.NewListenConfig()
	listener, err := lc.Listen(context.Background(), "tcp", "[::1]:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer listener.Close()

	if got := boundInterfaceOf(t, tcpListenerRaw(t, listener), true); got != loopback {
		t.Fatalf("IPV6_BOUND_IF = %d, want loopback index %d", got, loopback)
	}
	dialAndAccept(t, listener, listener.Addr().String())
}

func TestListenerScopeBindsLoopbackPacketConn(t *testing.T) {
	installScopeHooksForTest(t)
	loopback := requireLoopbackIndex(t)

	lc := inbound.NewListenConfig()
	conn, err := lc.ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer conn.Close()

	raw, err := conn.(*net.UDPConn).SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	if got := boundInterfaceOf(t, raw, false); got != loopback {
		t.Fatalf("IP_BOUND_IF = %d, want loopback index %d", got, loopback)
	}
}

func TestListenerScopeLeavesNonLoopbackListenersUnbound(t *testing.T) {
	// Function-level on purpose: the wildcard path through the full inbound
	// face gains companions, whose primary is wrapped out of SyscallConn
	// reach. The hook alone decides binding, so it is what must stay silent
	// for a non-loopback address.
	lc := net.ListenConfig{Control: listenerScopeControl}
	listener, err := lc.Listen(context.Background(), "tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer listener.Close()

	if got := boundInterfaceOf(t, tcpListenerRaw(t, listener), false); got != 0 {
		t.Fatalf("IP_BOUND_IF = %d for a wildcard listener, want 0 (unbound: the physical face must keep working)", got)
	}
}

func TestListenerScopeWildcardGainsLoopbackCompanions(t *testing.T) {
	installScopeHooksForTest(t)

	lc := inbound.NewListenConfig()
	listener, err := lc.Listen(context.Background(), "tcp", ":0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer listener.Close()

	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split listener address %q: %v", listener.Addr(), err)
	}
	dialAndAccept(t, listener, net.JoinHostPort("127.0.0.1", port))
	dialAndAccept(t, listener, net.JoinHostPort("::1", port))
}

func TestListenerScopeV4WildcardGainsOnlyV4Companion(t *testing.T) {
	installScopeHooksForTest(t)

	lc := inbound.NewListenConfig()
	listener, err := lc.Listen(context.Background(), "tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer listener.Close()

	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split listener address %q: %v", listener.Addr(), err)
	}
	dialAndAccept(t, listener, net.JoinHostPort("127.0.0.1", port))
	if conn, err := net.DialTimeout("tcp", net.JoinHostPort("::1", port), 500*time.Millisecond); err == nil {
		conn.Close()
		t.Fatal("[::1] answered although the v4-only wildcard should have no v6 companion")
	}
}

func TestListenerScopeCompanionConflictFailsTheListen(t *testing.T) {
	installScopeHooksForTest(t)

	squatter, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("squatter listen: %v", err)
	}
	defer squatter.Close()
	_, port, err := net.SplitHostPort(squatter.Addr().String())
	if err != nil {
		t.Fatalf("split squatter address: %v", err)
	}

	lc := inbound.NewListenConfig()
	listener, err := lc.Listen(context.Background(), "tcp4", "0.0.0.0:"+port)
	if err == nil {
		listener.Close()
		t.Fatal("Listen succeeded although the loopback companion port was taken; a wildcard listener whose loopback face is someone else's socket is the silent-dead state this fix exists to end")
	}
}

func TestListenerScopeCompanionCloseIsIdempotentAndReleasesPorts(t *testing.T) {
	installScopeHooksForTest(t)

	lc := inbound.NewListenConfig()
	listener, err := lc.Listen(context.Background(), "tcp", ":0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	address := listener.Addr().String()
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatalf("split listener address: %v", err)
	}

	if err := listener.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	_ = listener.Close() // second close must not panic

	if _, err := listener.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after close = %v, want net.ErrClosed", err)
	}

	// Every socket the wrapped listener owned must be released, or the next
	// start of the same configuration fails on its own leftovers.
	relisten, err := lc.Listen(context.Background(), "tcp", ":"+port)
	if err != nil {
		t.Fatalf("relisten after close: %v", err)
	}
	relisten.Close()
}

func TestNewServiceInstallsListenerScopeHooksByProcessPlacement(t *testing.T) {
	t.Cleanup(func() { installListenerScopeHooks(false) })
	if err := Setup(testOptions(t)); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	extension := newRecordingPlatform()
	extension.underNetworkExtension = true
	if _, err := NewService(extension); err != nil {
		t.Fatalf("NewService (extension): %v", err)
	}
	if inbound.DefaultListenerHook == nil || inbound.DefaultListenerWrapper == nil {
		t.Fatal("NewService under the Network Extension must install the listener scope hooks")
	}

	app := newRecordingPlatform()
	if _, err := NewService(app); err != nil {
		t.Fatalf("NewService (app): %v", err)
	}
	if inbound.DefaultListenerHook != nil || inbound.DefaultListenerWrapper != nil {
		t.Fatal("NewService outside the Network Extension must clear the listener scope hooks; an app process has no scope to repair")
	}
}

func TestListenerScopeSkipsNonHostPortAddresses(t *testing.T) {
	// The controller's unix-socket listener rides the same inbound face; an
	// address that does not split into host:port must pass through untouched.
	if err := listenerScopeControl("unix", "/tmp/hako-test.sock", nil); err != nil {
		t.Fatalf("listenerScopeControl on a unix address: %v", err)
	}
}
