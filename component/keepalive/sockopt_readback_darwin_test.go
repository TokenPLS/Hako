//go:build darwin

package keepalive

import (
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

// readKeepAliveSockopts reads back the two values darwin's own
// net/tcpsockopt_darwin.go writes, so a test can assert what the kernel actually holds
// rather than what an accessor returns. Both are expressed in seconds by the kernel.
func readKeepAliveSockopts(conn *net.TCPConn) (idleSeconds, intervalSeconds int, err error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var controlErr error
	err = raw.Control(func(fd uintptr) {
		idleSeconds, controlErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_KEEPALIVE)
		if controlErr != nil {
			return
		}
		intervalSeconds, controlErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_KEEPINTVL)
	})
	if err != nil {
		return 0, 0, err
	}
	return idleSeconds, intervalSeconds, controlErr
}

// The runtime GOOS skip this test used to open with is gone: the file is
// //go:build darwin, so the check could never be false. Keeping it would have
// implied the test guards a platform it cannot be compiled for.
//
// Lives here, not beside the other keepalive tests, because it calls
// readKeepAliveSockopts -- which only exists under //go:build darwin. Its
// sibling file carries no build constraint: `_apple` is not a GOOS suffix Go
// recognises, so that file compiles on every platform. A runtime
// `runtime.GOOS != "darwin"` skip cannot save a reference that fails to
// compile, and Linux CI reported exactly that: `undefined:
// readKeepAliveSockopts`. Local `go vet` on a Mac can never see it.
// TestDefaultsReachTheSocket is the assertion that matters: the values must actually be
// set on a real socket, not merely returned by an accessor. Readback uses the same
// sockopts darwin's own setKeepAliveIdle/Interval write.
func TestDefaultsReachTheSocket(t *testing.T) {
	restore := saveKeepAlive()
	defer restore()
	SetKeepAliveIdle(0)
	SetKeepAliveInterval(0)
	SetDisableKeepAlive(false)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()

	dialer := &net.Dialer{}
	SetNetDialer(dialer)
	conn, err := dialer.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	idle, interval, err := readKeepAliveSockopts(conn.(*net.TCPConn))
	if err != nil {
		t.Fatalf("read keepalive sockopts: %v", err)
	}
	if idle != 300 {
		t.Fatalf("TCP_KEEPALIVE on the socket = %ds, want 300s; the default never reached the kernel", idle)
	}
	if interval != 75 {
		t.Fatalf("TCP_KEEPINTVL on the socket = %ds, want 75s", interval)
	}
}
