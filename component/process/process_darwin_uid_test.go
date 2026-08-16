//go:build darwin

package process

import (
	"net"
	"net/netip"
	"os"
	"testing"
)

// The uid was returned as a hardcoded 0 here for as long as this file existed, which silently
// broke every UID rule on darwin: a rule for uid 0 matched every connection and a rule for any
// real uid matched none. Nothing failed loudly, which is why it survived.
//
// sing-box reads it at xsocket_n.so_uid -- the field immediately before the pid this code already
// read, at the same base (searcher_darwin_shared.go: darwinXsocketUID 64, darwinXsocketLastPID
// 68). Two independent implementations agreeing on the neighbouring offset is the cross-check that
// makes a raw struct read defensible.
//
// The test makes its own connection rather than looking for one on the machine, so it asserts a
// value it knows: the socket belongs to this test process, so the uid must be this process's uid.

func TestDarwinLookupReturnsTheSocketOwnerUid(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()

	client, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	if server := <-accepted; server != nil {
		defer server.Close()
	}

	local := client.LocalAddr().(*net.TCPAddr)
	address, ok := netip.AddrFromSlice(local.IP.To4())
	if !ok {
		t.Fatalf("could not read the local address back as an address: %v", local.IP)
	}

	uid, path, err := findProcessName("tcp", address, local.Port)
	if err != nil {
		t.Fatalf("findProcessName for this process's own socket: %v", err)
	}

	if want := uint32(os.Getuid()); uid != want {
		t.Fatalf("uid = %d, want %d. A hardcoded 0 here makes a UID rule for uid 0 match every "+
			"connection and a rule for any real uid match none, and nothing reports the mismatch",
			uid, want)
	}
	if path == "" {
		t.Fatal("no executable path returned; the pid read at the adjacent offset is what " +
			"cross-checks the uid offset, so an empty path means the struct layout assumption is wrong")
	}
}
