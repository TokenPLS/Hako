//go:build darwin

package tunnel

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/TokenPLS/Hako/component/process"
	C "github.com/TokenPLS/Hako/constant"
)

// The end of the chain, on a real socket this process owns.
//
// component/process/process_darwin_uid_test.go already proved the lookup itself works, and it
// passed for the whole time PROCESS-* rules matched nothing on macOS: it called the function
// directly, so it could only ever measure the function. What was broken was the caller. This
// test goes through resolveMetadata -- the same closure the rule engine calls -- so it measures
// the branch, and it is the one that goes red under the framework's own tag set (-tags cmfa)
// before the fix and green after.
func TestResolveMetadataAttributesTheConnectionToThisProcess(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	go func() {
		if accepted, err := listener.Accept(); err == nil {
			defer accepted.Close()
		}
	}()

	conn, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	local := conn.LocalAddr().(*net.TCPAddr).AddrPort()
	remote := conn.RemoteAddr().(*net.TCPAddr).AddrPort()

	previousMode, previousFindProcess := Mode(), FindProcessMode()
	t.Cleanup(func() {
		SetMode(previousMode)
		SetFindProcessMode(previousFindProcess)
	})
	// Direct keeps this off the rule engine: resolveMetadata still runs the FindProcess helper
	// (FindProcessAlways calls it before the mode switch) but then returns proxies["DIRECT"]
	// instead of needing a loaded ruleset.
	SetMode(Direct)
	SetFindProcessMode(process.FindProcessAlways)

	metadata := &C.Metadata{
		NetWork: C.TCP,
		Type:    C.TUN,
		SrcIP:   local.Addr().Unmap(),
		SrcPort: local.Port(),
		DstIP:   remote.Addr().Unmap(),
		DstPort: remote.Port(),
	}
	if _, _, err := resolveMetadata(metadata); err != nil {
		t.Fatalf("resolveMetadata: %v", err)
	}

	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("executable: %v", err)
	}
	// proc_pidpath answers with the resolved path, and on macOS /var is a symlink to
	// /private/var, which is where a test binary lives. Resolve both sides or the two spellings
	// of the same file look like a failed lookup.
	if executable, err = filepath.EvalSymlinks(executable); err != nil {
		t.Fatalf("resolve executable: %v", err)
	}
	if metadata.ProcessPath != executable {
		t.Errorf("ProcessPath = %q, want %q -- the socket belongs to this test process",
			metadata.ProcessPath, executable)
	}
	if metadata.Process != filepath.Base(executable) {
		t.Errorf("Process = %q, want %q", metadata.Process, filepath.Base(executable))
	}
	if !metadata.UidKnown {
		t.Error("UidKnown = false; a resolved owner must mark the uid present, or UID rules defer")
	}
	if metadata.Uid != uint32(os.Getuid()) {
		t.Errorf("Uid = %d, want %d", metadata.Uid, os.Getuid())
	}
	if !metadata.SourceIdentityKnown {
		t.Error("SourceIdentityKnown = false; UID rules need it set to match exactly")
	}
}

// And the call site must read that variable, not the build tag directly.
//
// Without this, the two spellings are indistinguishable in the untagged run every developer and
// every CI job here actually does: features.CMFA is false, resolvesOwnerByPackageName is false,
// and both branches behave identically. Flipping the variable is what makes the difference
// observable -- a call site still keyed off features.CMFA keeps resolving the owner and this
// goes red, with no tag required.
func TestTheCallSiteReadsThePredicateAndNotTheTag(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	go func() {
		if accepted, err := listener.Accept(); err == nil {
			defer accepted.Close()
		}
	}()

	conn, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	local := conn.LocalAddr().(*net.TCPAddr).AddrPort()
	remote := conn.RemoteAddr().(*net.TCPAddr).AddrPort()

	previousMode, previousFindProcess := Mode(), FindProcessMode()
	previousPredicate := resolvesOwnerByPackageName
	t.Cleanup(func() {
		SetMode(previousMode)
		SetFindProcessMode(previousFindProcess)
		resolvesOwnerByPackageName = previousPredicate
	})
	SetMode(Direct)
	SetFindProcessMode(process.FindProcessAlways)
	resolvesOwnerByPackageName = true

	metadata := &C.Metadata{
		NetWork: C.TCP,
		Type:    C.TUN,
		SrcIP:   local.Addr().Unmap(),
		SrcPort: local.Port(),
		DstIP:   remote.Addr().Unmap(),
		DstPort: remote.Port(),
	}
	if _, _, err := resolveMetadata(metadata); err != nil {
		t.Fatalf("resolveMetadata: %v", err)
	}

	if metadata.ProcessPath != "" {
		t.Errorf("ProcessPath = %q with resolvesOwnerByPackageName=true; the socket table was "+
			"read anyway, so the call site is not reading the predicate", metadata.ProcessPath)
	}
	if metadata.UidKnown || metadata.SourceIdentityKnown {
		t.Errorf("UidKnown=%v SourceIdentityKnown=%v with resolvesOwnerByPackageName=true; "+
			"the package-name branch supplies neither", metadata.UidKnown, metadata.SourceIdentityKnown)
	}
}
