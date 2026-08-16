package hako

import (
	"net"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/TokenPLS/Hako/config"
)

// freeLoopbackPort returns a port nothing is listening on, by taking one and giving it back.
// A hardcoded port makes a test that fails on whoever's machine already uses it.
func freeLoopbackPort(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a port: %v", err)
	}
	_, port, err := net.SplitHostPort(listener.Addr().String())
	_ = listener.Close()
	if err != nil {
		t.Fatalf("split reserved address: %v", err)
	}
	if _, err := strconv.Atoi(port); err != nil {
		t.Fatalf("reserved port is not a number: %q", port)
	}
	return port
}

// withSetupClashAPIPath points the package-level socket path at a test's own, and puts it back.
// applyExternalController reads it directly because the reload path has no other source.
func withSetupClashAPIPath(t *testing.T, path string) {
	t.Helper()
	setupMu.Lock()
	previous := setupClashAPIPath
	setupClashAPIPath = path
	setupMu.Unlock()
	t.Cleanup(func() {
		setupMu.Lock()
		setupClashAPIPath = previous
		setupMu.Unlock()
	})
}

// packageSourceFiles returns this package's non-test Go sources, keyed by file name.
func packageSourceFiles(t *testing.T) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read the package directory: %v", err)
	}
	sources := map[string]string{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		body, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		sources[name] = string(body)
	}
	if len(sources) == 0 {
		t.Fatal("no non-test sources found; the scan would pass by finding nothing")
	}
	return sources
}

func controllerConfig(t *testing.T, addr string) *config.Config {
	t.Helper()
	cfg, err := parseConfigForIOS(`
external-controller: `+addr+`
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`, true)
	if err != nil {
		t.Fatalf("parse controller fixture: %v", err)
	}
	return cfg
}

// The user's controller has to be listening when Start returns, and that is not the same claim
// as "the configuration this core built for it was correct". The device proved the difference:
//
//	[Apple] external-controller listening as configured: addr="0.0.0.0:9090"
//	RESTful API listening at: [::]:9090
//	External controller serve error: accept tcp [::]:9090: use of closed network connection
//
// Three milliseconds. route.ReCreateServer replaces the entire listener set rather than merging
// into it, and the Start path called it twice: once with the user's address alongside this
// binding's socket, then again -- after tun verification -- with the socket alone. The second
// call is what a reader would describe as "start the App Group API", and it silently closed the
// listener the first call had just opened.
//
// Every existing test passed through all of this, because they assert on what
// controllerServerConfig returns. That value was right the whole time. The defect lived in what
// happened to it afterwards, which is the shape of bug an intermediate-product assertion cannot
// see: verify your own step, never the last one.
//
// So this test asserts the end state, by connecting. Nothing about the configuration struct
// appears in it on purpose.
func TestStartLeavesTheConfiguredControllerListening(t *testing.T) {
	port := freeLoopbackPort(t)
	addr := "127.0.0.1:" + port
	path := shortClashSocketPath(t)
	cfg := controllerConfig(t, addr)

	if err := startControlPlane(cfg, path); err != nil {
		t.Fatalf("startControlPlane: %v", err)
	}
	t.Cleanup(func() { stopClashAPI(path) })

	tcp, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("the configured controller is not listening at %s: %v -- the user wrote this "+
			"address and the core reported opening it", addr, err)
	}
	_ = tcp.Close()

	unix, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("the binding's own App Group socket is not listening at %s: %v -- both live in "+
			"one route.Config, so opening the user's address must not cost us ours", path, err)
	}
	_ = unix.Close()
}

// 0600 on the App Group socket is a published SDK contract, and it survives exactly as long as
// nobody calls route.ReCreateServer without re-applying it: upstream's startUnix ends with an
// unconditional os.Chmod(addr, 0o666), which is deliberate for a desktop controller and wrong
// for ours.
//
// Reload is the path that lost it. It re-creates the server whenever a controller is configured
// and nothing tightened the mode afterwards, so one reload widened the socket for the rest of
// the session. That was read out of the code rather than measured on a device -- the consuming
// lane could not enumerate the App Group container -- and it is straight-line code with no
// branch, which is why it is fixed rather than filed.
func TestReloadKeepsTheAppGroupSocketAt0600(t *testing.T) {
	port := freeLoopbackPort(t)
	addr := "127.0.0.1:" + port
	path := shortClashSocketPath(t)
	cfg := controllerConfig(t, addr)

	if err := startControlPlane(cfg, path); err != nil {
		t.Fatalf("startControlPlane: %v", err)
	}
	t.Cleanup(func() { stopClashAPI(path) })

	withSetupClashAPIPath(t, path)
	applyExternalController(cfg)

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat the App Group socket after reload: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("the App Group socket is %04o after a reload, not 0600; upstream's startUnix "+
			"chmods 0666 on every re-create and something has to tighten it back", mode)
	}
}

// The two defects above are one defect: route.ReCreateServer is a whole-set replacement that
// reads like an addition. Any second shape of argument in this package is another listener set
// silently replacing the first, so the shapes are enumerated rather than trusted.
//
// A grep-shaped test is usually decoration. This one is not, because the claim it makes is
// exact and mechanical: there are two legitimate arguments -- the merged configuration, and the
// empty one that tears everything down -- and a third is the bug returning. It was checked by
// putting the original bug back and watching it fail.
func TestEveryControlPlaneCreationUsesTheMergedConfiguration(t *testing.T) {
	const teardown = "&route.Config{}" // stopClashAPI: close everything, listen to nothing

	sources := packageSourceFiles(t)
	found := 0
	for name, body := range sources {
		for index, line := range strings.Split(body, "\n") {
			// Comment lines are skipped, and that is a correction rather than a loophole: the
			// doc comment on recreateControlPlane QUOTES upstream's applyRoute, so the scan
			// flagged prose explaining the rule as a violation of it. A call cannot execute from
			// inside a comment, and both directions were re-checked by mutation afterwards --
			// the real bug in code still turns this red, the same text in a comment does not.
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			call := strings.Index(line, "route.ReCreateServer(")
			if call < 0 {
				continue
			}
			found++
			argument := strings.TrimSuffix(strings.TrimSpace(line[call+len("route.ReCreateServer("):]), ")")
			if argument == teardown {
				continue
			}
			// Anything else must be a value this file derived from controllerServerConfig --
			// the one place that merges the user's controller with the binding's socket.
			derived := strings.Contains(body, argument+" := controllerServerConfig(") ||
				strings.HasPrefix(argument, "controllerServerConfig(")
			if !derived {
				t.Errorf("%s:%d creates a control plane from %q, which does not come from "+
					"controllerServerConfig. route.ReCreateServer REPLACES the whole listener "+
					"set, so a second shape here closes whatever the first one opened -- which "+
					"is how the user's external-controller lived for three milliseconds on a "+
					"device", name, index+1, argument)
			}
		}
	}
	if found == 0 {
		t.Fatal("no route.ReCreateServer call found in this package; the scan is measuring nothing")
	}
}

// The branch that runs outside the extension had never been executed by anything -- not a
// device, not a test. It survived by being a side effect: one unconditional line ran on every
// Start, and the extension's own second call happened to be the only thing anyone verified.
// Making it an explicit `else` was an improvement to how it reads and changed nothing about what
// is known to work. "Now it has a name" is not "now it is verified", and the second is easy to
// mistake for the first.
//
// The short base path is not cosmetic. testOptions builds one from t.TempDir(), and a Darwin
// sockaddr_un holds 103 bytes: with this test's name the socket path came to 130, bind() failed
// EINVAL, and the probe reported "no binding socket outside the extension". That reads exactly
// like a finding about the product. It was a finding about the test's name -- caught only
// because a second probe with a shorter name disagreed, and two probes that disagree mean
// neither is a fact yet.
func TestNonNetworkExtensionStartOpensTheConfiguredController(t *testing.T) {
	port := freeLoopbackPort(t)
	addr := "127.0.0.1:" + port

	options := testOptions(t)
	options.BasePath = shortSocketDirectory(t)
	if err := Setup(options); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	service, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	t.Cleanup(func() { _ = service.Close() })

	document := strings.Replace(helloYAML, "mode: rule", "mode: rule\nexternal-controller: "+addr, 1)
	if err := service.Start(document); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { stopClashAPI(ClashAPIPath()) })

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("a start outside the extension did not open the configured controller at %s: "+
			"%v -- this branch used to be an unconditional line and nothing ever ran it", addr, err)
	}
	_ = conn.Close()

	// The second fact, measured rather than assumed: this path ALSO opens the binding's App
	// Group socket, because controllerServerConfig always fills UnixAddr from Setup. Nothing
	// outside the extension consumes it -- the app that would talk to it is this same process.
	// Recorded, not changed: whether a macOS Application should carry a control socket at all is
	// that lane's process model, and the behaviour predates the branch being named.
	// TestNonNetworkExtensionStartKeepsClashAPIOff pins the other side, where no controller is
	// configured and no socket appears, so the two together say where the line currently falls.
	unix, err := net.Dial("unix", ClashAPIPath())
	if err != nil {
		t.Fatalf("the binding socket is not listening outside the extension: %v -- if this is now "+
			"deliberate, say so here and tell the macOS lane; do not let it change silently", err)
	}
	_ = unix.Close()
}
