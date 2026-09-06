package hako

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/TokenPLS/Hako/config"
	"github.com/TokenPLS/Hako/hub/route"
	"github.com/TokenPLS/Hako/log"
)

const clashAPISocketName = "clash.sock"

// Darwin sockaddr_un.sun_path is 104 bytes including the trailing NUL.
const clashAPIMaxUnixPathBytes = 103

var (
	clashAPIStartTimeout = 3 * time.Second
	clashAPIStopTimeout  = time.Second
	clashAPIPollInterval = 20 * time.Millisecond
)

// ClashAPIPath returns the binding-owned App Group Unix socket path. The
// platform and user YAML cannot override this value.
func ClashAPIPath() string {
	setupMu.Lock()
	defer setupMu.Unlock()
	return bridgeSafeString(setupClashAPIPath)
}

// bindingSocketPathFor returns the binding socket address the control plane should
// listen on, which is empty on a profile that cannot bind one.
//
// A function rather than a condition at each entry point, because there are two --
// the extension Start and the reload path -- and this file has already paid once
// for a rule that lived at one of them and not the other: secureBindingControlSocket
// was a line in Start, the reload path re-created the server without it, and one
// reload left the socket 0666 for the session.
func bindingSocketPathFor(path string) string {
	if !currentRuntimePolicy(true).bindsUnixControlSocket {
		return ""
	}
	return path
}

// startControlPlane brings up every control-plane listener in one transaction: this binding's
// App Group Unix socket and, when the configuration asks for one, the user's
// external-controller.
//
// One transaction is the whole point, and it replaces a two-call sequence that shipped and
// failed on a device. route.ReCreateServer REPLACES the listener set rather than adding to it,
// so calling it once with the user's address and again with only the socket closed the address
// three milliseconds after opening it:
//
//	RESTful API listening at: [::]:9090
//	External controller serve error: accept tcp [::]:9090: use of closed network connection
//
// Nothing in this file was wrong on its own. The second call was written when there was no
// first one, and its comment -- "ReCreateServer receives no TCP/TLS/pipe/UI address" -- was
// true the day it was written and became the line that ate the user's configuration.
func startControlPlane(cfg *config.Config, path string) error {
	// Setup assigns this path on every profile, before anything can reach Start,
	// so an empty one means Setup did not run. Checked BEFORE the policy, because
	// the version that checked it after made it unreachable: the resolver returns
	// "" for a path that is already "", so "this platform binds no socket" and
	// "you did not call Setup" arrived as the same value and the second stopped
	// being reported on every platform, tvOS included.
	if path == "" {
		return fmt.Errorf("hako: Clash API path is empty; call Setup before Start")
	}
	// tvOS gets the user's external-controller and nothing of ours. A third-party
	// process there cannot bind an AF_UNIX socket at any path -- measured on an
	// Apple TV 4K, tvOS 26.6, nine locations, EPERM every time -- so the binding
	// socket below cannot exist and the readiness dial that follows it can never
	// succeed. The observed shape was the tunnel reaching tun-verified and the
	// core stopping three seconds later, which reads as a kernel fault and is a
	// platform wall.
	//
	// Two failures were seen in sequence and only the second is the wall, worth
	// recording because fixing the first looks like success: the path was first
	// 109 bytes against Darwin's 103-byte sun_path, because tvOS grants write
	// access only inside Library/Caches of the App Group and that prefix alone is
	// 98 bytes. Shortening it produced the EPERM.
	//
	// Nothing takes its place. sing-box listens on loopback TCP for this
	// (127.0.0.1:8964); the tvOS app here reaches the core through the provider
	// message IPC, which never opens this socket, so a listener would answer
	// nobody while adding the one thing spent a session learning to respect.
	//
	// Resolved once, into the value every later line uses. The raw path is not
	// consulted again below on purpose: the first version of this kept using it
	// after the resolution and the reload path shipped the consequence -- a chmod
	// against a socket the same function had just decided not to create.
	socket := bindingSocketPathFor(path)
	if socket != "" {
		if len([]byte(socket)) > clashAPIMaxUnixPathBytes {
			return fmt.Errorf("hako: Clash API Unix path is %d bytes; Darwin limit is %d: %s", len([]byte(socket)), clashAPIMaxUnixPathBytes, socket)
		}
		_ = os.Remove(socket)
	}
	// The Hako controller is an embedded, App-Group-only control plane. Keep
	// upstream read APIs and safe runtime actions, but remove config/rule,
	// restart and updater mutations that would bypass the immutable revision
	// pipeline or perform network acquisition inside the Extension.
	route.SetEmbedMode(true)
	// The geo updater is the one capability this product implements on macOS and not on iOS, and
	// the product rule says that is an acceptable outcome: implement everything upstream offers,
	// and where a platform genuinely cannot, implementing it on the platform that can is enough.
	//
	// The asymmetry is measured on both sides. An iOS packet tunnel was killed at 49.5 MiB and
	// GeoIP.dat is 17 MB to fetch and unpack; a macOS app extension was measured living steadily
	// at 62.4 MiB with no limit configured. The macOS number does not prove the download fits --
	// it proves the iOS ceiling is not what bounds it there, which is the difference between a
	// wall with evidence and a wall inherited from another platform.
	// Asked as "does this profile inherit the iOS packet tunnel's behavior"
	// rather than "is it not iOS": tvOS has its own seat now, and the measured
	// asymmetry above is between iOS and macOS. Nothing was ever measured on an
	// Apple TV, so it stays on the side that was proven safe rather than
	// crossing to the side that was proven safe *elsewhere*.
	route.SetGeoUpdaterAllowed(!currentRuntimeProfile().inheritsIOSPacketTunnelBehavior())
	server := recreateControlPlane(cfg, socket)
	if server.Addr != "" || server.TLSAddr != "" {
		log.Infoln("[Apple] external-controller listening as configured: addr=%q tls=%q", server.Addr, server.TLSAddr)
	}
	if socket == "" {
		// The user's external-controller, if the configuration asked for one, is
		// already listening from recreateControlPlane above. There is no socket of
		// ours to secure and none to wait for.
		return nil
	}

	if err := secureBindingControlSocket(socket); err != nil {
		stopClashAPI(socket)
		return err
	}

	deadline := time.Now().Add(clashAPIStartTimeout)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("unix", socket, clashAPIPollInterval)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		lastErr = err
		time.Sleep(clashAPIPollInterval)
	}
	stopClashAPI(socket)
	return fmt.Errorf("hako: Clash API Unix listener not ready: %w", lastErr)
}

// secureBindingControlSocket narrows the App Group socket to 0600.
//
// It is a function rather than a line because it has to run after EVERY route.ReCreateServer,
// and being a line is exactly how the reload path lost it. Upstream's startUnix ends with an
// unconditional os.Chmod(addr, 0o666) -- deliberate for a desktop controller that other local
// tools connect to, wrong for a socket whose only legitimate peer is the containing app. So
// every re-create re-widens it, and one reload was enough to leave it 0666 for the session.
//
// The App Group sandbox remains the primary boundary; this is the deterministic filesystem one,
// and it is a published SDK contract, which makes losing it a broken promise rather than a
// missed hardening.
// The parameter is named socket, not path, and that is the smaller half of a fix
// rather than a rename: it takes the address a listener was actually created on.
// Callers that hand it the pathname they started from are the defect this file
// shipped, and a scan enforces the distinction now that the name makes it visible.
func secureBindingControlSocket(socket string) error {
	if err := os.Chmod(socket, 0o600); err != nil {
		return fmt.Errorf("hako: secure Clash API Unix socket: %w", err)
	}
	return nil
}

// stopClashAPI closes every native controller listener and removes the stale
// Unix pathname. Calls are idempotent and safe before a listener has started.
//
// The listener teardown is unconditional and the pathname work is not, and the
// split is load-bearing rather than tidy. route.ReCreateServer is what closes the
// USER's external-controller, which exists on every profile including the one that
// binds no socket of ours; gating the whole function on the policy would have left
// a tvOS Close with the user's TCP listener still up. What the policy gates is the
// half that is about a pathname: draining a socket nothing bound, and removing a
// file this process did not create.
func stopClashAPI(path string) {
	// Listener half first and unconditionally, as the comment above always said and the code
	// did not do: the empty-path guard sat above this line, and a Start outside the extension
	// never assigns the path Close hands in, so that Close closed nothing and reported success
	// with the user's controller still answering. An empty path says nothing about what is
	// listening; it says there is no pathname of ours to drain or remove.
	route.ReCreateServer(&route.Config{})
	userControllerLive.Store(false)
	if path == "" {
		return
	}
	socket := bindingSocketPathFor(path)
	if socket == "" {
		return
	}
	deadline := time.Now().Add(clashAPIStopTimeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("unix", socket, clashAPIPollInterval)
		if err != nil {
			break
		}
		_ = conn.Close()
		time.Sleep(clashAPIPollInterval)
	}
	_ = os.Remove(socket)
}
