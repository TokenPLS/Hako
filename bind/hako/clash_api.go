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
	return setupClashAPIPath
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
	if path == "" {
		return fmt.Errorf("hako: Clash API path is empty; call Setup before Start")
	}
	if len([]byte(path)) > clashAPIMaxUnixPathBytes {
		return fmt.Errorf("hako: Clash API Unix path is %d bytes; Darwin limit is %d: %s", len([]byte(path)), clashAPIMaxUnixPathBytes, path)
	}
	_ = os.Remove(path)
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
	server := recreateControlPlane(cfg, path)
	if server.Addr != "" || server.TLSAddr != "" {
		log.Infoln("[Apple] external-controller listening as configured: addr=%q tls=%q", server.Addr, server.TLSAddr)
	}
	if err := secureBindingControlSocket(path); err != nil {
		stopClashAPI(path)
		return err
	}

	deadline := time.Now().Add(clashAPIStartTimeout)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("unix", path, clashAPIPollInterval)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		lastErr = err
		time.Sleep(clashAPIPollInterval)
	}
	stopClashAPI(path)
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
func secureBindingControlSocket(path string) error {
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("hako: secure Clash API Unix socket: %w", err)
	}
	return nil
}

// stopClashAPI closes every native controller listener and removes the stale
// Unix pathname. Calls are idempotent and safe before a listener has started.
func stopClashAPI(path string) {
	if path == "" {
		return
	}
	route.ReCreateServer(&route.Config{})
	deadline := time.Now().Add(clashAPIStopTimeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("unix", path, clashAPIPollInterval)
		if err != nil {
			break
		}
		_ = conn.Close()
		time.Sleep(clashAPIPollInterval)
	}
	_ = os.Remove(path)
}
