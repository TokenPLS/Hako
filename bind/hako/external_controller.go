package hako

import (
	"sync/atomic"

	"github.com/TokenPLS/Hako/config"
	"github.com/TokenPLS/Hako/hub/route"
	"github.com/TokenPLS/Hako/log"
)

// userControllerLive records whether the last control-plane transaction left the USER's
// external-controller (TCP or TLS) listening. It is the one fact the reload path needs and
// cannot read back from upstream: route's listeners are package-private, and asking it would
// mean a fork delta for a boolean.
//
// It is written in exactly two places -- recreateControlPlane, the only function that hands a
// live configuration to route.ReCreateServer, and stopClashAPI, the only one that hands it the
// empty set -- and TestEveryControlPlaneCreationUsesTheMergedConfiguration keeps those the only
// two, so the latch cannot say "nothing is listening" while something is. The other direction
// (a listen error leaving the latch true with nothing bound) costs one harmless re-create.
var userControllerLive atomic.Bool

// controllerServerConfig turns the user's controller fields into the server configuration,
// alongside this binding's own App Group socket.
//
// Nothing is added, removed or second-guessed. Two earlier attempts at this field each invented
// a condition -- a permission switch, then a downgrade to loopback when a network-reachable
// address carried no secret -- and both were rejected for the same reason: they are stricter
// than upstream and not required by the platform, which is this repository's own definition of
// an invented constraint (hako-core-overconstraint-audit). The reasoning behind the second one
// was that a user who writes 0.0.0.0:9090 probably copied it from a tutorial and does not mean
// it. That is deciding what someone meant, which is not this side's to decide.
//
// The one thing that could justify a restriction later is App Review refusing the surface. Then
// the evidence is the review text, not a prediction about it.
//
// unguardedControllerNotices still speaks when the address is reachable off-device with no
// secret. Saying is not restricting.
func controllerServerConfig(cfg *config.Config, bindingSocketPath string) *route.Config {
	server := &route.Config{UnixAddr: bindingSocketPath}
	if cfg == nil || cfg.Controller == nil {
		return server
	}
	controller := cfg.Controller
	server.Addr = controller.ExternalController
	server.TLSAddr = controller.ExternalControllerTLS
	server.Secret = controller.Secret
	server.DohServer = controller.ExternalDohServer
	// The controller's TLS material lives in cfg.TLS, not on Controller -- upstream wires it
	// the same way (hub/hub.go:71-75). Those five fields were stripped by this core on the
	// stated ground that their only consumer was stripped with them. That consumer is back, so
	// the ground is gone: external-controller-tls without a certificate is a listener that
	// cannot start.
	if cfg.TLS != nil {
		server.Certificate = cfg.TLS.Certificate
		server.PrivateKey = cfg.TLS.PrivateKey
		server.ClientAuthType = cfg.TLS.ClientAuthType
		server.ClientAuthCert = cfg.TLS.ClientAuthCert
		server.EchKey = cfg.TLS.EchKey
	}
	// isDebug was never set, so /debug/gc and /debug/pprof were absent from every build. That is
	// not this core being stricter than upstream -- upstream gates them the same way -- it is a
	// switch nobody wired, which is a different defect and needs a different fix.
	//
	// log-level: debug is the trigger, because it is the one the user already reaches for when
	// they want the core to tell them more, and because it makes the exposure legible: the same
	// line that turns on verbose logging turns on the profiler. The controller's own unguarded
	// notice already says what an unauthenticated address means; this does not change who can
	// reach it, only what is behind it once they do.
	server.IsDebug = cfg.General.LogLevel == log.DEBUG
	server.Cors = route.Cors{
		AllowOrigins:        controller.Cors.AllowOrigins,
		AllowPrivateNetwork: controller.Cors.AllowPrivateNetwork,
	}
	// external-controller-unix is deliberately NOT forwarded: this binding already owns
	// UnixAddr for its App Group control plane, and route.Config has one slot. Honouring the
	// user's path here would replace the channel the containing app talks to, which is not a
	// restriction on the user so much as a collision -- reported as such rather than silently
	// preferred either way.
	return server
}

// recreateControlPlane is the only place a live configuration reaches route.ReCreateServer, and
// it exists because upstream's applyRoute (hub/hub.go:60-63) is TWO statements, not one:
//
//	if cfg.Controller.ExternalUI != "" { route.SetUIPath(cfg.Controller.ExternalUI) }
//	route.ReCreateServer(...)
//
// Only the second was ported when the controller surface was wired. The result was a field
// consumed exactly halfway: executor.ApplyConfig downloaded the dashboard the configuration
// named -- the seconds a user waits on first start -- and then nothing served it, because
// hub/route/server.go:159 mounts /ui only when the package-level uiPath is set and hub.go:62 is
// its sole assignment in the tree. A device answered 404 for every /ui path while the files sat
// in the container. Paying for a download and serving nothing is worse than either whole answer.
//
// The order is load-bearing, which is why these are one function rather than two statements to
// remember in two paths: router() reads uiPath while it builds the route table, so a SetUIPath
// after ReCreateServer configures the NEXT server. Same shape as the defect that put this file's
// neighbour here -- whoever calls last decides.
func recreateControlPlane(cfg *config.Config, bindingSocketPath string) *route.Config {
	if cfg != nil && cfg.Controller != nil && cfg.Controller.ExternalUI != "" {
		route.SetUIPath(cfg.Controller.ExternalUI)
	}
	server := controllerServerConfig(cfg, bindingSocketPath)
	route.ReCreateServer(server)
	userControllerLive.Store(server.Addr != "" || server.TLSAddr != "")
	return server
}

// applyExternalController re-creates the control-plane server so the user's configured
// controller listens alongside this binding's App Group socket.
//
// It is the RELOAD path's entry point, and the entry point for a Start outside the extension.
// A Start inside the extension goes through startControlPlane instead, which does the same
// thing plus the readiness wait. It used to run on both, and that was the defect: the extension
// Start then called route.ReCreateServer a second time with only the socket, closing the
// listener this function had opened. ReCreateServer replaces the set; it does not merge.
//
// One caveat is real and is reported rather than hidden: route.ReCreateServer builds every
// listener from one router, and this binding sets SetEmbedMode(true) for its own socket
// .
// Embed mode is process-global, so the user's controller serves the same reduced route set --
// reads, proxy selection, connection close -- without PUT/PATCH /configs, /restart or
// /upgrade. Separating the two would need the two listeners to carry different routers, which
// upstream's shape does not offer; that is a fork delta with its own cost, not something to
// slip in here.
func applyExternalController(cfg *config.Config) {
	path := setupClashAPIPath
	if path == "" {
		return
	}
	// startControlPlane refuses an over-long socket path with a named error; this path had no
	// such check and handed it to route.ReCreateServer, whose startUnix logs "unix listen error"
	// and returns, leaving no socket and no failure anywhere the caller can see. That silence is
	// not theoretical: a test whose name pushed the path to 130 bytes produced a probe reading
	// "the binding socket does not exist outside the extension", which looks like a fact about
	// this branch and is a fact about Darwin's 103-byte sockaddr_un.
	// Resolved once, before anything reads the pathname. Everything below uses the
	// resolved value, and that is the fix for a defect this function shipped: it
	// passed the resolved address to recreateControlPlane and then went on using
	// the raw one, so on a profile that binds no socket the reload still chmod'ed
	// the pathname and logged "secure Clash API Unix socket: no such file" -- an
	// error about an absence that is the design.
	socket := bindingSocketPathFor(path)
	if len([]byte(socket)) > clashAPIMaxUnixPathBytes {
		log.Errorln("[iOS] Clash API Unix path is %d bytes; Darwin limit is %d: %s",
			len([]byte(socket)), clashAPIMaxUnixPathBytes, socket)
	}
	if probe := controllerServerConfig(cfg, socket); probe.Addr == "" && probe.TLSAddr == "" &&
		!userControllerLive.Load() {
		// Nothing configured and nothing listening: leave the socket as Setup created it rather
		// than tearing down and rebuilding a listener the app is already talking to.
		//
		// "Nothing configured" alone was the condition once, and it read as "nothing to build",
		// which was true. It was also "nothing to close", which was not: a reload that took the
		// user's external-controller OUT returned here and left the old listener, old secret and
		// all, answering until the tunnel died. Upstream re-creates the set on every apply; this
		// only skips when the set is already what the configuration says.
		return
	}
	server := recreateControlPlane(cfg, socket)
	if server.Addr == "" && server.TLSAddr == "" {
		log.Infoln("[Apple] external-controller removed from the configuration: closed")
	} else {
		log.Infoln("[Apple] external-controller listening as configured: addr=%q tls=%q", server.Addr, server.TLSAddr)
	}
	// Upstream's startUnix chmods 0666 on every re-create, so the App Group socket has to be
	// narrowed again here. Leaving it out is what made a single reload widen it for the rest of
	// the session -- a published 0600 contract broken by a path that never mentioned
	// permissions.
	//
	// Developer-facing, not reader-facing: nothing the user writes causes this and nothing they
	// can write fixes it. It is logged rather than returned because reload has already committed
	// the configuration through ApplyConfig, and failing here would report a rollback that did
	// not happen -- the same reasoning the proxy-share reload uses two functions away.
	if socket == "" {
		// No socket of ours went into the server above, so there is no mode to
		// narrow and nothing upstream's startUnix could have widened.
		return
	}
	if err := secureBindingControlSocket(socket); err != nil {
		log.Errorln("[iOS] %v", err)
	}
}
