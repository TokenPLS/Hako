package hako

import "sync/atomic"

// allowLanPermitted gates the one field in the local-proxy group that decides who can reach
// the device: allow-lan. Everything else in that group configures a listener; this one moves
// it from 127.0.0.1 to every interface (listener/listener.go:709-718 genAddr).
//
// The gate exists because of when this core changed, not because of what the platform allows.
// The capability itself ships on the Mac App Store -- Shadowrocket's packet tunnel declares
// NSLocalNetworkUsageDescription for a local proxy service and imports listen/bind/accept. But
// that precedent is for a switch the user flips, not for a value arriving inside an imported
// subscription. Honouring it straight would have changed the security posture of already
// shipped users with nobody pressing anything: same config, same device, new kernel, open
// proxy on every network they join. A change nobody asked for is not a capability.
//
// The shape is fixed by one constraint from the ruling: the safe state must not depend on the
// app remembering to ask for it. So the permission is a bool whose zero value is "no" -- a
// build that never calls SetAllowLanPermitted never exposes anything, and forgetting is
// indistinguishable from declining. An enum with a "default" member, or a parameter the app
// passes on Start, would both have failed that test the first time somebody forgot.
//
// It is read on every parse rather than latched at Start, so revoking takes effect on the next
// reload instead of the next process launch.
//
// The permission is a CEILING, not a request. Two different people say yes, in two different
// places, before anything is exposed:
//
//	exposed = permission (the person holding the device, in the app)
//	          AND allow-lan (the configuration, asking for it)
//
// Config asks and nobody permitted -> stripped, and reported through /hako/v1/deviations.
// Permitted and the config never asked -> still loopback, because nothing requested it.
//
// The second half is the one that will look like a simplification later ("the user turned
// local-network sharing on, so turn allow-lan on"). Doing that would let an app-level switch
// reach into every configuration the user ever imports, including the ones whose authors never
// asked for it -- which is the failure this gate exists to prevent, arriving from the other
// side. TestPermissionAloneExposesNothingWithoutTheConfigurationAsking pins it, and that test
// was mutation-checked: making the permission imply allow-lan turns it red.
//
// KNOWN BYPASS, recorded rather than quietly tolerated (2026-08-10). This gate watches the
// configuration. It does not watch the control plane, and since PATCH /configs was opened,
// allow-lan is in that request body. So the exposure this gate exists to prevent can arrive in
// two steps that each look ordinary:
//
//  1. a subscription writes external-controller: 0.0.0.0:9090 with no secret -- no gate at all
//  2. anyone on the same network sends PATCH /configs {"allow-lan": true}
//
// The person "pressing something" in step 2 is not necessarily the person holding the device,
// which is what the reasoning for opening PATCH originally assumed. The consuming lane caught
// that.
//
// It is recorded rather than closed, and the reason is that closing it here would be the wrong
// place: once an unauthenticated controller is reachable off-device, allow-lan is the lightest
// thing available to whoever reaches it -- they can already select proxies, read the running
// configuration and close connections. Guarding PATCH would lock the window.
//
// What the inconsistency actually shows is where the gates are uneven: allow-lan: true needs a
// person to agree in the app, and external-controller: 0.0.0.0 with no secret needs nothing,
// while the consequence of the second is at least as large. That unevenness is now something
// someone looked at and left, rather than something nobody had put side by side.
// unguardedControllerNotices names the open-proxy outcome for exactly this reason.
//
// Granularity is global rather than per-profile, and that is a categorical answer rather than
// an implementation convenience: allow-lan decides which interface the listening socket binds
// to, which is about whether THIS DEVICE can be reached on whatever network it has joined. A
// profile decides which exit the traffic takes. Making the permission per-profile would give a
// subscription's author a say in whether the device is open on a cafe's Wi-Fi -- exactly the
// thing being prevented.
var allowLanPermitted atomic.Bool

// SetAllowLanPermitted records whether the containing app has obtained the user's agreement to
// expose the configured local proxy to the local network. It is app-level state, not
// per-profile: the question it answers is "may this device serve the network it is on", which
// is about the device and the person holding it rather than about one subscription.
//
// Until it is called with true, a configuration's allow-lan is reported as gated through
// /hako/v1/deviations and the listener stays on 127.0.0.1.
func SetAllowLanPermitted(permitted bool) {
	allowLanPermitted.Store(permitted)
}

// AllowLanPermitted reports the permission held by THIS process.
//
// That qualifier is the whole content of this comment. The containing app and the extension
// are two processes with two Go runtimes and therefore two copies of this variable; the
// extension's is the one that decides anything, and a call from the app reads a copy nothing
// ever writes -- it answers false forever. An earlier version of this comment said the app
// could "render its own switch from the value the core is actually using", which is exactly
// the mistake it now warns against: the app would render a switch that is always off.
//
// Inside the extension it is the honest read, and that is what it is for. The cross-process
// question -- "what is the running core doing with my allow-lan" -- is answered by
// /hako/v1/deviations, which reports allow-lan as gated when the permission is absent and
// stops reporting it once granted. That answer travels between processes; this one does not.
func AllowLanPermitted() bool {
	return allowLanPermitted.Load()
}
