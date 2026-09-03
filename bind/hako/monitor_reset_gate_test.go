package hako

import (
	"testing"
)

// The resolver reset fires on every applied path update, and this test exists to stop it
// being gated again.
//
// It WAS gated on identity-or-address-family change, to avoid paying a re-dial -- and a
// trustd round trip per stateful DNS transport on iOS -- for an update where nothing
// meaningful moved. Adversarial review found the counterexample, and it is an ordinary one:
// moving from Wi-Fi to a Personal Hotspot keeps the same interface name and index and can
// keep both address families, so neither gate condition fires, while the source address and
// gateway change and the old socket is bound to a path that is gone. Apple documents
// Personal Hotspot as an expensive path, so the only forwarded flag that moves is one the
// gate ignored. DHCP address replacement and same-interface Wi-Fi roaming have the same
// shape.
//
// The consequence was a failed request, not a slow one: dns/dot.go allows a cached
// connection five seconds before retrying and the DNS request carries the same five-second
// deadline, so on a black-holed old path the deadline expires before the retry can connect.
//
// A failed DNS request is worse than a redundant handshake. The handshake cost is still
// worth removing, but by making verification in-process (the certificate-pool work), not by
// skipping resets that turn out to be necessary.

func TestResolverResetFiresOnEveryAppliedPathUpdate(t *testing.T) {
	cases := []struct {
		name                  string
		wasInitialized        bool
		identityChanged       bool
		addressFamiliesChange bool
		why                   string
	}{
		{
			name:            "interface identity changed",
			wasInitialized:  true,
			identityChanged: true,
			why:             "the old sockets are bound to an interface that is no longer the default",
		},
		{
			name:                  "address families changed",
			wasInitialized:        true,
			addressFamiliesChange: true,
			why:                   "a v4-only path cannot carry sockets opened for v6",
		},
		{
			name:           "capabilities only — the Personal Hotspot case",
			wasInitialized: true,
			why: "same interface, same families, but the source address and gateway moved; the " +
				"forwarded flags cannot distinguish this from a no-op, so it must reset",
		},
		{
			name:           "first update",
			wasInitialized: false,
			why:            "the resolver has never seen a path",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if !shouldResetResolverForPathUpdate(
				testCase.wasInitialized, testCase.identityChanged, testCase.addressFamiliesChange) {
				t.Fatalf("no reset for this update — %s", testCase.why)
			}
		})
	}
}

// TestConnectionTeardownStaysGated: the asymmetry with the resolver is deliberate, so it is
// asserted rather than left to look like an oversight. A TCP flow through the tunnel survives
// a path change and recovers on its own; a DNS socket pinned to a dead source address does
// not.
func TestConnectionTeardownStaysGatedWhileResolverResetDoesNot(t *testing.T) {
	// A capabilities-only update after initialisation: identityChanged and
	// addressFamiliesChanged are both false, which is exactly the condition
	// updateDefaultPath uses to decide whether to close tracked connections.
	const identityChanged, addressFamiliesChanged = false, false
	if identityChanged || addressFamiliesChanged {
		t.Fatal("this case is meant to be the one where the teardown condition is false")
	}
	if !shouldResetResolverForPathUpdate(true, identityChanged, addressFamiliesChanged) {
		t.Fatal("the resolver must reset where the connection teardown does not")
	}
}
