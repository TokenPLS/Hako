package hako

import (
	"strings"
	"testing"

	"github.com/TokenPLS/Hako/config"
)

// The unguarded-controller notice tells a reader what someone reaching that address can do, and
// the list has to be true. It said "change proxies, rules and mode" -- accurate until PATCH
// /configs was opened, which added the one consequence a reader would weigh differently:
// allow-lan is in the PATCH body, so a stranger on the same network can turn the device into an
// open proxy without touching the configuration file or the app.
//
// The consuming lane found the hole in this side's reasoning. The argument for opening PATCH
// had been "a PATCH is someone pressing something, unlike a subscription arriving silently".
// That is true only if the person pressing is the one holding the device. With
// external-controller on 0.0.0.0 and no secret, it is anyone on the network -- two steps, each
// individually unremarkable, composing into exactly the exposure the allow-lan permission gate
// exists to prevent.
//
// Opening PATCH is still right, for the reason they gave rather than the one this side gave:
// once an unauthenticated controller is reachable, allow-lan is the lightest thing available to
// whoever reaches it. Guarding PATCH would be locking the window. What the notice owes the
// reader is an accurate list of what the unlocked door leads to.
func TestUnguardedControllerNoticeNamesTheOpenProxyConsequence(t *testing.T) {
	raw := &config.RawConfig{ExternalController: "0.0.0.0:9090"}
	notices := unguardedControllerNotices(raw)
	if len(notices) != 1 {
		t.Fatalf("expected one notice for an unguarded controller, got %d: %v", len(notices), notices)
	}
	for _, required := range []string{"allow-lan", "proxy"} {
		if !strings.Contains(notices[0], required) {
			t.Errorf("the notice never mentions %q, so a reader cannot weigh the worst outcome:\n%s",
				required, notices[0])
		}
	}
}

// A secret, or loopback, and the notice stays quiet -- otherwise it fires for readers nothing
// happened to and stops being read.
func TestGuardedOrLoopbackControllerSaysNothing(t *testing.T) {
	for name, raw := range map[string]*config.RawConfig{
		"secret set": {ExternalController: "0.0.0.0:9090", Secret: "hunter2"},
		"loopback":   {ExternalController: "127.0.0.1:9090"},
		"unset":      {},
	} {
		if notices := unguardedControllerNotices(raw); len(notices) != 0 {
			t.Errorf("%s produced %v", name, notices)
		}
	}
}
