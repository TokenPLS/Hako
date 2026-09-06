package hako

import (
	"strings"
	"testing"

	"github.com/TokenPLS/Hako/config"
)

// The RESTful API surface follows the same rule the user set for the listener surface: if a
// shipping App Store app does it, the platform is not the obstacle. sing-box.app is on the Mac
// App Store and its core carries clash_api / external_controller / external_ui / secret --
// reproducible with `strings -a
// /Applications/sing-box.app/Contents/Frameworks/Library.framework/Versions/A/Library`.
//
// So these are honoured as written. It stays opt-in exactly as upstream has it: a config that
// does not name external-controller gets no API, which is mihomo's own default.
func TestControllerSurfaceMatchesUpstream(t *testing.T) {
	const document = `
external-controller: 127.0.0.1:9090
external-controller-tls: 127.0.0.1:9443
external-controller-unix: /tmp/hako-test.sock
external-controller-cors:
  allow-origins: ["https://example.invalid"]
  allow-private-network: true
external-doh-server: /dns-query
secret: hunter2
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	mihomo, ours := parseBoth(t, document)

	for name, pair := range map[string][2]string{
		"external-controller":      {mihomo.Controller.ExternalController, ours.Controller.ExternalController},
		"external-controller-tls":  {mihomo.Controller.ExternalControllerTLS, ours.Controller.ExternalControllerTLS},
		"external-controller-unix": {mihomo.Controller.ExternalControllerUnix, ours.Controller.ExternalControllerUnix},
		"external-doh-server":      {mihomo.Controller.ExternalDohServer, ours.Controller.ExternalDohServer},
		"secret":                   {mihomo.Controller.Secret, ours.Controller.Secret},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%s: mihomo %q, ours %q", name, pair[0], pair[1])
		}
	}
	if len(mihomo.Controller.Cors.AllowOrigins) != len(ours.Controller.Cors.AllowOrigins) {
		t.Errorf("cors allow-origins: mihomo %d, ours %d",
			len(mihomo.Controller.Cors.AllowOrigins), len(ours.Controller.Cors.AllowOrigins))
	}
}

// external-ui was the one member of this family that stayed stripped, and this test pinned that.
// It no longer does, and the reason it stopped is worth keeping: the hold was
// ("downloads happen app-side"), which is an architecture decision of ours, not a platform
// limit -- Apple does not stop an extension from making an outbound request. Under the standard
// the product stated (upstream allows it, the platform allows it, therefore we allow it), that
//
// The parity assertion lives in external_controller_test.go now. What is left here is the guard
// against the reason coming back: if someone re-strips these three, they need a platform fact,
// not.
func TestExternalUIIsNoLongerHeldBackByAnArchitectureDecision(t *testing.T) {
	const document = `
external-controller: 127.0.0.1:9090
external-ui: ui
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	_, ours := parseBoth(t, document)
	finalizeConfigForIOS(ours, true)
	if ours.Controller.ExternalUI == "" {
		t.Error("external-ui was stripped again. This is not a platform limit -- an extension " +
			"may make outbound requests, and upstream only downloads when the directory the app " +
			"was supposed to fill is empty. Re-stripping needs a platform fact")
	}
}

// An API that can reconfigure the running tunnel, reachable from the network, with no secret,
// is worth a line. mihomo behaves the same and so do we -- saying so is not refusing.
func TestANetworkReachableControllerWithoutASecretIsAnnounced(t *testing.T) {
	for name, testCase := range map[string]struct {
		document string
		announce bool
	}{
		"wildcard bind, no secret": {"external-controller: 0.0.0.0:9090\n", true},
		"wildcard bind, secret":    {"external-controller: 0.0.0.0:9090\nsecret: hunter2\n", false},
		"loopback, no secret":      {"external-controller: 127.0.0.1:9090\n", false},
	} {
		t.Run(name, func(t *testing.T) {
			raw, err := config.UnmarshalRawConfig([]byte(testCase.document +
				"proxies: []\nproxy-groups: []\nrules:\n  - MATCH,DIRECT\n"))
			if err != nil {
				t.Fatalf("fixture: %v", err)
			}
			notices := unguardedControllerNotices(raw)
			if got := len(notices) > 0; got != testCase.announce {
				t.Errorf("announced = %v, want %v (%v)", got, testCase.announce, notices)
			}
			for _, notice := range notices {
				if strings.Contains(notice, "hunter2") {
					t.Error("the notice renders the secret")
				}
			}
		})
	}
}
