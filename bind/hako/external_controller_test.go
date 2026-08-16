package hako

import (
	"strings"
	"testing"

	"github.com/TokenPLS/Hako/config"
	C "github.com/TokenPLS/Hako/constant"
	"github.com/TokenPLS/Hako/constant/features"
)

// The product ruling is one sentence: what the user writes is what runs. No permission gate, no
// downgrade when a non-loopback address carries no secret, no condition this side invented. The
// only thing that could ever justify a restriction is App Review refusing the surface, and then
// the evidence would be the review text, not a prediction.
//
// So the controller's address, TLS address, secret, CORS and DoH path travel from the
// configuration to route.ReCreateServer unchanged.
func TestControllerConfigReachesTheServerAsWritten(t *testing.T) {
	const document = `
external-controller: 0.0.0.0:9090
external-controller-tls: 0.0.0.0:9443
secret: hunter2
external-doh-server: /dns-query
external-controller-cors:
  allow-origins: ["https://example.invalid"]
  allow-private-network: true
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	_, ours := parseBoth(t, document)
	finalizeConfigForIOS(ours, true)

	got := controllerServerConfig(ours, "/tmp/hako-test.sock")
	if got.Addr != "0.0.0.0:9090" {
		t.Errorf("addr = %q, want the address the user wrote", got.Addr)
	}
	if got.TLSAddr != "0.0.0.0:9443" {
		t.Errorf("tls addr = %q, want the address the user wrote", got.TLSAddr)
	}
	if got.Secret != "hunter2" {
		t.Error("secret did not reach the server")
	}
	if got.DohServer != "/dns-query" {
		t.Errorf("doh server = %q", got.DohServer)
	}
	if len(got.Cors.AllowOrigins) != 1 {
		t.Errorf("cors origins = %v", got.Cors.AllowOrigins)
	}
	// The binding's own App Group socket is not replaced by the user's controller; both listen.
	if got.UnixAddr != "/tmp/hako-test.sock" {
		t.Errorf("the binding's own socket was dropped: %q", got.UnixAddr)
	}
}

// No gate: a configuration that names a controller gets one, with nothing having been switched
// on anywhere. This is the ruling stated as a test, because the previous two attempts at this
// field both added a condition and both were rejected.
func TestNoPermissionIsRequiredForTheControllerToRun(t *testing.T) {
	const document = `
external-controller: 0.0.0.0:9090
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	_, ours := parseBoth(t, document)
	finalizeConfigForIOS(ours, true)
	if got := controllerServerConfig(ours, "/tmp/hako-test.sock"); got.Addr == "" {
		t.Error("the controller address was dropped with no permission asked for; the ruling is " +
			"that what the user writes is what runs")
	}
}

// A non-loopback address with no secret is honoured, exactly as upstream honours it. The core
// still says so -- saying is not restricting -- but it does not move the listener.
func TestAnUnguardedControllerIsHonouredAndAnnounced(t *testing.T) {
	const document = `
external-controller: 0.0.0.0:9090
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	_, ours := parseBoth(t, document)
	finalizeConfigForIOS(ours, true)
	if got := controllerServerConfig(ours, "/tmp/s.sock"); got.Addr != "0.0.0.0:9090" {
		t.Errorf("addr = %q; an unguarded controller is not downgraded to loopback -- that was "+
			"stricter than upstream and not required by the platform, which is this repository's "+
			"own definition of an invented constraint", got.Addr)
	}
	notices := unguardedControllerNotices(mustUnmarshalRaw(t, document))
	if len(notices) == 0 {
		t.Error("nothing was said about an unguarded network-reachable controller")
	}
	for _, notice := range notices {
		if strings.Contains(notice, "refus") || strings.Contains(notice, "not started") {
			t.Errorf("the notice describes a restriction that no longer exists: %s", notice)
		}
	}
}

// A configuration that names no controller leaves the binding's own socket alone.
func TestASilentConfigurationLeavesOnlyTheBindingSocket(t *testing.T) {
	const document = `
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	_, ours := parseBoth(t, document)
	finalizeConfigForIOS(ours, true)
	got := controllerServerConfig(ours, "/tmp/hako-test.sock")
	if got.Addr != "" || got.TLSAddr != "" {
		t.Errorf("a network listener appeared for a configuration that asked for none: %+v", got)
	}
	if got.UnixAddr != "/tmp/hako-test.sock" {
		t.Error("the binding's own socket was dropped")
	}
}

// external-ui was the last field held back, and it was held back ("downloads happen
// app-side"), not by the platform: Apple does not stop an extension from making an outbound
// request -- TN3120 only bars hosting a listener, and macOS needs one entitlement it already
// should have. Under the standard the product stated, that makes it a decision of ours rather
// than a limit, and the ruling is to behave as upstream does.
//
// Upstream's behaviour, read off component/updater/update_ui.go:51-77: naming either the path
// or the name arms the auto-download, and AutoDownloadUI then downloads ONLY when the directory
// is empty ("UI already exists, skip downloading" otherwise). So in this product's normal flow
// -- the app materialises the dashboard into the container first -- nothing is fetched inside
// the extension. The download is the fallback for a directory nobody filled.
func TestExternalUIIsHonouredAsUpstreamHonoursIt(t *testing.T) {
	const document = `
external-controller: 127.0.0.1:9090
external-ui: ui
external-ui-name: dashboard
external-ui-url: https://example.invalid/ui.zip
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	mihomo, ours := parseBoth(t, document)
	finalizeConfigForIOS(ours, true)

	for name, pair := range map[string][2]string{
		"external-ui":      {mihomo.Controller.ExternalUI, ours.Controller.ExternalUI},
		"external-ui-name": {mihomo.Controller.ExternalUIName, ours.Controller.ExternalUIName},
		"external-ui-url":  {mihomo.Controller.ExternalUIURL, ours.Controller.ExternalUIURL},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%s: mihomo %q, ours %q", name, pair[0], pair[1])
		}
	}
}

// Honouring a field means inheriting its validation too, and that is not free here. Upstream
// checks external-ui against C.Path.IsSafePath (config/config.go:861-862) and fails the WHOLE
// configuration when the path is not under the home directory or SAFE_PATHS. While the field
// was stripped before ParseRawConfig, that check could never fire; now it can.
//
// The practical shape: a subscription copied from a desktop that writes an absolute path --
// external-ui: /etc/clash/ui -- stops the tunnel from starting, where it used to start with the
// field silently dropped. That is exactly what desktop mihomo does with the same file, so it is
// the yardstick behaviour and it stays. What must not happen is discovering it from a user.
//
// A relative path is the shape that works, on every platform: it resolves under the home
// directory, which inside the extension is the container the app already writes the dashboard
// into.
//
// The rest of this test used to assert that an ABSOLUTE path outside the home directory fails
// the whole configuration, and that assertion was wrong about the product this repository ships.
// constant/path.go:88 reads
//
//	if p.allowUnsafePath || features.CMFA { return true }
//
// and every Apple artifact is built with -tags cmfa (cmd/build_libbox baseTags), so
// constant/features/cmfa.go sets CMFA = true and IsSafePath is unconditionally true in the
// shipped binary. The test passed only because `go test` ran without the tags the product is
// built with.
//
// I had read that exact line earlier the same day, while checking whether anything set
// allowUnsafePath, and concluded the check applied. The `|| features.CMFA` was in the text in
// front of me. The consuming lane found it by running the suite under the artifact's real tag
// set, which is the only way this class of mistake surfaces: a test that measures a different
// feature set than the one that ships cannot be wrong in a way its own output reveals.
//
// So what is pinned now is the yardstick claim, which holds in both worlds: whatever upstream's
// parser decides about a path, this core decides the same. The absolute-path outcome is read off
// upstream rather than asserted, so this test states the truth under either tag set instead of
// one of them.
func TestExternalUIPathHandlingMatchesUpstreamUnderEitherFeatureSet(t *testing.T) {
	document := func(path string) string {
		return `
external-controller: 127.0.0.1:9090
external-ui: ` + path + `
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	}

	for _, path := range []string{"/etc/clash/ui", "ui"} {
		_, upstreamErr := config.Parse([]byte(document(path)))
		_, oursErr := parseConfigForIOS(document(path), true)
		if (upstreamErr == nil) != (oursErr == nil) {
			t.Errorf("external-ui %q: upstream %v, ours %v -- the yardstick decides which paths a "+
				"configuration may name, in whichever build this is", path, upstreamErr, oursErr)
		}
	}

	// A relative path has to work in every build, because it is the shape this product actually
	// uses: the app materialises the dashboard into the container and names it relatively.
	if _, err := parseConfigForIOS(document("ui"), true); err != nil {
		t.Errorf("a relative external-ui must parse: %v", err)
	}
}

// The CMFA fact itself, stated where somebody will trip over it. It is not a defect -- upstream
// ships the same escape for the same tag -- but it silently disarms four callers of IsSafePath,
// including PATCH /configs' path field, and the batch that opened that route did not know.
func TestSafePathCheckingIsDisarmedInEveryShippedArtifact(t *testing.T) {
	outside := "/etc/clash/ui"
	safe := C.Path.IsSafePath(outside)
	if features.CMFA != safe {
		t.Errorf("features.CMFA=%v but IsSafePath(%q)=%v; constant/path.go:88 short-circuits on "+
			"CMFA, so these two cannot disagree", features.CMFA, outside, safe)
	}
	if !features.CMFA {
		t.Log("this run is NOT the shipped feature set: cmd/build_libbox builds every Apple " +
			"artifact with -tags cmfa, so a suite run without it measures a different binary")
	}
}
