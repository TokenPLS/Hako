package hako

import (
	"net"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The tvOS seat exists so tvOS stops arriving here as iOS. It was created
// carrying the iOS values on loan, and exactly one of them has since been
// measured apart: a third-party process on tvOS cannot bind an AF_UNIX socket
// . The rest are still on loan -- not the memory ceiling
// (os_proc_available_memory is available on tvOS 13.0+ and has never been read on
// the device), not whether the Caches directory tvOS forces resources into
// survives a reboot. Until they are measured, the iOS behavior is the
// conservative one, and the seat is what gives those measurements somewhere to
// land.

func TestTVOSPacketTunnelIsANamedRuntimeProfile(t *testing.T) {
	profile, err := normalizeRuntimeProfile(RuntimeProfileTVOSPacketTunnel)
	if err != nil {
		t.Fatalf("normalizeRuntimeProfile(%q) = %v", RuntimeProfileTVOSPacketTunnel, err)
	}
	if profile != runtimeProfileTVOSPacketTunnel {
		t.Fatalf("normalizeRuntimeProfile(%q) = %v, want the tvOS profile",
			RuntimeProfileTVOSPacketTunnel, profile)
	}
	if got := profile.String(); got != RuntimeProfileTVOSPacketTunnel {
		t.Fatalf("profile.String() = %q, want %q", got, RuntimeProfileTVOSPacketTunnel)
	}
	if profile == runtimeProfileIOSPacketTunnel {
		t.Fatal("the tvOS profile is the same value as the iOS one; then it is not a seat, " +
			"and every diagnostic that prints a profile keeps reporting an Apple TV as an iPhone")
	}
}

// tvOS carried the iOS policy unchanged until a device said otherwise, and one
// field has now been measured apart. Everything else must still match: the
// comparison is on the whole struct rather than a list, so a field added later
// is covered without anyone remembering to add it, and the exceptions are named
// one at a time.
//
// Measured on an Apple TV 4K running tvOS 26.6: a third-party process cannot
// bind an AF_UNIX socket at any filesystem location. Nine candidate paths, every
// one EPERM. Upstream sing-box carries the same split for the same reason
// (experimental/libbox/command_server.go: `if !sTVOS { listenUNIX() } else {
// listenTCP() }`).
var tvOSPolicyExceptions = map[string]bool{"bindsUnixControlSocket": true}

func TestTVOSPolicyIsFieldForFieldTheIOSPolicy(t *testing.T) {
	for _, underNE := range []bool{true, false} {
		tvOS := runtimePolicyFor(runtimeProfileTVOSPacketTunnel, underNE)
		iOS := runtimePolicyFor(runtimeProfileIOSPacketTunnel, underNE)
		// The seat itself is the one intended difference.
		if tvOS.profile != runtimeProfileTVOSPacketTunnel {
			t.Fatalf("underNetworkExtension=%v: policy carries profile %v, want the tvOS seat",
				underNE, tvOS.profile)
		}
		tvOS.profile = iOS.profile
		if tvOS != iOS {
			for _, field := range differingPolicyFields(tvOS, iOS) {
				if !tvOSPolicyExceptions[field] {
					t.Fatalf("underNetworkExtension=%v: tvOS policy differs from iOS in %s, "+
						"which is not one of the measured exceptions. A divergence has to be "+
						"a deliberate edit with a device behind it, not a side effect.",
						underNE, field)
				}
			}
		}
	}
}

func TestTVOSResolvesTheSameOwnerMetadataAsIOS(t *testing.T) {
	for _, underNE := range []bool{true, false} {
		tvOS := runtimePolicyFor(runtimeProfileTVOSPacketTunnel, underNE).processMetadata()
		iOS := runtimePolicyFor(runtimeProfileIOSPacketTunnel, underNE).processMetadata()
		if tvOS != iOS {
			t.Fatalf("underNetworkExtension=%v: tvOS process metadata = %+v, iOS = %+v",
				underNE, tvOS, iOS)
		}
	}
}

// The policy struct is not the whole story. Two shipping gates decide behavior
// by comparing the profile directly, and both would have flipped for tvOS the
// moment the seat existed:
//
//   - clash_api.go let the geo updater run wherever the profile is not iOS. A
//     tvOS seat would have turned it on, sending a 17 MB GeoIP.dat fetch and
//     unpack into a Network Extension whose ceiling nobody has measured.
//   - service.go armed the self-expiring pause timer only for iOS. A tvOS seat
//     would have removed it, leaving a tvOS pause to wait on a wake() callback
//     that may never arrive -- the exact stranding that timer exists to stop.
//
// Both now ask this predicate instead, so "tvOS carries the iOS values" is one
// fact in one place rather than a coincidence repeated at every call site.
func TestTVOSInheritsTheIOSPacketTunnelBehaviorPredicate(t *testing.T) {
	if !runtimeProfileTVOSPacketTunnel.inheritsIOSPacketTunnelBehavior() {
		t.Fatal("the tvOS profile does not inherit iOS packet tunnel behavior; " +
			"the geo updater turns on and the end-pause timer turns off, neither of which was decided")
	}
	if !runtimeProfileIOSPacketTunnel.inheritsIOSPacketTunnelBehavior() {
		t.Fatal("the iOS profile does not inherit its own behavior")
	}
	for _, profile := range []runtimeProfile{runtimeProfileMacOSPacketTunnel, runtimeProfileMacOSApplication} {
		if profile.inheritsIOSPacketTunnelBehavior() {
			t.Fatalf("%v inherits iOS packet tunnel behavior; the macOS profiles were measured "+
				"out of it on purpose", profile)
		}
	}
}

// Absence cannot be asserted by running the code -- a gate someone adds
// tomorrow in a file this test never calls would not fail any behavior test.
// So this reads the source. It is scoped to the shape that actually caused the
// bug: comparing a profile against the iOS constant with == or !=, which
// silently answers "no" for tvOS.
func TestNoShippingGateComparesAgainstTheIOSProfileDirectly(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}
	// Positive control: the pattern must be able to match at all. If this
	// regexp stops matching the shape it is meant to catch, the scan below
	// reports a clean tree for the wrong reason.
	pattern := regexp.MustCompile(`[!=]=\s*runtimeProfileIOSPacketTunnel|runtimeProfileIOSPacketTunnel\s*[!=]=`)
	if !pattern.MatchString("if currentRuntimeProfile() != runtimeProfileIOSPacketTunnel {") {
		t.Fatal("the scan pattern no longer matches the shape it exists to catch")
	}

	var offenders []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		// runtime_profile.go is where the enum and the predicate live; its own
		// switch and the predicate body are the declaration, not a gate.
		if name == "runtime_profile.go" {
			continue
		}
		source, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for index, line := range strings.Split(string(source), "\n") {
			if pattern.MatchString(line) {
				offenders = append(offenders, filepath.Join(name)+":"+itoa(index+1)+" "+strings.TrimSpace(line))
			}
		}
	}
	if len(offenders) > 0 {
		t.Fatalf("these gates decide behavior by comparing against the iOS profile, which answers "+
			"\"no\" for tvOS without anyone deciding that:\n  %s\nuse "+
			"inheritsIOSPacketTunnelBehavior() unless the difference is the point",
			strings.Join(offenders, "\n  "))
	}
}

func differingPolicyFields(got, want appleRuntimePolicy) []string {
	gotValue := reflect.ValueOf(got)
	wantValue := reflect.ValueOf(want)
	var fields []string
	for index := 0; index < gotValue.NumField(); index++ {
		if !reflect.DeepEqual(
			gotValue.Field(index).String()+gotValue.Field(index).Type().String(),
			wantValue.Field(index).String()+wantValue.Field(index).Type().String(),
		) || gotValue.Field(index).Kind() == reflect.Bool &&
			gotValue.Field(index).Bool() != wantValue.Field(index).Bool() {
			fields = append(fields, gotValue.Type().Field(index).Name)
		}
	}
	if len(fields) == 0 {
		fields = append(fields, "(no field differs; the struct comparison and this reporter disagree)")
	}
	return fields
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var digits []byte
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	return string(digits)
}

// The control plane's own Unix socket cannot exist on tvOS. The kernel
// reached tun-verified on a real Apple TV and shut down two milliseconds later,
// because startControlPlane waits for a listener that can never come up: a
// three-second dial loop against a socket whose bind returned EPERM.
//
// Two separate failures were seen before the cause was clear, and only the second
// is the real one -- worth recording so nobody fixes the first and declares
// victory. First the path was 109 bytes against Darwin's 103-byte sun_path, since
// tvOS only grants write access to Library/Caches inside the App Group and that
// prefix alone is 98 bytes. Shortening it to 101 bytes cleared that and produced
// `bind: operation not permitted` instead.
func TestTVOSDoesNotBindTheBindingControlSocket(t *testing.T) {
	for _, underNE := range []bool{true, false} {
		if runtimePolicyFor(runtimeProfileTVOSPacketTunnel, underNE).bindsUnixControlSocket {
			t.Fatal("the tvOS profile still opens the binding Unix socket; on a device that " +
				"bind returns EPERM, the readiness dial never succeeds, and the core stops " +
				"three seconds after the tunnel came up")
		}
		if !runtimePolicyFor(runtimeProfileIOSPacketTunnel, underNE).bindsUnixControlSocket {
			t.Fatal("iOS stopped binding the control socket; the App Group socket is how the " +
				"containing app reaches the controller there")
		}
		if !runtimePolicyFor(runtimeProfileMacOSPacketTunnel, underNE).bindsUnixControlSocket {
			t.Fatal("macOS stopped binding the control socket")
		}
	}
}

// The resolver answers correctly for every profile. That is worth pinning and it
// is not the thing that was broken.
//
// The first version of this file stopped here, and it was a test that could not
// fail for the defect it was written about: it called bindingSocketPathFor
// itself, fed the result into controllerServerConfig by hand, and asserted on
// what came back. Both production entry points were absent from it. The reload
// path was at that moment passing the resolved address to the listener and the
// RAW pathname to chmod, and this test agreed with itself throughout. Asserting
// on a composition you performed in the test is asserting that you can read your
// own code -- the entry points are below.
func TestTVOSResolvesNoBindingSocketAddress(t *testing.T) {
	const path = "/tmp/hako-test/clash.sock"
	withRuntimeProfile(t, runtimeProfileTVOSPacketTunnel)
	if address := bindingSocketPathFor(path); address != "" {
		t.Fatalf("tvOS resolved a binding socket address %q; binding it returns EPERM on the "+
			"device, and the readiness dial that follows never completes", address)
	}

	for _, profile := range []runtimeProfile{
		runtimeProfileIOSPacketTunnel,
		runtimeProfileMacOSPacketTunnel,
		runtimeProfileMacOSApplication,
	} {
		setupRuntimeProfile.Store(uint32(profile))
		if address := bindingSocketPathFor(path); address != path {
			t.Fatalf("%v resolved %q instead of the binding socket; the containing app "+
				"reaches the controller through it", profile, address)
		}
	}
}

// bindingSocketPathFor asks currentRuntimePolicy(true) -- it hardcodes "under the
// Network Extension" -- and it is called from the reload path and from a Start
// outside the extension, where that is not true.
//
// It is correct today only because no profile's answer depends on placement. That
// is a fact about the policy table, not about the resolver, and nothing was
// holding it: the day someone writes `policy.bindsUnixControlSocket =
// underNetworkExtension`, the resolver silently starts answering about a process
// it is not in. This is what holds it, so that day turns red here instead.
func TestTheBindingSocketDecisionDoesNotDependOnProcessPlacement(t *testing.T) {
	for _, profile := range allRuntimeProfiles() {
		inExtension := runtimePolicyFor(profile, true).bindsUnixControlSocket
		onHost := runtimePolicyFor(profile, false).bindsUnixControlSocket
		if inExtension != onHost {
			t.Fatalf("%v binds the control socket in the extension (%v) and outside it (%v). "+
				"bindingSocketPathFor asks currentRuntimePolicy(true) from both the reload path "+
				"and a non-extension Start, so it now answers about the wrong process on one of "+
				"them -- give it the placement instead of hardcoding it", profile, inExtension, onHost)
		}
	}
}

// Both entry points, running for real, against a decoy.
//
// A regular file is placed at the socket pathname with a mode nothing in this
// package would choose. On a profile that owns the pathname the file is consumed:
// startControlPlane removes it and binds a socket in its place. On tvOS nothing
// there is ours, so it must survive every entry point untouched -- not removed,
// not chmod'ed to 0600, still a regular file with its bytes in it.
//
// The decoy is what makes this a measurement rather than a restatement. Each of
// the three operations has to suppress leaves a different mark on it:
// os.Remove takes the file away, os.Chmod changes its mode, a successful bind
// replaces it with a socket. The reload path was chmod'ing it when this was
// written, and it is the reason this test exists in this shape.
func TestNoControlPlaneEntryPointTouchesThePathnameOnTVOS(t *testing.T) {
	port := freeLoopbackPort(t)
	addr := "127.0.0.1:" + port
	path := shortClashSocketPath(t)

	withRuntimeProfile(t, runtimeProfileTVOSPacketTunnel)
	withSetupClashAPIPath(t, path)
	cfg := controllerConfig(t, addr)
	t.Cleanup(func() { stopClashAPI(path) })

	writeDecoy(t, path)
	if err := startControlPlane(cfg, path); err != nil {
		t.Fatalf("startControlPlane on tvOS: %v -- it must bring up the user's controller and "+
			"return, not fail, and not wait on a socket that cannot exist", err)
	}
	assertDecoyIntact(t, path, "startControlPlane")

	// The user's controller is the whole point of the tvOS path: it is the only
	// listener that profile has, so "we skipped our socket" must not have skipped
	// the thing next to it.
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("tvOS opened no controller at %s: %v -- the socket is what tvOS cannot have; "+
			"the address the user wrote is not", addr, err)
	}
	_ = conn.Close()

	applyExternalController(cfg)
	assertDecoyIntact(t, path, "applyExternalController (the reload path)")

	// Teardown is the third call site and it is deliberately NOT gated as a whole:
	// route.ReCreateServer is what closes the user's controller, and that exists on
	// tvOS. Gating the function instead of the pathname half would have left this
	// listener up after Close.
	stopClashAPI(path)
	assertDecoyIntact(t, path, "stopClashAPI")
	assertNotListening(t, addr, "stopClashAPI on tvOS")
}

// The positive control, and it is not optional: every assertion above is that
// something did NOT happen, which a test whose decoy is unreachable also reports.
// This runs the same decoy through the same entry point on the profile that does
// own the pathname, and requires it to be gone.
//
// What consumes the decoy is upstream, not this package: route's startUnix calls
// syscall.Unlink on the address before it binds (hub/route/server.go), so the
// os.Remove in startControlPlane is belt-and-braces and poisoning it leaves this
// test green -- which was tried, and read for a minute as the control being
// broken. The poison that turns it red is the premise: make bindingSocketPathFor
// answer "" for iOS and the decoy survives an iOS start. A control is proven by
// the poison that reaches what it measures, and this one measures whether the
// profile owns the pathname, not which line clears it.
func TestTheDecoyIsSomethingTheControlPlaneWouldTouch(t *testing.T) {
	path := shortClashSocketPath(t)
	withRuntimeProfile(t, runtimeProfileIOSPacketTunnel)
	withSetupClashAPIPath(t, path)
	t.Cleanup(func() { stopClashAPI(path) })

	writeDecoy(t, path)
	if err := startControlPlane(nil, path); err != nil {
		t.Fatalf("startControlPlane on iOS: %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("nothing at the socket pathname after an iOS start: %v", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("the pathname is %v after an iOS start, not a socket. The decoy survived the "+
			"profile that DOES own this pathname, so its survival on tvOS proves nothing",
			info.Mode())
	}
}

const decoyContents = "not a socket"

func writeDecoy(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(decoyContents), 0o644); err != nil {
		t.Fatalf("place the decoy at %s: %v", path, err)
	}
}

func assertDecoyIntact(t *testing.T, path, after string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("after %s the decoy at %s is gone (%v). Nothing on tvOS bound this pathname, "+
			"so removing it is this process deleting a file it did not create", after, path, err)
	}
	if info.Mode()&os.ModeSocket != 0 {
		t.Fatalf("after %s the pathname is a socket; on the device that bind returns EPERM", after)
	}
	if mode := info.Mode().Perm(); mode != 0o644 {
		t.Fatalf("after %s the decoy is %04o, not 0644. Something chmod'ed the raw pathname -- "+
			"the 0600 narrowing belongs to a socket this profile never created, and on a device "+
			"it logs `secure Clash API Unix socket: no such file` instead", after, mode)
	}
	body, err := os.ReadFile(path)
	if err != nil || string(body) != decoyContents {
		t.Fatalf("after %s the decoy's contents are %q/%v, want %q", after, string(body), err, decoyContents)
	}
}

// assertNotListening waits, briefly, for the user's controller at addr to stop answering.
// `after` names the operation under test; the message is only as good as that name.
func assertNotListening(t *testing.T, addr string, after string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err != nil {
			return
		}
		_ = conn.Close()
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the user's controller is still listening at %s after %s. Whatever gates that "+
		"operation gates the pathname half; the listener half must run regardless, or a Close or "+
		"a reload leaves an open surface behind", addr, after)
}

// Absence again, and by scan again, for the same reason as the gate above it: a
// third call site added tomorrow in a file none of these tests execute would pass
// all of them.
//
// Scoped to the two files that hold the resolver's callers, and to the shape that
// caused the bug -- an operation on the SOCKET performed against the pathname the
// caller started from, after the resolver has already answered about it. The rule
// is mechanical: below the resolution, the pathname argument of anything that
// touches the filesystem or a listener is a RESOLVED name.
//
// Stated as an allowlist of resolved names rather than a denylist of the raw one
// (an external review pointed out that `\bpath\b` was escapable by renaming the
// variable), and counted per operation rather than in total, because a total of
// six can be one shape found six times and another shape not found at all.
func TestNoSocketOperationTakesTheUnresolvedPathname(t *testing.T) {
	// The capture is the pathname argument of each operation; everything else on
	// the line is the operation's own business.
	operations := map[string]*regexp.Regexp{
		"os.Remove":                  regexp.MustCompile(`os\.Remove\(([^)]*)\)`),
		"os.Chmod":                   regexp.MustCompile(`os\.Chmod\(([^,]*),`),
		`net.DialTimeout("unix", …)`: regexp.MustCompile(`net\.DialTimeout\("unix",\s*([^,]*),`),
		"secureBindingControlSocket": regexp.MustCompile(`secureBindingControlSocket\(([^)]*)\)`),
		"controllerServerConfig":     regexp.MustCompile(`controllerServerConfig\([^,]*,\s*([^)]*)\)`),
		"recreateControlPlane":       regexp.MustCompile(`recreateControlPlane\([^,]*,\s*([^)]*)\)`),
	}
	// The two names a resolved address travels under: the local the resolver
	// assigns, and the parameter the two configuration builders take it as.
	resolved := map[string]bool{"socket": true, "bindingSocketPath": true}

	// Positive controls, both directions: the shape that caused the bug must be
	// caught, and the shape that fixed it must pass, or the scan is reading
	// neither and reports a clean pair of files for the wrong reason.
	if arg := operations["secureBindingControlSocket"].FindStringSubmatch(
		"\tif err := secureBindingControlSocket(path); err != nil {"); arg == nil || resolved[arg[1]] {
		t.Fatal("the scan no longer recognises the shape it exists to catch")
	}
	if arg := operations["secureBindingControlSocket"].FindStringSubmatch(
		"\tif err := secureBindingControlSocket(socket); err != nil {"); arg == nil || !resolved[arg[1]] {
		t.Fatal("the scan no longer accepts the shape that fixed the bug")
	}
	if arg := operations["recreateControlPlane"].FindStringSubmatch(
		"\tserver := recreateControlPlane(cfg, raw)"); arg == nil || resolved[arg[1]] {
		t.Fatal("a renamed raw pathname escapes the scan; the allowlist is not being applied")
	}

	sources := packageSourceFiles(t)
	found := map[string]int{}
	for _, name := range []string{"clash_api.go", "external_controller.go"} {
		body, ok := sources[name]
		if !ok {
			t.Fatalf("%s is not in this package; the scan is looking at nothing", name)
		}
		for index, line := range strings.Split(body, "\n") {
			trimmed := strings.TrimSpace(line)
			// Declarations name a parameter, they do not operate on it, and the
			// resolution line is where the raw pathname is SUPPOSED to appear.
			if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "func ") ||
				strings.Contains(line, "bindingSocketPathFor(path)") {
				continue
			}
			for operation, shape := range operations {
				match := shape.FindStringSubmatch(line)
				if match == nil {
					continue
				}
				found[operation]++
				if argument := strings.TrimSpace(match[1]); !resolved[argument] {
					t.Errorf("%s:%d %s operates on %q, which is not a resolved pathname:\n    %s\n"+
						"bindingSocketPathFor has already decided whether this profile owns that "+
						"pathname. Using anything but its answer afterwards is how the reload path "+
						"came to chmod a socket the same function had just declined to create",
						name, index+1, operation, argument, trimmed)
				}
			}
		}
	}
	for operation := range operations {
		if found[operation] == 0 {
			t.Errorf("no %s call found across the two files; the scan is measuring nothing for "+
				"that shape -- if the operation moved, move the scan with it", operation)
		}
	}
}
