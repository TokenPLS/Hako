package hako

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// The tvOS seat exists so tvOS stops arriving here as iOS. It carries the iOS
// values on purpose: nothing about an Apple TV Network Extension has been
// measured -- not the memory ceiling (os_proc_available_memory is available on
// tvOS 13.0+ and has never been read on the device), not whether the Caches
// directory tvOS forces resources into survives a reboot. Until it is, the iOS
// behavior is the conservative one, and the seat is what gives those
// measurements somewhere to land.

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

// Compares the whole struct rather than a list of fields. A hand-written list
// of fields goes stale the moment someone adds one: the new field is outside
// the list, the test still passes, and "tvOS inherits iOS" quietly stops being
// true. This assertion is the only thing standing between that claim and
// drift, so it must cover fields that do not exist yet.
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
			t.Fatalf("underNetworkExtension=%v: tvOS policy differs from iOS in %s",
				underNE, strings.Join(differingPolicyFields(tvOS, iOS), ", "))
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
