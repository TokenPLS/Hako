package tunnel

import (
	"runtime"
	"testing"

	"github.com/TokenPLS/Hako/constant/features"
)

// Who supplies the connection owner is a property of the HOST, not of the build tag this fork
// happens to reuse.
//
// Upstream keys the choice off features.CMFA alone, which is correct upstream: the only thing
// built with -tags cmfa there is ClashMetaForAndroid. This fork carries the tag on every Apple
// artifact too, for reasons that have nothing to do with
// process attribution -- a platform-supplied TUN descriptor, IsSafePath, the loopback detector.
// So `cmfa` alone sent darwin into FindPackageName, where DefaultPackageNameResolver is nil and
// every call returns ErrPlatformNotSupport. component/process/process_darwin.go was compiled
// into every shipped framework, worked, and had no caller; every PROCESS-* and UID rule on
// macOS matched nothing, silently, while the Rules page told the user they were available.
//
// The table is spelled out rather than read off this binary's own tags on purpose. A test that
// asks `features.CMFA` what it is passes trivially in the untagged run that CI actually does,
// which is how a defect that only exists under -tags cmfa stayed invisible. These cases are
// inputs, so they bite in every configuration.
func TestOnlyAnAndroidHostSuppliesPackageNames(t *testing.T) {
	for _, testCase := range []struct {
		name string
		cmfa bool
		goos string
		want bool
	}{
		{name: "ClashMetaForAndroid", cmfa: true, goos: "android", want: true},
		{name: "Apple framework (macOS)", cmfa: true, goos: "darwin", want: false},
		{name: "Apple framework (iOS names itself darwin)", cmfa: true, goos: "ios", want: false},
		{name: "mihomo CLI on Android", cmfa: false, goos: "android", want: false},
		{name: "mihomo CLI on macOS", cmfa: false, goos: "darwin", want: false},
		{name: "mihomo CLI on Linux", cmfa: false, goos: "linux", want: false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got := ownerLookupUsesPackageName(testCase.cmfa, testCase.goos); got != testCase.want {
				t.Fatalf("ownerLookupUsesPackageName(cmfa=%v, goos=%q) = %v, want %v",
					testCase.cmfa, testCase.goos, got, testCase.want)
			}
		})
	}
}

// And the value the production path reads must be that same predicate applied to this build,
// not a second copy of the rule that can drift from it.
func TestThisBuildAsksThePredicateRatherThanTheTagDirectly(t *testing.T) {
	want := ownerLookupUsesPackageName(features.CMFA, runtime.GOOS)
	if resolvesOwnerByPackageName != want {
		t.Fatalf("resolvesOwnerByPackageName = %v for cmfa=%v goos=%q, want %v",
			resolvesOwnerByPackageName, features.CMFA, runtime.GOOS, want)
	}
}
