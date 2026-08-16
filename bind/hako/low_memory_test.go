//go:build with_low_memory

package hako

import "testing"

// Guards the iOS memory recipe: when built with the with_low_memory tag
// the flag must be observable so Swift
// and CI can confirm the constrained build. The macOS slice is built without
// the tag and therefore does not compile this test.
func TestLowMemoryBuildActive(t *testing.T) {
	if !LowMemoryBuild() {
		t.Fatal("with_low_memory tag set but LowMemoryBuild() = false")
	}
}
