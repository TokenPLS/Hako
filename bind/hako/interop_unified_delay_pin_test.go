package hako

import (
	"testing"

	"github.com/TokenPLS/Hako/adapter"
)

// pinUnifiedDelayOff declares that a fixture measures with unified-delay OFF
// semantics: exactly one HEAD per URLTest. The knob is a package-global
// (adapter.UnifiedDelay) that any test booting a real core now flips to the
// factory default true; a count-asserting fixture
// that does not pin it is order-dependent, and was, silently, before the
// default changed.
func pinUnifiedDelayOff(t *testing.T) {
	t.Helper()
	prior := adapter.UnifiedDelay.Swap(false)
	t.Cleanup(func() { adapter.UnifiedDelay.Store(prior) })
}
