//go:build ios

package hako

// buildIsNEBudgetedPlatform: this slice was built for the iOS family — the
// gomobile "ios" build tag is set for ios, iossimulator, tvos and
// tvossimulator, and not for macos. Those are exactly the platforms whose
// Network Extensions run under the ~50 MiB jetsam budget. GOOS cannot make
// this distinction: the tvOS slices build with GOOS=darwin, same as macOS
// (gomobile cmd/gomobile/env.go platformOS/platformTags).
//
// Two trip-wires by the same table: a maccatalyst build also carries the
// "ios" tag and would be waved through -- this project builds no catalyst
// slice, re-judge before it ever does -- and the iOS slice running as
// "iPad app on Mac" would pace where no jetsam wall exists, which is
// harmless and that distribution channel is disabled anyway.
const buildIsNEBudgetedPlatform = true
