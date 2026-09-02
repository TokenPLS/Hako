package hako

import (
	"time"

	"github.com/dlclark/regexp2"
)

const maximumRegularExpressionMatchDurationForIOS = 100 * time.Millisecond

func init() {
	// regexp2 deliberately defaults to an unlimited match duration because it
	// supports backreferences and lookarounds through a backtracking engine.
	// Hako keeps those mihomo-compatible expressions, but an untrusted config or
	// provider must not be able to occupy a Network Extension worker forever.
	// Package initialization runs before service/config goroutines, so changing
	// the process-wide constructor default here is race-free and also covers
	// regex values decoded later by the upstream structure decoder.
	regexp2.DefaultMatchTimeout = maximumRegularExpressionMatchDurationForIOS
}
