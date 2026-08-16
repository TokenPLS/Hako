//go:build !darwin

package keepalive

// Non-Apple platforms keep upstream behaviour: zero means "let Go choose", and Go's
// 15s/15s costs nothing where there is no radio to wake out of idle. See
// defaults_darwin.go for why Apple needs an explicit value and why the carve-out is
// deliberately not widened to here.
const (
	defaultKeepAliveIdle     = 0
	defaultKeepAliveInterval = 0
)
