package keepalive

import (
	"net"
	"runtime"
	"time"

	"github.com/TokenPLS/Hako/common/atomic"
)

var (
	keepAliveIdle     = atomic.NewInt64(0)
	keepAliveInterval = atomic.NewInt64(0)
	disableKeepAlive  = atomic.NewBool(false)
)

func SetKeepAliveIdle(t time.Duration) {
	keepAliveIdle.Store(int64(t))
}

func SetKeepAliveInterval(t time.Duration) {
	keepAliveInterval.Store(int64(t))
}

// KeepAliveIdle returns the configured idle time, or the platform default when nothing
// was configured. Zero means unconfigured: configuration is the only writer, and it has
// no default of its own, so without this the zero would reach Go and pick up Go's
// 15-second default -- see defaults_darwin.go for why that is wrong on Apple platforms.
func KeepAliveIdle() time.Duration {
	if configured := keepAliveIdle.Load(); configured != 0 {
		return time.Duration(configured)
	}
	return defaultKeepAliveIdle
}

// KeepAliveInterval returns the configured retransmit interval, or the platform default
// when nothing was configured. Same reasoning as KeepAliveIdle.
func KeepAliveInterval() time.Duration {
	if configured := keepAliveInterval.Load(); configured != 0 {
		return time.Duration(configured)
	}
	return defaultKeepAliveInterval
}

func SetDisableKeepAlive(disable bool) {
	if runtime.GOOS == "android" {
		setDisableKeepAlive(true)
	} else {
		setDisableKeepAlive(disable)
	}
}

func setDisableKeepAlive(disable bool) {
	disableKeepAlive.Store(disable)
}

func DisableKeepAlive() bool {
	return disableKeepAlive.Load()
}

func SetNetDialer(dialer *net.Dialer) {
	setNetDialer(dialer)
}

func SetNetListenConfig(lc *net.ListenConfig) {
	setNetListenConfig(lc)
}

func TCPKeepAlive(c net.Conn) {
	if tcp, ok := c.(TCPConn); ok && tcp != nil {
		tcpKeepAlive(tcp)
	}
}
