package listener

import (
	"testing"

	LC "github.com/TokenPLS/Hako/listener/config"
)

func TestCleanupClearsTunConfigForReusedDescriptor(t *testing.T) {
	LastTunConf = LC.Tun{
		Enable:         true,
		Device:         "hako-packet-flow",
		FileDescriptor: 42,
	}

	Cleanup()
	if LastTunConf.Enable || LastTunConf.FileDescriptor != 0 || LastTunConf.Device != "" {
		t.Fatalf("Cleanup retained stale tun config: %+v", LastTunConf)
	}
}
