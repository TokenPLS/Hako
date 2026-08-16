package ping_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/sing-tun/ping"
	"github.com/metacubex/sing/common/logger"

	"github.com/stretchr/testify/require"
)

func TestIsClosed(t *testing.T) {
	t.Parallel()
	destination, err := ping.ConnectDestination(context.Background(), logger.NOP(), nil, netip.MustParseAddr("1.1.1.1"), nil, 30*time.Second)
	require.NoError(t, err)
	defer destination.Close()
	time.Sleep(1 * time.Second)
	require.False(t, destination.IsClosed())
	destination.Close()
	require.True(t, destination.IsClosed())
}
