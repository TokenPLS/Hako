//go:build with_gvisor

package tun

import (
	"testing"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
)

type testNetworkDispatcher struct{}

func (testNetworkDispatcher) DeliverNetworkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {}
func (testNetworkDispatcher) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer)    {}

func TestLinkEndpointFilterPropagatesNilDetach(t *testing.T) {
	endpoint := channel.New(1, 1500, "")
	filter := &LinkEndpointFilter{LinkEndpoint: endpoint}
	filter.Attach(testNetworkDispatcher{})
	if !endpoint.IsAttached() {
		t.Fatal("underlying endpoint was not attached")
	}

	filter.Attach(nil)
	if endpoint.IsAttached() {
		t.Fatal("nil detach was wrapped as a non-nil dispatcher")
	}
}
