//go:build with_gvisor

package tun

import (
	"testing"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
)

// TestGVisorTCPBufferBytesControlsWindow proves the window policy: by
// default the stack uses the adaptive range (4 KiB min / 32 KiB initial /
// 256 KiB max, grown per connection by the moderation option), while a positive
// GVisorTCPBufferBytes pins Default == Max for controlled benchmark runs.
func TestGVisorTCPBufferBytesControlsWindow(t *testing.T) {
	original := GVisorTCPBufferBytes
	t.Cleanup(func() { GVisorTCPBufferBytes = original })

	for _, tc := range []struct {
		name                 string
		set                  int
		wantMin              int
		wantDefault, wantMax int
	}{
		{name: "default is the adaptive 4K/32K/128K range", set: 0, wantMin: 4096, wantDefault: 32 * 1024, wantMax: 128 * 1024},
		{name: "a negative override keeps the adaptive range", set: -1, wantMin: 4096, wantDefault: 32 * 1024, wantMax: 128 * 1024},
		{name: "a benchmark override pins a fixed window", set: 128 * 1024, wantMin: 1, wantDefault: 128 * 1024, wantMax: 128 * 1024},
	} {
		t.Run(tc.name, func(t *testing.T) {
			GVisorTCPBufferBytes = tc.set
			ipStack, err := NewGVisorStack(channel.New(1, 1500, ""))
			if err != nil {
				t.Fatal(err)
			}
			defer ipStack.Close()

			var rcv tcpip.TCPReceiveBufferSizeRangeOption
			if optErr := ipStack.TransportProtocolOption(tcp.ProtocolNumber, &rcv); optErr != nil {
				t.Fatalf("read receive buffer option: %v", optErr)
			}
			if rcv.Min != tc.wantMin || rcv.Default != tc.wantDefault || rcv.Max != tc.wantMax {
				t.Fatalf("receive buffer = %+v, want {%d %d %d}", rcv, tc.wantMin, tc.wantDefault, tc.wantMax)
			}
			var snd tcpip.TCPSendBufferSizeRangeOption
			if optErr := ipStack.TransportProtocolOption(tcp.ProtocolNumber, &snd); optErr != nil {
				t.Fatalf("read send buffer option: %v", optErr)
			}
			if snd.Min != tc.wantMin || snd.Default != tc.wantDefault || snd.Max != tc.wantMax {
				t.Fatalf("send buffer = %+v, want {%d %d %d}", snd, tc.wantMin, tc.wantDefault, tc.wantMax)
			}
			var moderation tcpip.TCPModerateReceiveBufferOption
			if optErr := ipStack.TransportProtocolOption(tcp.ProtocolNumber, &moderation); optErr != nil {
				t.Fatalf("read moderation option: %v", optErr)
			}
			if !bool(moderation) {
				t.Fatal("receive-buffer moderation must stay enabled (it grows the adaptive window)")
			}
		})
	}
}
