//go:build !with_quic

package hako

import (
	"strings"
	"testing"
	"time"
)

func TestNetworkQualityHTTP3FailsExplicitlyWhenExcluded(t *testing.T) {
	if NetworkQualityHTTP3Available() {
		t.Fatal("no-QUIC build advertised HTTP/3")
	}
	handler := newRecordingNetworkQualityHandler()
	test := NewNetworkQualityTest()
	t.Cleanup(test.Cancel)
	test.Start(NetworkQualityDefaultConfigURL, false, 1, true, handler)

	select {
	case message := <-handler.errors:
		if !strings.Contains(message, "HTTP/3") || !strings.Contains(message, "not included") {
			t.Fatalf("unexpected HTTP/3 error %q", message)
		}
	case <-time.After(time.Second):
		t.Fatal("HTTP/3 unsupported callback timed out")
	}
}
