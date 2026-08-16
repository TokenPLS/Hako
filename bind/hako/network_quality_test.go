package hako

import (
	"strings"
	"sync"
	"testing"
	"time"
)

type recordingNetworkQualityHandler struct {
	once    sync.Once
	errors  chan string
	results chan *NetworkQualityResult
}

func newRecordingNetworkQualityHandler() *recordingNetworkQualityHandler {
	return &recordingNetworkQualityHandler{
		errors:  make(chan string, 1),
		results: make(chan *NetworkQualityResult, 1),
	}
}

func (*recordingNetworkQualityHandler) OnProgress(*NetworkQualityProgress) {}
func (h *recordingNetworkQualityHandler) OnResult(result *NetworkQualityResult) {
	h.once.Do(func() { h.results <- result })
}
func (h *recordingNetworkQualityHandler) OnError(message string) {
	h.once.Do(func() { h.errors <- message })
}

func TestNetworkQualityConstantsMatchLibbox(t *testing.T) {
	if NetworkQualityDefaultConfigURL != "https://mensura.cdn-apple.com/api/v1/gm/config" {
		t.Fatalf("default config URL = %q", NetworkQualityDefaultConfigURL)
	}
	if NetworkQualityPhaseIdle != 0 || NetworkQualityPhaseDownload != 1 || NetworkQualityPhaseUpload != 2 || NetworkQualityPhaseDone != 3 {
		t.Fatal("network quality phases drifted from libbox")
	}
	if got := FormatBitrate(12_500_000); got != "12.5 Mbps" {
		t.Fatalf("FormatBitrate = %q", got)
	}
}

func TestNetworkQualityReportsConfigError(t *testing.T) {
	handler := newRecordingNetworkQualityHandler()
	test := NewNetworkQualityTest()
	t.Cleanup(test.Cancel)
	test.Start("http://127.0.0.1:1/config", false, 1, false, handler)

	select {
	case message := <-handler.errors:
		if !strings.Contains(message, "fetch config") {
			t.Fatalf("unexpected error %q", message)
		}
	case <-handler.results:
		t.Fatal("invalid config endpoint returned a result")
	case <-time.After(5 * time.Second):
		t.Fatal("network quality error callback timed out")
	}
}
