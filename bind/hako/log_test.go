package hako

import (
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

// blockingPlatform's WriteLog blocks until released, simulating a stalled
// Swift consumer.
type blockingPlatform struct {
	recordingPlatform
	release  chan struct{}
	received atomic.Int64
}

func (p *blockingPlatform) WriteLog(string) {
	p.received.Add(1)
	<-p.release // block until the test releases us
}

// DoD: a slow/stalled log consumer must not block the core's
// logging goroutine — Write returns immediately, overflow is dropped.
func TestLogBackpressureDoesNotBlockCore(t *testing.T) {
	t.Cleanup(func() { logrus.SetOutput(os.Stdout) })

	platform := &blockingPlatform{release: make(chan struct{})}
	writer := redirectLogs(platform)
	t.Cleanup(func() { stopLogRedirect(writer) })

	// Emit far more than the buffer; each call must return promptly even
	// though the consumer is blocked on the first line.
	done := make(chan struct{})
	go func() {
		for i := 0; i < logChannelSize*4; i++ {
			logrus.Infoln("hako backpressure probe")
		}
		close(done)
	}()

	select {
	case <-done:
		// Good: logging never blocked despite the stalled consumer.
	case <-time.After(5 * time.Second):
		t.Fatal("core logging blocked on a stalled WriteLog consumer")
	}

	writer.Close()
	close(platform.release) // let an in-flight WriteLog return
	select {
	case <-writer.stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("log drain goroutine did not terminate")
	}
}

// Startup lines are the ones that explain a kill: an iOS packet tunnel that
// crosses its memory budget is SIGKILLed, and whatever is still queued in this
// process dies with it. So while the tunnel is starting, Write must not return
// until the platform has taken the line (review P1-4: the guarantee has to be
// acknowledged delivery, not a bypass of one of the two queues).
func TestStartupLogsReachThePlatformBeforeWriteReturns(t *testing.T) {
	t.Cleanup(func() { logrus.SetOutput(os.Stdout) })

	platform := newRecordingPlatform()
	writer := redirectLogs(platform)
	t.Cleanup(func() { stopLogRedirect(writer) })

	logrus.Infoln("hako startup delivery probe")

	select {
	case line := <-platform.lines:
		if !strings.Contains(line, "hako startup delivery probe") {
			t.Fatalf("the platform received %q instead of the startup line", line)
		}
	default:
		t.Fatal("Write returned while the startup line was still queued in-process")
	}
}

// One stalled platform call must cost one budget, not one budget per line:
// after the first line times out the writer stops waiting for good, or a dead
// consumer would turn a few hundred startup lines into minutes of silence
// while the watchdog counts down.
func TestStartupDeliveryWaitIsSpentOnlyOnce(t *testing.T) {
	t.Cleanup(func() { logrus.SetOutput(os.Stdout) })

	platform := &blockingPlatform{release: make(chan struct{})}
	writer := redirectLogs(platform)
	t.Cleanup(func() { stopLogRedirect(writer) })

	start := time.Now()
	for i := 0; i < 8; i++ {
		logrus.Infoln("hako stalled startup probe")
	}
	elapsed := time.Since(start)
	if elapsed < startupDeliveryBudget {
		t.Fatalf("the first startup line was not awaited: %v", elapsed)
	}
	if elapsed > 2*startupDeliveryBudget {
		t.Fatalf("a stalled platform was awaited more than once: %v", elapsed)
	}

	writer.Close()
	close(platform.release)
	select {
	case <-writer.stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("log drain goroutine did not terminate")
	}
}

// Once the tunnel is established, throughput wins over the delivery guarantee:
// a stalled platform must not add even the bounded startup wait to Write.
func TestEstablishedTunnelLoggingDoesNotWaitForThePlatform(t *testing.T) {
	t.Cleanup(func() { logrus.SetOutput(os.Stdout) })

	platform := &blockingPlatform{release: make(chan struct{})}
	writer := redirectLogs(platform)
	t.Cleanup(func() { stopLogRedirect(writer) })
	writer.markTunnelEstablished()

	start := time.Now()
	for i := 0; i < 8; i++ {
		logrus.Infoln("hako steady probe")
	}
	if elapsed := time.Since(start); elapsed > 300*time.Millisecond {
		t.Fatalf("steady-state Write waited %v on a stalled platform", elapsed)
	}

	writer.Close()
	close(platform.release)
	select {
	case <-writer.stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("log drain goroutine did not terminate")
	}
}

func TestRedirectLogsStopsReplacedWriter(t *testing.T) {
	first := redirectLogs(newRecordingPlatform())
	second := redirectLogs(newRecordingPlatform())
	t.Cleanup(func() { stopLogRedirect(second) })
	select {
	case <-first.stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("replaced log writer did not stop")
	}
}

func TestRecentLogRingHonorsConfiguredMaximum(t *testing.T) {
	ring := &ringBuffer{}
	ring.setMax(3)
	for _, line := range []string{"one", "two", "three", "four"} {
		ring.add(line)
	}
	got := ring.snapshot()
	if len(got) != 3 || got[0] != "two" || got[2] != "four" {
		t.Fatalf("bounded ring = %v", got)
	}
}
