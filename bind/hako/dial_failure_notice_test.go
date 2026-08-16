package hako

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/log"
)

// warningCapture collects log payloads while a test runs. The core publishes through
// log.Subscribe, so this reads the same stream the containing app does.
type warningCapture struct {
	mu       sync.Mutex
	payloads []string
}

func captureWarnings(t *testing.T) *warningCapture {
	t.Helper()
	capture := &warningCapture{}
	subscription := log.Subscribe()
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case event, open := <-subscription:
				if !open {
					return
				}
				capture.mu.Lock()
				capture.payloads = append(capture.payloads, event.Payload)
				capture.mu.Unlock()
			case <-stop:
				return
			}
		}
	}()
	t.Cleanup(func() {
		// UnSubscribe FIRST, then stop reading. The other order deadlocks the whole process:
		// log.Infoln publishes into an observable that blocks on a full subscriber channel, so a
		// subscription whose reader has gone away wedges every later log call in the binary. The
		// first version of this helper did exactly that and hung the suite for ten minutes on an
		// unrelated test -- a test helper that stops draining a live subscription is not a slow
		// test, it is a stopped program.
		log.UnSubscribe(subscription)
		close(stop)
		<-done
	})
	return capture
}

func (c *warningCapture) matching(fragment string) []string {
	time.Sleep(50 * time.Millisecond) // let the publisher drain
	c.mu.Lock()
	defer c.mu.Unlock()
	var found []string
	for _, payload := range c.payloads {
		if strings.Contains(payload, fragment) {
			found = append(found, payload)
		}
	}
	return found
}

func resetDialFailureWatch(t *testing.T) {
	t.Helper()
	dialFailureWatch.Lock()
	dialFailureWatch.consecutive = 0
	dialFailureWatch.firstError = ""
	dialFailureWatch.announced = false
	dialFailureWatch.Unlock()
	t.Cleanup(func() {
		dialFailureWatch.Lock()
		dialFailureWatch.consecutive = 0
		dialFailureWatch.firstError = ""
		dialFailureWatch.announced = false
		dialFailureWatch.Unlock()
	})
}

func permissionDenied(_ string) error {
	return &net.OpError{
		Op:   "dial",
		Net:  "tcp",
		Addr: &net.TCPAddr{IP: net.ParseIP("93.184.216.34"), Port: 443},
		Err:  &os.SyscallError{Syscall: "connect", Err: syscall.EPERM},
	}
}

// The case this was built from: a macOS extension without the client-network entitlement logged
// 2,900 identical refusals in 65 seconds while the tunnel said connected, the tun fd was live,
// the phases were green and the controller was listening. The core knew every time; nobody was
// told. So the assertion is that a run of identical failures with no success produces exactly
// one sentence, and that the sentence names the thing to check.
func TestARunOfIdenticalRefusalsSaysSomethingOnce(t *testing.T) {
	resetDialFailureWatch(t)
	logs := captureWarnings(t)

	for i := 0; i < consecutiveDialFailuresBeforeNotice*3; i++ {
		observeDialOutcomeForNotice(permissionDenied(fmt.Sprintf("10.0.0.%d:443", i%200)))
	}

	notices := logs.matching("[Apple]")
	if len(notices) != 1 {
		t.Fatalf("expected exactly one notice for a run of %d identical failures, got %d:\n%s",
			consecutiveDialFailuresBeforeNotice*3, len(notices), strings.Join(notices, "\n"))
	}
	for _, required := range []string{"in a row", "entitlement"} {
		if !strings.Contains(notices[0], required) {
			t.Errorf("the notice never mentions %q, so a reader cannot act on it:\n%s", required, notices[0])
		}
	}
}

// One success means the path works and the failures were ordinary -- a dead node among live
// ones. Counting those towards a sentence that blames a permission would be the report crying
// wolf, which is how a report stops being read.
func TestOneSuccessResetsTheRun(t *testing.T) {
	resetDialFailureWatch(t)
	logs := captureWarnings(t)

	for i := 0; i < consecutiveDialFailuresBeforeNotice-1; i++ {
		observeDialOutcomeForNotice(permissionDenied("10.0.0.1:443"))
	}
	observeDialOutcomeForNotice(nil)
	for i := 0; i < consecutiveDialFailuresBeforeNotice-1; i++ {
		observeDialOutcomeForNotice(permissionDenied("10.0.0.2:443"))
	}

	if notices := logs.matching("[Apple]"); len(notices) != 0 {
		t.Errorf("a success in the middle should have reset the run, but got:\n%s", strings.Join(notices, "\n"))
	}
}

// Different failures in a row are what a broken network looks like, not what one broken
// permission looks like. Naming a single cause for a mixed run would be a confident wrong answer.
func TestMixedFailuresDoNotAccumulateIntoOneCause(t *testing.T) {
	resetDialFailureWatch(t)
	logs := captureWarnings(t)

	for i := 0; i < consecutiveDialFailuresBeforeNotice*2; i++ {
		if i%2 == 0 {
			observeDialOutcomeForNotice(permissionDenied("10.0.0.1:443"))
		} else {
			observeDialOutcomeForNotice(errors.New("dial tcp 10.0.0.2:443: i/o timeout"))
		}
	}

	if notices := logs.matching("[Apple]"); len(notices) != 0 {
		t.Errorf("alternating causes should not produce a notice blaming one of them:\n%s",
			strings.Join(notices, "\n"))
	}
}

// The tail comparison is what makes "identical" mean "same verdict about different addresses":
// every one of those 2,900 lines named a different destination.
func TestFailuresAboutDifferentAddressesStillCountAsTheSameComplaint(t *testing.T) {
	first := "dial tcp 93.184.216.34:443: connect: operation not permitted"
	second := "dial tcp 1.1.1.1:853: connect: operation not permitted"
	if !sameDialFailure(first, second) {
		t.Error("two refusals of different destinations were treated as different complaints, so " +
			"a run of them would never reach the threshold")
	}
	if sameDialFailure(first, "dial tcp 1.1.1.1:853: i/o timeout") {
		t.Error("a timeout and a refusal were treated as the same complaint")
	}
}
