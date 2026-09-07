package hako

import (
	"encoding/json"
	"net"
	"os"
	"syscall"
	"testing"
)

// The same shape a real dial failure has -- an OpError wrapping a SyscallError -- so
// errors.Is reaches the errno the way it does in production. permissionDenied above is the
// EPERM case; this one is parameterised because the advice is chosen by errno and a test
// that cannot vary it cannot show that.
func dialErrno(errno syscall.Errno) error {
	return &net.OpError{
		Op:   "dial",
		Net:  "tcp",
		Addr: &net.TCPAddr{IP: net.ParseIP("93.184.216.34"), Port: 443},
		Err:  &os.SyscallError{Syscall: "connect", Err: errno},
	}
}

func decodeDialHealth(t *testing.T) map[string]any {
	t.Helper()
	payload := DialHealthJSON()
	var decoded map[string]any
	if err := json.Unmarshal([]byte(payload), &decoded); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, payload)
	}
	return decoded
}

// The reason this exists at all. The notice is a log line, and a log line has no "cleared":
// observeDialOutcomeForNotice resets the run on the first success and says nothing, so a
// home-screen row lit from that line stays lit after the tunnel recovers. A caller needs a
// state it can read again, not an event it had to catch.
func TestDialHealthGoesBackToQuietAfterOneSuccess(t *testing.T) {
	resetDialFailureWatch(t)
	for attempt := 0; attempt < consecutiveDialFailuresBeforeNotice; attempt++ {
		observeDialOutcomeForNotice(dialErrno(syscall.EPERM))
	}

	lit := decodeDialHealth(t)
	if lit["consecutive"] != float64(consecutiveDialFailuresBeforeNotice) {
		t.Fatalf("consecutive = %v, want %d", lit["consecutive"], consecutiveDialFailuresBeforeNotice)
	}
	if lit["announced"] != true {
		t.Fatalf("announced = %v, want true once the run reached the threshold", lit["announced"])
	}
	if lit["firstError"] == nil || lit["firstError"] == "" {
		t.Fatalf("firstError is empty; the reader is shown the core's own sentence: %v", lit)
	}
	advice, _ := lit["advice"].(string)
	if advice == "" {
		t.Fatalf("advice is empty for an EPERM run: %v", lit)
	}
	if since, ok := lit["sinceUnix"].(float64); !ok || since <= 0 {
		t.Fatalf("sinceUnix = %v, want the unix second the run began", lit["sinceUnix"])
	}

	observeDialOutcomeForNotice(nil)

	cleared := decodeDialHealth(t)
	if cleared["consecutive"] != float64(0) {
		t.Fatalf("consecutive = %v, want 0 after a success", cleared["consecutive"])
	}
	if cleared["announced"] != false {
		t.Fatalf("announced = %v, want false after a success", cleared["announced"])
	}
	for _, key := range []string{"firstError", "advice", "sinceUnix"} {
		if value, present := cleared[key]; present {
			t.Fatalf("%s must be absent when nothing is wrong, got %v", key, value)
		}
	}
}

// The advice is the half of the sentence that names a likely cause, and it is derived from
// the errno rather than from the message text. Keeping the error itself is what makes that
// possible after the fact -- the run's first error is what the whole run is attributed to.
func TestDialHealthAdviceFollowsTheErrnoNotTheText(t *testing.T) {
	resetDialFailureWatch(t)
	observeDialOutcomeForNotice(dialErrno(syscall.ECONNREFUSED))
	refused, _ := decodeDialHealth(t)["advice"].(string)

	resetDialFailureWatch(t)
	observeDialOutcomeForNotice(dialErrno(syscall.EPERM))
	denied, _ := decodeDialHealth(t)["advice"].(string)

	if refused == "" || denied == "" {
		t.Fatalf("both errnos must produce advice, got %q and %q", refused, denied)
	}
	if refused == denied {
		t.Fatalf("ECONNREFUSED and EPERM must not read the same: %q", refused)
	}
}

// A run below the threshold is real and worth reading -- the caller decides what to draw --
// but it is not the announced one. Reporting `announced` separately is what lets a caller
// tell "three failures just now" from "twenty in a row and the core said so".
func TestDialHealthReportsARunBeforeItIsAnnounced(t *testing.T) {
	resetDialFailureWatch(t)
	for attempt := 0; attempt < 3; attempt++ {
		observeDialOutcomeForNotice(dialErrno(syscall.EPERM))
	}
	early := decodeDialHealth(t)
	if early["consecutive"] != float64(3) {
		t.Fatalf("consecutive = %v, want 3", early["consecutive"])
	}
	if early["announced"] != false {
		t.Fatalf("announced = %v, want false below the threshold", early["announced"])
	}
}
