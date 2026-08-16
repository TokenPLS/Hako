//go:build darwin

package rawfile

import (
	"testing"

	"golang.org/x/sys/unix"
)

// BlockingPollUntilStopped created a fresh kqueue on every call, and it is called from
// every would-block cycle of both dispatchers -- readV and recvmmsg -- i.e. on the tun
// ingress path.
//
// The reason to fix it is not CPU. Measured against this repository's own on-device
// baseline of ~119 microseconds of appex CPU per ingress packet, the ~840 ns saved is
// 0.7% of per-packet cost while the recorded noise floor is fourteen times larger, and
// the wakeup count is identical either way -- both forms block once in kevent with a nil
// timeout.
//
// The reason is that unix.Kqueue() consumes a file descriptor, so under fd pressure -- a
// Network Extension with hundreds of live connections -- it can return EMFILE or ENOMEM.
// That errno propagates from here into dispatch(), and dispatchLoop treats any error as
// terminal: it calls closed(err), releases the dispatcher and returns. One transient
// EMFILE therefore kills tun ingress permanently, with no path back short of restarting
// the tunnel. A poller that allocates its kqueue once at construction moves that failure
// to startup, where it is a handled error that cannot recur mid-flight.

func TestPollerReusesOneKqueueAcrossPolls(t *testing.T) {
	stop, notifyStop := eventPipe(t)
	data, _ := eventPipe(t)

	poller, err := NewPoller(stop)
	if err != nil {
		t.Fatalf("NewPoller: %v", err)
	}
	defer poller.Close()

	first := poller.kq
	for i := 0; i < 32; i++ {
		notifyStop(t)
		stopped, errno := poller.Poll(data, unix.POLLIN)
		if errno != 0 && errno != unix.EINTR {
			t.Fatalf("poll %d: %v", i, errno)
		}
		if !stopped {
			t.Fatalf("poll %d woke without reporting the stop descriptor; the contract is that a "+
				"stop wake is distinguishable from tun data", i)
		}
		drain(t, stop)
		if poller.kq != first {
			t.Fatalf("poll %d replaced the kqueue (%d -> %d); the whole point is one for the "+
				"dispatcher's lifetime", i, first, poller.kq)
		}
	}
}

// TestPollerDoesNotConsumeDescriptorsPerPoll is the assertion that matters: no descriptor
// is allocated while polling, so fd pressure cannot produce an EMFILE on this path and
// therefore cannot kill ingress.
func TestPollerDoesNotConsumeDescriptorsPerPoll(t *testing.T) {
	stop, notifyStop := eventPipe(t)
	data, _ := eventPipe(t)

	poller, err := NewPoller(stop)
	if err != nil {
		t.Fatalf("NewPoller: %v", err)
	}
	defer poller.Close()

	before := lowestFreeDescriptor(t)
	for i := 0; i < 64; i++ {
		notifyStop(t)
		if _, errno := poller.Poll(data, unix.POLLIN); errno != 0 && errno != unix.EINTR {
			t.Fatalf("poll %d: %v", i, errno)
		}
		drain(t, stop)
	}
	after := lowestFreeDescriptor(t)

	if after > before {
		t.Fatalf("64 polls moved the lowest free descriptor from %d to %d; a per-poll descriptor "+
			"is exactly what turns fd pressure into permanent ingress death", before, after)
	}
}

func TestPollerAllocatesNothingPerPoll(t *testing.T) {
	stop, notifyStop := eventPipe(t)
	data, _ := eventPipe(t)

	poller, err := NewPoller(stop)
	if err != nil {
		t.Fatalf("NewPoller: %v", err)
	}
	defer poller.Close()

	allocs := testing.AllocsPerRun(64, func() {
		notifyStop(t)
		_, _ = poller.Poll(data, unix.POLLIN)
		drain(t, stop)
	})
	if allocs > 0 {
		t.Fatalf("%.1f allocations per poll; the per-call form cost 3 and a persistent poller "+
			"must cost none", allocs)
	}
}

func TestPollerCloseReleasesTheKqueue(t *testing.T) {
	stop, _ := eventPipe(t)

	poller, err := NewPoller(stop)
	if err != nil {
		t.Fatalf("NewPoller: %v", err)
	}
	kq := poller.kq
	if err := poller.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := unix.Kevent(kq, nil, make([]unix.Kevent_t, 1), &unix.Timespec{}); err == nil {
		t.Fatal("the kqueue is still usable after Close; a dispatcher restart would leak one each time")
	}
	if err := poller.Close(); err != nil {
		t.Fatalf("Close must be idempotent, got %v", err)
	}
}

// eventPipe returns a readable descriptor standing in for the dispatcher's stop
// descriptor, plus a function that makes it readable.
func eventPipe(t *testing.T) (int, func(*testing.T)) {
	t.Helper()
	var fds [2]int
	if err := unix.Pipe(fds[:]); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = unix.Close(fds[0])
		_ = unix.Close(fds[1])
	})
	return fds[0], func(t *testing.T) {
		t.Helper()
		if _, err := unix.Write(fds[1], []byte{1}); err != nil {
			t.Fatalf("notify: %v", err)
		}
	}
}

func drain(t *testing.T, fd int) {
	t.Helper()
	buffer := make([]byte, 8)
	for {
		n, err := unix.Read(fd, buffer)
		if n <= 0 || err != nil {
			return
		}
		if n < len(buffer) {
			return
		}
	}
}

// lowestFreeDescriptor probes the descriptor table by taking the lowest free entry and
// giving it straight back. Unix allocates the lowest available number, so a leak shows up
// as this number climbing. Reading /dev/fd would be the obvious route but it is unreliable
// on darwin, where enumerating it stats entries through a descriptor that is itself
// changing underneath the walk.
func lowestFreeDescriptor(t *testing.T) int {
	t.Helper()
	fd, err := unix.Dup(0)
	if err != nil {
		t.Fatalf("probe descriptor table: %v", err)
	}
	if err := unix.Close(fd); err != nil {
		t.Fatalf("release probe descriptor: %v", err)
	}
	return fd
}
