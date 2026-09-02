//go:build darwin

package rawfile

import (
	"sync"

	"golang.org/x/sys/unix"
)

// Poller owns one kqueue for a dispatcher's whole lifetime and preserves
// BlockingPollUntilStopped's contract exactly: watch the stop descriptor and the tun
// descriptor together, block until either is ready, and report whether the wake came
// from the stop descriptor.
//
// BlockingPollUntilStopped used to create and close a kqueue on every call, and it is
// called from every would-block cycle of both dispatchers, i.e. on the tun ingress path.
// The CPU saving is real but is not why this exists: measured against this repository's
// own on-device baseline of roughly 119 microseconds of appex CPU per ingress packet, the
// ~840 ns is 0.7% of per-packet cost against a recorded noise floor fourteen times
// larger, and the number of wakeups is identical either way -- both forms block once in
// kevent with a nil timeout.
//
// It exists because unix.Kqueue() consumes a file descriptor. In a Network Extension with
// hundreds of live connections it can return EMFILE or ENOMEM, and that errno propagates
// into dispatch(), which dispatchLoop treats as terminal: closed(err), release, return.
// A single transient EMFILE therefore ends tun ingress permanently, with no recovery
// short of restarting the tunnel. Allocating once at construction moves that failure to
// startup, where it is a handled error that cannot recur mid-flight.
//
// Upstream sagernet/sing-tun adopted the same idea, but it also deleted
// readVDispatcher, so the path Apple targets actually use has no upstream counterpart to
// copy from; only the shape is shared.
type Poller struct {
	closeOnce sync.Once
	kq        int
	stopFD    int

	// Reused across polls so a poll costs no allocation. Three is the maximum a
	// dispatcher ever registers: the stop descriptor, plus a read and/or write filter
	// on the tun descriptor.
	registration [3]unix.Kevent_t
	results      [3]unix.Kevent_t
}

// NewPoller creates the kqueue and remembers the stop descriptor. Any
// descriptor-exhaustion error surfaces here, at construction, rather than mid-flight
// where it would be fatal to ingress.
func NewPoller(stopFD int) (*Poller, error) {
	kq, err := unix.Kqueue()
	if err != nil {
		return nil, err
	}
	return &Poller{kq: kq, stopFD: stopFD}, nil
}

// Close releases the kqueue. Idempotent, so a dispatcher released more than once does
// not double-close a descriptor that may since have been reused by something else.
func (p *Poller) Close() error {
	var err error
	p.closeOnce.Do(func() {
		err = unix.Close(p.kq)
	})
	return err
}

// Poll blocks until the stop descriptor becomes readable or fd signals one of events,
// and reports whether the stop descriptor was among them. Same return contract as the
// per-call form it replaces, including that a wake from both reports stopped.
//
// Registration is re-applied per call rather than once at construction because the
// caller may pass different event masks for the same descriptor. EV_ADD on an existing
// filter updates it instead of duplicating it, so this stays idempotent and
// allocation-free.
func (p *Poller) Poll(fd int, events int16) (bool, unix.Errno) {
	count := 0

	p.registration[count] = unix.Kevent_t{
		Ident:  uint64(p.stopFD),
		Filter: unix.EVFILT_READ,
		Flags:  unix.EV_ADD | unix.EV_ENABLE,
	}
	count++

	if events&unix.POLLIN != 0 {
		p.registration[count] = unix.Kevent_t{
			Ident:  uint64(fd),
			Filter: unix.EVFILT_READ,
			Flags:  unix.EV_ADD | unix.EV_ENABLE,
		}
		count++
	}
	if events&unix.POLLOUT != 0 {
		p.registration[count] = unix.Kevent_t{
			Ident:  uint64(fd),
			Filter: unix.EVFILT_WRITE,
			Flags:  unix.EV_ADD | unix.EV_ENABLE,
		}
		count++
	}

	n, err := unix.Kevent(p.kq, p.registration[:count], p.results[:count], nil)
	if err != nil {
		if errno, ok := err.(unix.Errno); ok {
			return false, errno
		}
		return false, unix.EINVAL
	}

	stopped := false
	var errno unix.Errno
	for i := 0; i < n; i++ {
		event := &p.results[i]
		if int(event.Ident) == p.stopFD && event.Filter == unix.EVFILT_READ {
			stopped = true
			continue
		}
		if int(event.Ident) == fd && event.Flags&unix.EV_ERROR != 0 {
			errno = unix.Errno(event.Data)
		}
	}
	return stopped, errno
}
