package hako

import (
	"errors"
	"strings"
	"sync"
	"syscall"

	"github.com/TokenPLS/Hako/log"
	"github.com/TokenPLS/Hako/tunnel"
)

// consecutiveDialFailuresBeforeNotice is how many dials in a row must fail, with no success in
// between, before this core says out loud that nothing is getting out.
//
// Twenty rather than three, because a handful of failures is ordinary: a dead node, a domain
// that does not resolve, a captive portal. What is not ordinary is twenty in a row with not one
// success, and the case this exists for produced two thousand nine hundred of them in
// sixty-five seconds.
const consecutiveDialFailuresBeforeNotice = 20

// dialFailureWatch turns "the core knew every time and nobody was told" into one sentence.
//
// The failure it was built from: a macOS extension shipped without the network-client
// entitlement. Every outbound dial was refused by the sandbox, the core logged each one at
// warning level, and meanwhile the tunnel reported itself connected, the tun fd was live, the
// startup phases were all green and the controller was listening. Every self-check this core has
// looks inward -- did I start, did I bind, did I get the descriptor -- and not one of them can
// see whether a packet left the machine.
//
// That was the third time the same shape landed: inbound blocked by the sandbox, outbound
// blocked by the sandbox, and a controller that lived three milliseconds. All three were found
// by someone doing something from outside: nc, curl, and this log. So the useful thing is not
// another inward check; it is to notice that the outward ones are all failing the same way and
// say so.
var dialFailureWatch struct {
	sync.Mutex
	consecutive int
	firstError  string
	announced   bool
}

func init() {
	tunnel.SetDialOutcomeObserver(observeDialOutcomeForNotice)
}

func observeDialOutcomeForNotice(err error) {
	dialFailureWatch.Lock()
	defer dialFailureWatch.Unlock()

	if err == nil {
		// One success is enough to say the path works, so the run of failures means something
		// ordinary -- a dead node among live ones -- and the counter starts over. The announcement
		// resets too: a tunnel that recovers and later breaks again deserves to be told twice.
		dialFailureWatch.consecutive = 0
		dialFailureWatch.firstError = ""
		dialFailureWatch.announced = false
		return
	}

	reason := err.Error()
	if dialFailureWatch.consecutive == 0 {
		dialFailureWatch.firstError = reason
	} else if !sameDialFailure(dialFailureWatch.firstError, reason) {
		// Different failures in a row are what a broken network looks like, not what one broken
		// permission looks like. Restart the run rather than counting unrelated errors towards a
		// sentence that would name a single cause.
		dialFailureWatch.firstError = reason
		dialFailureWatch.consecutive = 1
		return
	}

	dialFailureWatch.consecutive++
	if dialFailureWatch.consecutive < consecutiveDialFailuresBeforeNotice || dialFailureWatch.announced {
		return
	}
	dialFailureWatch.announced = true

	// [Apple + Warnln is the pair the containing app selects on. This is reader-facing on
	// purpose: the user is looking at a tunnel that says it is connected while nothing works, and
	// they are the only one who can act on the answer.
	log.Warnln("[Apple] %d outbound connections in a row failed and none succeeded: %s. %s",
		dialFailureWatch.consecutive, reason, dialFailureAdvice(err))
}

// sameDialFailure asks whether two dial errors are the same complaint about different addresses.
// The text carries the destination, so comparing whole strings would never match; what repeats
// is the tail, which is the syscall or resolver verdict.
func sameDialFailure(first, second string) bool {
	return dialFailureTail(first) == dialFailureTail(second)
}

func dialFailureTail(reason string) string {
	if index := strings.LastIndex(reason, ": "); index >= 0 {
		return reason[index+2:]
	}
	return reason
}

// dialFailureAdvice names the likeliest cause without asserting it. EPERM on an outbound dial
// from an Apple app extension has one overwhelmingly common source -- the process was not given
// the client-network entitlement -- and saying so is worth more than a generic sentence. It is
// still phrased as the thing to check first, because a local firewall produces the same errno.
func dialFailureAdvice(err error) string {
	switch {
	case errors.Is(err, syscall.EPERM):
		return "the operating system is refusing this process permission to connect, which on " +
			"Apple platforms usually means the app extension is missing the client-network " +
			"entitlement, or a local firewall is blocking it"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "the destinations are reachable but refusing the connection"
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
		return "no route to the destinations; check whether the device has network access at all"
	default:
		return "the tunnel reports itself connected, so this is happening after the tunnel came up"
	}
}
