package adapter

import (
	"context"
	"errors"
	"net"
	"syscall"
)

// URLTestFailure explains a failed URL test in terms a caller can act on
// WITHOUT reading the sentence. The client used to do this by matching a dozen
// substrings against the kernel's English, which meant any rewording
// here silently changed the category over there, with nothing to go red.
//
// Message carries the sentence unchanged beside the classification: the
// category is for behaviour, the sentence is for the reader, and neither
// replaces the other.
type URLTestFailure struct {
	// Kind is the coarse category, read from the error's TYPE:
	// timeout, canceled, dial, write, read, status, unknown.
	//
	// There is deliberately no "dns" kind. That was the client's invention,
	// matched on the substring "dns", and it merged cases that have to stay
	// apart: EADDRNOTAVAIL on a loopback resolver (a socket bound to a
	// physical interface --) and ECONNREFUSED (nothing listening) are
	// the same "dns" to a substring and completely different problems to a
	// reader. The errno says which; a category never could.
	Kind string
	// Errno is the symbolic name of the underlying syscall error
	// ("EADDRNOTAVAIL"), empty when the chain carries none or the platform
	// cannot name it.
	Errno string
	// Message is the error verbatim.
	Message string
}

const (
	URLTestFailureTimeout  = "timeout"
	URLTestFailureCanceled = "canceled"
	URLTestFailureStatus   = "status"
	URLTestFailureUnknown  = "unknown"
)

// ClassifyURLTestFailure returns nil when the probe succeeded. `satisfied` and
// `status` come from URLTestOutcome: an answer outside the caller's expected
// range is an OUTCOME with a nil error, so it is classified from those
// rather than from an error that does not exist.
func ClassifyURLTestFailure(err error, satisfied bool, status int) *URLTestFailure {
	if err == nil && satisfied {
		return nil
	}
	failure := &URLTestFailure{Kind: URLTestFailureUnknown}
	if err != nil {
		failure.Message = err.Error()
	}

	switch {
	case err == nil && !satisfied:
		failure.Kind = URLTestFailureStatus
		if failure.Message == "" {
			failure.Message = unexpectedStatusSentence(status)
		}
		return failure
	case errors.Is(err, context.DeadlineExceeded):
		failure.Kind = URLTestFailureTimeout
	case errors.Is(err, context.Canceled):
		failure.Kind = URLTestFailureCanceled
	default:
		// net.OpError names the operation that failed -- dial, write, read --
		// which is the part of "where did this break" that survives rewording.
		var opErr *net.OpError
		if errors.As(err, &opErr) && opErr.Op != "" {
			failure.Kind = opErr.Op
		}
	}

	var errno syscall.Errno
	if errors.As(err, &errno) {
		failure.Errno = errnoName(errno)
	}
	return failure
}

func unexpectedStatusSentence(status int) string {
	return "unexpected HTTP status " + itoa(status) + " from URL test target"
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	negative := v < 0
	if negative {
		v = -v
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if negative {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
