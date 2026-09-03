package adapter

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"
)

// The client used to read the failure out of the kernel's English prose: a
// dozen `contains` matched against wordings this tree is free to change, so a
// reworded error silently changed the category with nothing going red.
// Classification belongs here, where the error still has its type, and it is
// done with errors.Is/As so it survives rewording.
//
// It deliberately does NOT have a "dns" kind. That was the client's invented
// category, matched on the substring "dns", and it merged the very things that
// solve a case: today a user's nodes all failed with EADDRNOTAVAIL (a socket
// bound to a physical interface) where ECONNREFUSED would have meant
// nothing was listening. One category cannot say that; the errno can.

func TestClassifyURLTestFailureReadsTypesNotWords(t *testing.T) {
	for _, tc := range []struct {
		name      string
		err       error
		satisfied bool
		status    int
		wantKind  string
		wantErrno string
	}{
		{
			// The shape of today's real defect, wrapped exactly as the dialer
			// wraps it: component/dialer/dialer.go:455 uses %w, so the chain
			// survives all the way here.
			name:      "loopback write refused by a bound socket",
			err:       fmt.Errorf("dns resolve failed: %w", &net.OpError{Op: "write", Err: syscall.EADDRNOTAVAIL}),
			satisfied: true,
			wantKind:  "write",
			wantErrno: "EADDRNOTAVAIL",
		},
		{
			name:      "nothing listening",
			err:       &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED},
			satisfied: true,
			wantKind:  "dial",
			wantErrno: "ECONNREFUSED",
		},
		{
			name:      "probe outlived its deadline",
			err:       fmt.Errorf("get: %w", context.DeadlineExceeded),
			satisfied: true,
			wantKind:  "timeout",
			wantErrno: "",
		},
		{
			name:      "caller hung up",
			err:       fmt.Errorf("get: %w", context.Canceled),
			satisfied: true,
			wantKind:  "canceled",
			wantErrno: "",
		},
		{
			// Answered, just not with the status the caller wanted. This is an
			// outcome, not an error, so it arrives with err == nil.
			name:      "answered with an unexpected status",
			err:       nil,
			satisfied: false,
			status:    403,
			wantKind:  "status",
			wantErrno: "",
		},
		{
			name:      "something with no type to read",
			err:       errors.New("a sentence and nothing else"),
			satisfied: true,
			wantKind:  "unknown",
			wantErrno: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyURLTestFailure(tc.err, tc.satisfied, tc.status)
			if got == nil {
				t.Fatalf("no failure classified")
			}
			if got.Kind != tc.wantKind {
				t.Errorf("kind = %q, want %q", got.Kind, tc.wantKind)
			}
			if got.Errno != tc.wantErrno {
				t.Errorf("errno = %q, want %q", got.Errno, tc.wantErrno)
			}
		})
	}
}

// the verbatim sentence is never replaced by the classification, it
// travels beside it. A reader who needs the truth gets the truth.
func TestClassifyURLTestFailureKeepsTheVerbatimSentence(t *testing.T) {
	err := fmt.Errorf("dns resolve failed: %w", &net.OpError{Op: "write", Err: syscall.EADDRNOTAVAIL})
	got := ClassifyURLTestFailure(err, true, 0)
	if got.Message != err.Error() {
		t.Fatalf("message = %q, want the error verbatim %q", got.Message, err.Error())
	}
}

// A success is not a failure, and must classify as nothing at all.
func TestClassifyURLTestFailureIsNilOnSuccess(t *testing.T) {
	if got := ClassifyURLTestFailure(nil, true, 204); got != nil {
		t.Fatalf("a satisfied probe with no error classified as %+v", got)
	}
}

// The poison the iOS lane asked for, as a test rather than a ritual: rewording
// the kernel's prose must not move the category. If this ever fails, the
// classifier has grown a substring match.
func TestClassifyURLTestFailureSurvivesRewording(t *testing.T) {
	inner := &net.OpError{Op: "write", Err: syscall.EADDRNOTAVAIL}
	for _, prose := range []string{
		"dns resolve failed: %w",
		"all DNS requests failed, first error: %w",
		"could not work out where that name lives: %w",
		"%w",
	} {
		got := ClassifyURLTestFailure(fmt.Errorf(prose, inner), true, 0)
		if got.Kind != "write" || got.Errno != "EADDRNOTAVAIL" {
			t.Fatalf("wording %q changed the classification to kind=%q errno=%q", prose, got.Kind, got.Errno)
		}
	}
}
