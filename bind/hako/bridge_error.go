package hako

import (
	"reflect"
	"strings"
	"unicode/utf8"
)

// bridgeSafeError is the last stop before an error crosses the gomobile
// bridge. The generated Objective-C side wraps a Go error into an NSError
// whose userInfo dictionary is built from the message string; that string is
// decoded as UTF-8, and a non-empty message holding bytes that are not valid
// UTF-8 decodes to nil, which makes the dictionary constructor throw and
// aborts the process where Swift cannot catch it. Such bytes are reachable
// from ordinary input: a YAML document may carry arbitrary bytes in a string
// field, and upstream error sentences embed those bytes verbatim.
//
// A valid message passes through untouched, keeping the error value and its
// chain. An invalid one keeps the whole sentence — each run of undecodable
// bytes becomes one Unicode replacement rune — and still unwraps to the
// original error, so errors.Is and errors.As keep working through the
// repair. This is encoding repair at the process boundary, not redaction:
// every readable byte stays.
//
// A typed-nil error (a non-nil interface holding a nil pointer) would make
// err.Error() dereference nil right here, and a panic on this path aborts
// the process at the cgo boundary. Since every bridge exit funnels through
// this function, it answers that shape itself: loudly, with a non-nil
// error, never by crashing and never by turning a failure into a success.
func bridgeSafeError(err error) error {
	if err == nil {
		return nil
	}
	if value := reflect.ValueOf(err); value.Kind() == reflect.Ptr && value.IsNil() {
		return &bridgeRepairedError{
			message: "hako: internal: error value is a typed nil (" + value.Type().String() + ")",
		}
	}
	message := err.Error()
	if utf8.ValidString(message) {
		return err
	}
	return &bridgeRepairedError{message: strings.ToValidUTF8(message, "�"), inner: err}
}

// bridgeRepairedError carries the repaired message while unwrapping to the
// error it repaired, so identity checks survive the encoding fix.
type bridgeRepairedError struct {
	message string
	inner   error
}

func (e *bridgeRepairedError) Error() string { return e.message }

func (e *bridgeRepairedError) Unwrap() error { return e.inner }
