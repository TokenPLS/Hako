package hako

import "testing"

// Close()'s async teardown goroutine must recover panics so a fault
// during shutdown cannot crash the host app across the gomobile boundary.
// Start's goroutine is already recover-wrapped (service.go); Close must match.

func TestRunGuardedTeardownRunsStep(t *testing.T) {
	ran := false
	runGuardedTeardown(func() { ran = true })
	if !ran {
		t.Fatal("runGuardedTeardown did not run the teardown step")
	}
}

func TestRunGuardedTeardownRecoversPanic(t *testing.T) {
	// If the guard fails to contain the panic, it escapes to this test-level
	// recover; a clean return proves the host boundary is protected.
	escaped := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				escaped = true
			}
		}()
		runGuardedTeardown(func() { panic("boom from core teardown") })
	}()
	if escaped {
		t.Fatal("runGuardedTeardown let the panic escape the gomobile boundary")
	}
}
