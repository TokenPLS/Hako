package networkquality

import "testing"

func TestHTTP12PathDoesNotInitializeHTTP3Factory(t *testing.T) {
	factory, err := NewOptionalHTTP3Factory(nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if factory != nil {
		t.Fatal("HTTP/1.1+2 path unexpectedly initialized a QUIC factory")
	}
}
