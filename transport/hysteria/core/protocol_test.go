package core

import (
	"bytes"
	"testing"
)

func TestUDPMessagePackRoundTrip(t *testing.T) {
	want := udpMessage{
		SessionID: 7,
		Host:      "127.0.0.1",
		Port:      5353,
		MsgID:     9,
		FragID:    0,
		FragCount: 1,
		Data:      []byte("hako-hysteria-udp"),
	}

	packed := want.Pack()
	if len(packed) != want.Size() {
		t.Fatalf("packed size = %d, want %d", len(packed), want.Size())
	}

	var got udpMessage
	if err := got.Unpack(packed); err != nil {
		t.Fatalf("Unpack(Pack()) error = %v", err)
	}
	if got.SessionID != want.SessionID ||
		got.Host != want.Host ||
		got.Port != want.Port ||
		got.MsgID != want.MsgID ||
		got.FragID != want.FragID ||
		got.FragCount != want.FragCount ||
		!bytes.Equal(got.Data, want.Data) {
		t.Fatalf("Unpack(Pack()) = %#v, want %#v", got, want)
	}
}

func TestClientRequestUDPRoundTrip(t *testing.T) {
	want := ClientRequest{UDP: true}
	var encoded bytes.Buffer
	if err := WriteClientRequest(&encoded, want); err != nil {
		t.Fatalf("WriteClientRequest() error = %v", err)
	}

	got, err := ReadClientRequest(&encoded)
	if err != nil {
		t.Fatalf("ReadClientRequest() error = %v", err)
	}
	if !got.UDP {
		t.Fatal("ReadClientRequest().UDP = false, want true")
	}
}
