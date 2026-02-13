package ipc

import (
	"bytes"
	"testing"
)

func TestNewEncoderDecoderRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)
	if enc == nil {
		t.Fatalf("expected non-nil encoder")
	}

	want := Message{Cmd: CommandPing, Room: "room-1"}
	if err := enc.Encode(want); err != nil {
		t.Fatalf("encode message: %v", err)
	}

	dec := NewDecoder(&buf)
	if dec == nil {
		t.Fatalf("expected non-nil decoder")
	}

	var got Message
	if err := dec.Decode(&got); err != nil {
		t.Fatalf("decode message: %v", err)
	}
	if got.Cmd != want.Cmd || got.Room != want.Room {
		t.Fatalf("unexpected round-trip payload: %#v", got)
	}
}
