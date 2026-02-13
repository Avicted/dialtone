//go:build !windows

package ipc

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestListenDialRoundTrip(t *testing.T) {
	addr := filepath.Join(t.TempDir(), "ipc.sock")
	ln, err := Listen(addr)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	recv := make(chan Message, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var msg Message
		if err := NewDecoder(conn).Decode(&msg); err != nil {
			return
		}
		recv <- msg
		_ = NewEncoder(conn).Encode(Message{Event: EventPong})
	}()

	conn, err := Dial(addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	if err := NewEncoder(conn).Encode(Message{Cmd: CommandPing, Room: "room-1"}); err != nil {
		t.Fatalf("encode to server: %v", err)
	}

	select {
	case got := <-recv:
		if got.Cmd != CommandPing || got.Room != "room-1" {
			t.Fatalf("unexpected server payload: %#v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for server receive")
	}

	var pong Message
	if err := NewDecoder(conn).Decode(&pong); err != nil {
		t.Fatalf("decode server reply: %v", err)
	}
	if pong.Event != EventPong {
		t.Fatalf("unexpected server reply: %#v", pong)
	}
}

func TestListenDialEmptyAddr(t *testing.T) {
	if _, err := Listen(""); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("Listen empty addr error = %v, want %v", err, os.ErrInvalid)
	}
	if _, err := Dial(""); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("Dial empty addr error = %v, want %v", err, os.ErrInvalid)
	}
}
