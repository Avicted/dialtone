package main

import (
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Avicted/dialtone/internal/ipc"
)

func TestVoiceIPCEnsureConnAndSend(t *testing.T) {
	addr := filepath.Join(t.TempDir(), "voice.sock")
	ln, err := ipc.Listen(addr)
	if err != nil {
		t.Fatalf("listen ipc: %v", err)
	}
	defer ln.Close()

	received := make(chan ipc.Message, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		dec := ipc.NewDecoder(conn)
		var msg ipc.Message
		if err := dec.Decode(&msg); err != nil {
			return
		}
		received <- msg
	}()

	v := newVoiceIPC(addr)
	if err := v.ensureConn(); err != nil {
		t.Fatalf("ensureConn: %v", err)
	}
	if err := v.send(ipc.Message{Cmd: ipc.CommandPing}); err != nil {
		t.Fatalf("send: %v", err)
	}
	if err := v.ensureConn(); err != nil {
		t.Fatalf("ensureConn second call: %v", err)
	}

	select {
	case msg := <-received:
		if msg.Cmd != ipc.CommandPing {
			t.Fatalf("expected ping command, got %#v", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for IPC message")
	}
}

func TestVoiceIPCReadLoopReportsEnsureConnError(t *testing.T) {
	v := newVoiceIPC("")
	ch := make(chan ipc.Message, 2)
	go v.readLoop(ch)

	select {
	case msg, ok := <-ch:
		if !ok {
			t.Fatalf("expected error message before channel close")
		}
		if msg.Event != ipc.EventError {
			t.Fatalf("expected error event, got %#v", msg)
		}
		if !strings.Contains(msg.Error, "voice ipc address is empty") {
			t.Fatalf("unexpected error payload: %q", msg.Error)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for error event")
	}

	select {
	case _, ok := <-ch:
		if ok {
			t.Fatalf("expected channel to be closed")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for channel close")
	}
}

func TestVoiceIPCReadLoopReceivesMessageThenResetsOnDisconnect(t *testing.T) {
	addr := filepath.Join(t.TempDir(), "voice.sock")
	ln, err := ipc.Listen(addr)
	if err != nil {
		t.Fatalf("listen ipc: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		enc := ipc.NewEncoder(conn)
		_ = enc.Encode(ipc.Message{Event: ipc.EventPong})
		_ = conn.Close()
	}()

	v := newVoiceIPC(addr)
	ch := make(chan ipc.Message, 4)
	go v.readLoop(ch)

	select {
	case msg := <-ch:
		if msg.Event != ipc.EventPong {
			t.Fatalf("expected pong event, got %#v", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for pong")
	}

	select {
	case msg := <-ch:
		if msg.Event != ipc.EventError {
			t.Fatalf("expected error event after disconnect, got %#v", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for disconnect error")
	}

	select {
	case _, ok := <-ch:
		if ok {
			t.Fatalf("expected read loop channel to be closed")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for channel close")
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	if v.conn != nil || v.enc != nil || v.dec != nil {
		t.Fatalf("expected IPC connection state reset after read failure")
	}
}

func TestVoiceIPCEnsureConnFailsWithoutCodecState(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	v := &voiceIPC{addr: "in-memory", conn: client}
	err := v.ensureConn()
	if err == nil || !strings.Contains(err.Error(), "voice ipc encoder not available") {
		t.Fatalf("expected codec availability error, got %v", err)
	}
}

func TestVoiceIPCSendEncodeErrorResetsConnection(t *testing.T) {
	client, server := net.Pipe()
	_ = server.Close()

	v := &voiceIPC{
		addr: "in-memory",
		conn: client,
		enc:  json.NewEncoder(client),
		dec:  json.NewDecoder(client),
	}
	err := v.send(ipc.Message{Cmd: ipc.CommandPing})
	if err == nil {
		t.Fatalf("expected encode error when peer is closed")
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	if v.conn != nil || v.enc != nil || v.dec != nil {
		t.Fatalf("expected connection state reset after encode failure")
	}
}
