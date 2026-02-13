package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/Avicted/dialtone/internal/ipc"
)

func TestIPCConnSend(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	state := &ipcConn{conn: serverConn, enc: json.NewEncoder(serverConn)}
	errCh := make(chan error, 1)
	go func() {
		errCh <- state.send(ipc.Message{Event: ipc.EventVoiceReady})
	}()

	var msg ipc.Message
	if err := json.NewDecoder(clientConn).Decode(&msg); err != nil {
		t.Fatalf("decode sent message: %v", err)
	}
	if msg.Event != ipc.EventVoiceReady {
		t.Fatalf("unexpected sent message: %#v", msg)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("ipcConn.send failed: %v", err)
	}
}

func TestIPCServerHandleCommandPaths(t *testing.T) {
	t.Run("missing handler emits error", func(t *testing.T) {
		serverConn, clientConn := net.Pipe()
		defer serverConn.Close()
		defer clientConn.Close()

		s := &ipcServer{}
		state := &ipcConn{conn: serverConn, enc: json.NewEncoder(serverConn)}
		go s.handleCommand(context.Background(), ipc.Message{Cmd: ipc.CommandPing}, state)

		var msg ipc.Message
		if err := json.NewDecoder(clientConn).Decode(&msg); err != nil {
			t.Fatalf("decode error payload: %v", err)
		}
		if msg.Event != ipc.EventError || msg.Error != "ipc handler unavailable" {
			t.Fatalf("unexpected error payload: %#v", msg)
		}
	})

	t.Run("handler response emits event", func(t *testing.T) {
		serverConn, clientConn := net.Pipe()
		defer serverConn.Close()
		defer clientConn.Close()

		s := &ipcServer{h: func(context.Context, ipc.Message) (ipc.Message, error) {
			return ipc.Message{Event: ipc.EventPong}, nil
		}}
		state := &ipcConn{conn: serverConn, enc: json.NewEncoder(serverConn)}
		go s.handleCommand(context.Background(), ipc.Message{Cmd: ipc.CommandPing}, state)

		var msg ipc.Message
		if err := json.NewDecoder(clientConn).Decode(&msg); err != nil {
			t.Fatalf("decode handler response: %v", err)
		}
		if msg.Event != ipc.EventPong {
			t.Fatalf("unexpected response payload: %#v", msg)
		}
	})

	t.Run("handler error emits error", func(t *testing.T) {
		serverConn, clientConn := net.Pipe()
		defer serverConn.Close()
		defer clientConn.Close()

		s := &ipcServer{h: func(context.Context, ipc.Message) (ipc.Message, error) {
			return ipc.Message{}, fmt.Errorf("boom")
		}}
		state := &ipcConn{conn: serverConn, enc: json.NewEncoder(serverConn)}
		go s.handleCommand(context.Background(), ipc.Message{Cmd: ipc.CommandPing}, state)

		var msg ipc.Message
		if err := json.NewDecoder(clientConn).Decode(&msg); err != nil {
			t.Fatalf("decode handler error: %v", err)
		}
		if msg.Event != ipc.EventError || msg.Error != "boom" {
			t.Fatalf("unexpected handler error payload: %#v", msg)
		}
	})
}

func TestIPCServerTrackUntrackAndBroadcast(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	s := &ipcServer{}
	state := &ipcConn{conn: serverConn, enc: json.NewEncoder(serverConn)}
	s.trackConn(state)
	if len(s.conns) != 1 {
		t.Fatalf("expected tracked conn count 1, got %d", len(s.conns))
	}

	errCh := make(chan error, 1)
	go func() {
		var msg ipc.Message
		err := json.NewDecoder(clientConn).Decode(&msg)
		if err == nil && msg.Event != ipc.EventInfo {
			err = fmt.Errorf("unexpected broadcast payload: %#v", msg)
		}
		errCh <- err
	}()

	s.Broadcast(ipc.Message{Event: ipc.EventInfo, Error: "hello"})
	if err := <-errCh; err != nil {
		t.Fatalf("broadcast receive: %v", err)
	}

	s.untrackConn(serverConn)
	if len(s.conns) != 0 {
		t.Fatalf("expected tracked conn count 0, got %d", len(s.conns))
	}
}

func TestIPCServerHandleConnLifecycle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := newIPCServer("", func(_ context.Context, msg ipc.Message) (ipc.Message, error) {
		if msg.Cmd == ipc.CommandPing {
			return ipc.Message{Event: ipc.EventPong}, nil
		}
		return ipc.Message{}, nil
	})

	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	done := make(chan struct{})
	go func() {
		s.handleConn(ctx, serverConn)
		close(done)
	}()

	dec := json.NewDecoder(clientConn)
	enc := json.NewEncoder(clientConn)

	var ready ipc.Message
	if err := dec.Decode(&ready); err != nil {
		t.Fatalf("decode ready event: %v", err)
	}
	if ready.Event != ipc.EventVoiceReady {
		t.Fatalf("expected ready event, got %#v", ready)
	}

	if err := enc.Encode(ipc.Message{Cmd: ipc.CommandPing}); err != nil {
		t.Fatalf("encode ping: %v", err)
	}
	var resp ipc.Message
	if err := dec.Decode(&resp); err != nil {
		t.Fatalf("decode ping response: %v", err)
	}
	if resp.Event != ipc.EventPong {
		t.Fatalf("expected pong response, got %#v", resp)
	}

	if err := enc.Encode(ipc.Message{Event: ipc.EventInfo}); err != nil {
		t.Fatalf("encode no-op message: %v", err)
	}

	_ = clientConn.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for handleConn to exit")
	}

	if len(s.conns) != 0 {
		t.Fatalf("expected all conns untracked after close, got %d", len(s.conns))
	}
}
