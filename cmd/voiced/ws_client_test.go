package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"nhooyr.io/websocket"
)

func TestVoicedWSClientConnectSendReadClose(t *testing.T) {
	recv := make(chan VoiceSignal, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ws" {
			t.Errorf("expected /ws, got %s", r.URL.Path)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer token" {
			t.Errorf("expected auth header, got %q", got)
			return
		}
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Errorf("accept websocket: %v", err)
			return
		}
		defer conn.Close(websocket.StatusNormalClosure, "done")

		_, data, err := conn.Read(context.Background())
		if err != nil {
			t.Errorf("read client signal: %v", err)
			return
		}
		var in VoiceSignal
		if err := json.Unmarshal(data, &in); err != nil {
			t.Errorf("decode client signal: %v", err)
			return
		}
		recv <- in

		_ = conn.Write(context.Background(), websocket.MessageText, []byte(`{"type":"voice_join","channel_id":"room-1"}`))
		_ = conn.Write(context.Background(), websocket.MessageText, []byte(`{"type":"  "}`))
		_ = conn.Write(context.Background(), websocket.MessageText, []byte(`not-json`))
	}))
	defer server.Close()

	client, err := ConnectWS(server.URL, "token")
	if err != nil {
		t.Fatalf("ConnectWS: %v", err)
	}
	defer client.Close()

	if err := client.Send(VoiceSignal{Type: "ping", ChannelID: "room-1"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	select {
	case msg := <-recv:
		if msg.Type != "ping" || msg.ChannelID != "room-1" {
			t.Fatalf("unexpected sent signal: %#v", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for sent signal")
	}

	ch := make(chan VoiceSignal, 2)
	go client.ReadLoop(ch)
	select {
	case msg := <-ch:
		if msg.Type != "voice_join" || msg.ChannelID != "room-1" {
			t.Fatalf("unexpected read signal: %#v", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for server signal")
	}
}

func TestVoicedWSClientSendClosedAndCloseIdempotent(t *testing.T) {
	client := &WSClient{closed: true}
	if err := client.Send(VoiceSignal{Type: "ping"}); err == nil {
		t.Fatalf("expected Send to fail when closed")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close(websocket.StatusNormalClosure, "done")
	}))
	defer server.Close()

	realClient, err := ConnectWS(server.URL, "token")
	if err != nil {
		t.Fatalf("ConnectWS: %v", err)
	}
	realClient.Close()
	realClient.Close()
}

func TestVoicedWSClientReadLoopClosesChannelOnSocketClose(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		_ = conn.Close(websocket.StatusNormalClosure, "done")
	}))
	defer server.Close()

	client, err := ConnectWS(server.URL, "token")
	if err != nil {
		t.Fatalf("ConnectWS: %v", err)
	}
	defer client.Close()

	ch := make(chan VoiceSignal, 1)
	go client.ReadLoop(ch)
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatalf("expected closed read channel")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for read loop close")
	}
}

func TestVoicedWSClientConnectInvalidURL(t *testing.T) {
	client, err := ConnectWS("://bad-url", "token")
	if err == nil || client != nil {
		t.Fatalf("expected malformed URL dial error, got client=%v err=%v", client, err)
	}
}

func TestVoicedWSClientReadLoopStopsOnCancelWhenChannelBlocked(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close(websocket.StatusNormalClosure, "done")
		_ = conn.Write(context.Background(), websocket.MessageText, []byte(`{"type":"voice_join","channel_id":"room-1"}`))
		<-r.Context().Done()
	}))
	defer server.Close()

	client, err := ConnectWS(server.URL, "token")
	if err != nil {
		t.Fatalf("ConnectWS: %v", err)
	}
	defer client.Close()

	ch := make(chan VoiceSignal)
	done := make(chan struct{})
	go func() {
		client.ReadLoop(ch)
		close(done)
	}()

	time.Sleep(100 * time.Millisecond)
	client.cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("ReadLoop did not stop after cancel")
	}
}
