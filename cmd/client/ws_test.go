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

func TestWSClientSendReadClose(t *testing.T) {
	recv := make(chan SendMessage, 1)
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
			t.Errorf("accept: %v", err)
			return
		}
		defer conn.Close(websocket.StatusNormalClosure, "done")
		_, data, err := conn.Read(context.Background())
		if err != nil {
			t.Errorf("read: %v", err)
			return
		}
		var msg SendMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			t.Errorf("decode: %v", err)
			return
		}
		recv <- msg
		out := ServerMessage{Type: "channel.message.new", ChannelID: "ch", Sender: "user", Body: "body", SentAt: time.Now().UTC().Format(time.RFC3339Nano)}
		data, _ = json.Marshal(out)
		_ = conn.Write(context.Background(), websocket.MessageText, data)
	}))
	defer server.Close()

	ws, err := ConnectWS(server.URL, "token")
	if err != nil {
		t.Fatalf("ConnectWS: %v", err)
	}
	defer ws.Close()

	if err := ws.Send(SendMessage{Type: "ping", Body: "hello"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	got := <-recv
	if got.Type != "ping" || got.Body != "hello" {
		t.Fatalf("unexpected send: %#v", got)
	}

	ch := make(chan ServerMessage, 1)
	go ws.ReadLoop(ch)
	select {
	case msg := <-ch:
		if msg.Type != "channel.message.new" {
			t.Fatalf("unexpected server msg: %#v", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for message")
	}
}
