package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"nhooyr.io/websocket"
)

func TestWSClientSendClosed(t *testing.T) {
	ws := &WSClient{closed: true}
	if err := ws.Send(SendMessage{Type: "ping"}); err == nil {
		t.Fatalf("expected closed error")
	}
}

func TestWSClientCloseIdempotent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close(websocket.StatusNormalClosure, "done")
		_ = conn.Close(websocket.StatusNormalClosure, "done")
	}))
	defer server.Close()

	client, err := ConnectWS(server.URL, "token")
	if err != nil {
		t.Fatalf("ConnectWS: %v", err)
	}
	client.Close()
	client.Close()
}

func TestWSClientReadLoopSkipsInvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close(websocket.StatusNormalClosure, "done")
		_ = conn.Write(context.Background(), websocket.MessageText, []byte("not-json"))
	}))
	defer server.Close()

	client, err := ConnectWS(server.URL, "token")
	if err != nil {
		t.Fatalf("ConnectWS: %v", err)
	}
	ch := make(chan ServerMessage, 1)
	go client.ReadLoop(ch)
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatalf("expected channel closed without message")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for close")
	}
}
