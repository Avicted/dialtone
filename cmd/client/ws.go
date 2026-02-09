package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"nhooyr.io/websocket"
)

type WSClient struct {
	conn   *websocket.Conn
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	closed bool
}

type ServerMessage struct {
	Type          string `json:"type"`
	MessageID     string `json:"message_id"`
	Sender        string `json:"sender"`
	SenderName    string `json:"sender_name"`
	SenderNameEnc string `json:"sender_name_enc,omitempty"`
	RoomID        string `json:"room_id,omitempty"`
	SenderPubKey  string `json:"sender_public_key,omitempty"`
	KeyEnvelope   string `json:"key_envelope,omitempty"`
	Body          string `json:"body"`
	SentAt        string `json:"sent_at"`
	Code          string `json:"code"`
	Message       string `json:"message"`
}

type SendMessage struct {
	Type          string            `json:"type"`
	RoomID        string            `json:"room_id,omitempty"`
	Body          string            `json:"body"`
	MessageID     string            `json:"message_id,omitempty"`
	PublicKey     string            `json:"public_key,omitempty"`
	SenderNameEnc string            `json:"sender_name_enc,omitempty"`
	KeyEnvelopes  map[string]string `json:"key_envelopes,omitempty"`
}

func ConnectWS(serverURL, token string) (*WSClient, error) {
	wsURL := strings.Replace(serverURL, "https://", "wss://", 1)
	wsURL = strings.Replace(wsURL, "http://", "ws://", 1)
	wsURL = wsURL + "/ws?token=" + token

	ctx, cancel := context.WithCancel(context.Background())

	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("websocket dial: %w", err)
	}

	return &WSClient{
		conn:   conn,
		ctx:    ctx,
		cancel: cancel,
	}, nil
}

func (c *WSClient) Send(msg SendMessage) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return fmt.Errorf("connection closed")
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	writeCtx, writeCancel := context.WithTimeout(c.ctx, 5*time.Second)
	defer writeCancel()
	return c.conn.Write(writeCtx, websocket.MessageText, data)
}

func (c *WSClient) ReadLoop(ch chan<- ServerMessage) {
	defer close(ch)
	for {
		_, data, err := c.conn.Read(c.ctx)
		if err != nil {
			return
		}
		var msg ServerMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}
		select {
		case ch <- msg:
		case <-c.ctx.Done():
			return
		}
	}
}

func (c *WSClient) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	c.cancel()
	_ = c.conn.Close(websocket.StatusNormalClosure, "bye")
}
