package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"nhooyr.io/websocket"
)

type VoiceSignal struct {
	Type      string `json:"type"`
	ChannelID string `json:"channel_id,omitempty"`
	Sender    string `json:"sender,omitempty"`
	Recipient string `json:"recipient,omitempty"`
	SDP       string `json:"sdp,omitempty"`
	Candidate string `json:"candidate,omitempty"`
}

type WSClient struct {
	conn   *websocket.Conn
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	closed bool
}

func ConnectWS(serverURL, token string) (*WSClient, error) {
	wsURL := strings.Replace(serverURL, "https://", "wss://", 1)
	wsURL = strings.Replace(wsURL, "http://", "ws://", 1)
	wsURL = wsURL + "/ws"

	ctx, cancel := context.WithCancel(context.Background())
	options := &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": []string{"Bearer " + token}},
	}
	conn, _, err := websocket.Dial(ctx, wsURL, options)
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

func (c *WSClient) Send(msg VoiceSignal) error {
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

func (c *WSClient) ReadLoop(ch chan<- VoiceSignal) {
	defer close(ch)
	for {
		_, data, err := c.conn.Read(c.ctx)
		if err != nil {
			return
		}
		var msg VoiceSignal
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}
		if strings.TrimSpace(msg.Type) == "" {
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
