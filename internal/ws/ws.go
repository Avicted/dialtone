package ws

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"nhooyr.io/websocket"
)

const (
	sendBuffer   = 64
	writeTimeout = 5 * time.Second
)

type Hub struct {
	register   chan *Client
	unregister chan *Client
	clients    map[*Client]struct{}
	count      atomic.Int64
}

func NewHub() *Hub {
	return &Hub{
		register:   make(chan *Client),
		unregister: make(chan *Client),
		clients:    make(map[*Client]struct{}),
	}
}

func (h *Hub) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			for c := range h.clients {
				c.close(websocket.StatusGoingAway, "server shutdown")
			}
			return
		case c := <-h.register:
			h.clients[c] = struct{}{}
			h.count.Add(1)
		case c := <-h.unregister:
			if _, ok := h.clients[c]; !ok {
				continue
			}
			delete(h.clients, c)
			h.count.Add(-1)
			c.close(websocket.StatusNormalClosure, "bye")
		}
	}
}

func (h *Hub) ClientCount() int64 {
	return h.count.Load()
}

func (h *Hub) HandleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}

	ctx, cancel := context.WithCancel(r.Context())
	client := &Client{
		conn:   conn,
		hub:    h,
		ctx:    ctx,
		cancel: cancel,
		send:   make(chan []byte, sendBuffer),
	}

	h.register <- client

	go client.writeLoop()
	go client.readLoop()
}

type Client struct {
	conn      *websocket.Conn
	hub       *Hub
	ctx       context.Context
	cancel    context.CancelFunc
	send      chan []byte
	closeOnce sync.Once
}

func (c *Client) Send(msg []byte) bool {
	select {
	case c.send <- msg:
		return true
	default:
		return false
	}
}

func (c *Client) readLoop() {
	defer func() {
		c.hub.unregister <- c
	}()

	for {
		_, _, err := c.conn.Read(c.ctx)
		if err != nil {
			return
		}
	}
}

func (c *Client) writeLoop() {
	for {
		select {
		case <-c.ctx.Done():
			return
		case msg, ok := <-c.send:
			if !ok {
				return
			}
			ctx, cancel := context.WithTimeout(c.ctx, writeTimeout)
			err := c.conn.Write(ctx, websocket.MessageBinary, msg)
			cancel()
			if err != nil {
				c.hub.unregister <- c
				return
			}
		}
	}
}

func (c *Client) close(status websocket.StatusCode, reason string) {
	c.closeOnce.Do(func() {
		c.cancel()
		close(c.send)
		_ = c.conn.Close(status, reason)
	})
}
