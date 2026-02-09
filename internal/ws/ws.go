package ws

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Avicted/dialtone/internal/auth"
	"github.com/Avicted/dialtone/internal/device"
	"github.com/Avicted/dialtone/internal/message"
	"github.com/Avicted/dialtone/internal/storage"
	"github.com/Avicted/dialtone/internal/user"
	"github.com/google/uuid"
	"nhooyr.io/websocket"
)

const (
	sendBuffer   = 64
	writeTimeout = 5 * time.Second
)

type Hub struct {
	register   chan *Client
	unregister chan *Client
	incoming   chan incomingMessage
	clients    map[*Client]struct{}
	byDevice   map[deviceKey]*Client
	byUser     map[user.ID]map[*Client]struct{}
	messages   message.Repository
	devices    device.Repository
	count      atomic.Int64
}

func NewHub(messages message.Repository, devices device.Repository) *Hub {
	return &Hub{
		register:   make(chan *Client),
		unregister: make(chan *Client),
		incoming:   make(chan incomingMessage, 256),
		clients:    make(map[*Client]struct{}),
		byDevice:   make(map[deviceKey]*Client),
		byUser:     make(map[user.ID]map[*Client]struct{}),
		messages:   messages,
		devices:    devices,
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
			h.byDevice[c.deviceKey()] = c
			if h.byUser[c.userID] == nil {
				h.byUser[c.userID] = make(map[*Client]struct{})
			}
			h.byUser[c.userID][c] = struct{}{}
			h.count.Add(1)
		case c := <-h.unregister:
			if _, ok := h.clients[c]; !ok {
				continue
			}
			delete(h.clients, c)
			delete(h.byDevice, c.deviceKey())
			if clients := h.byUser[c.userID]; clients != nil {
				delete(clients, c)
				if len(clients) == 0 {
					delete(h.byUser, c.userID)
				}
			}
			h.count.Add(-1)
			c.close(websocket.StatusNormalClosure, "bye")
		case msg := <-h.incoming:
			h.handleIncoming(ctx, msg)
		}
	}
}

func (h *Hub) ClientCount() int64 {
	return h.count.Load()
}

func (h *Hub) HandleWS(w http.ResponseWriter, r *http.Request) {
	if h.messages == nil || h.devices == nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	validator, ok := r.Context().Value(authValidatorKey{}).(tokenValidator)
	if !ok || validator == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	clientSession, err := authenticateRequest(r, validator)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}

	ctx, cancel := context.WithCancel(r.Context())
	client := &Client{
		conn:     conn,
		hub:      h,
		ctx:      ctx,
		cancel:   cancel,
		send:     make(chan []byte, sendBuffer),
		userID:   clientSession.UserID,
		deviceID: clientSession.DeviceID,
	}

	h.register <- client

	go client.writeLoop()
	go client.readLoop()

	h.sendHistory(ctx, client)
}

type Client struct {
	conn      *websocket.Conn
	hub       *Hub
	ctx       context.Context
	cancel    context.CancelFunc
	send      chan []byte
	closeOnce sync.Once
	userID    user.ID
	deviceID  device.ID
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
		_, data, err := c.conn.Read(c.ctx)
		if err != nil {
			return
		}
		msg, err := decodeIncoming(data)
		if err != nil {
			c.sendError("invalid_message", err.Error())
			continue
		}
		c.hub.incoming <- incomingMessage{client: c, msg: msg}
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
			err := c.conn.Write(ctx, websocket.MessageText, msg)
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

func (c *Client) sendEvent(payload any) {
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	_ = c.Send(data)
}

func (c *Client) sendError(code, message string) {
	c.sendEvent(errorEvent{Type: "error", Code: code, Message: message})
}

func (c *Client) deviceKey() deviceKey {
	return deviceKey{userID: c.userID, deviceID: c.deviceID}
}

type deviceKey struct {
	userID   user.ID
	deviceID device.ID
}

type incomingMessage struct {
	client *Client
	msg    inboundMessage
}

type inboundMessage struct {
	Type       string  `json:"type"`
	Recipient  user.ID `json:"recipient"`
	Body       string  `json:"body"`
	MessageID  string  `json:"message_id"`
	ClientTime string  `json:"client_time"`
}

type outboundMessage struct {
	Type      string  `json:"type"`
	MessageID string  `json:"message_id"`
	Sender    user.ID `json:"sender"`
	Body      string  `json:"body"`
	SentAt    string  `json:"sent_at"`
}

type errorEvent struct {
	Type    string `json:"type"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

type tokenValidator interface {
	ValidateToken(token string) (auth.Session, error)
}

type authValidatorKey struct{}

func WithAuthValidator(next http.Handler, validator tokenValidator) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), authValidatorKey{}, validator)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func authenticateRequest(r *http.Request, validator tokenValidator) (auth.Session, error) {
	if validator == nil {
		return auth.Session{}, auth.ErrUnauthorized
	}
	if token := strings.TrimSpace(r.URL.Query().Get("token")); token != "" {
		return validator.ValidateToken(token)
	}
	if header := strings.TrimSpace(r.Header.Get("Authorization")); header != "" {
		return parseAuthHeader(header, validator)
	}
	return auth.Session{}, auth.ErrUnauthorized
}

func parseAuthHeader(header string, validator tokenValidator) (auth.Session, error) {
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return auth.Session{}, auth.ErrUnauthorized
	}
	return validator.ValidateToken(parts[1])
}

func decodeIncoming(data []byte) (inboundMessage, error) {
	var msg inboundMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return inboundMessage{}, err
	}
	msg.Type = strings.TrimSpace(msg.Type)
	msg.Body = strings.TrimSpace(msg.Body)
	if msg.Type == "message.send" {
		if msg.Recipient == "" || msg.Body == "" {
			return inboundMessage{}, errors.New("recipient and body are required")
		}
	}
	return msg, nil
}

func (h *Hub) handleIncoming(ctx context.Context, incoming incomingMessage) {
	switch incoming.msg.Type {
	case "message.send":
		h.handleSend(ctx, incoming.client, incoming.msg)
	default:
		incoming.client.sendError("unsupported_type", "unsupported message type")
	}
}

func (h *Hub) handleSend(ctx context.Context, sender *Client, msg inboundMessage) {
	if sender == nil || sender.userID == "" {
		return
	}
	if msg.Recipient == "" || msg.Body == "" {
		sender.sendError("invalid_message", "recipient and body are required")
		return
	}

	if h.messages == nil {
		sender.sendError("server_error", "message storage unavailable")
		return
	}

	recipientDevices, err := h.devices.ListByUser(ctx, msg.Recipient)
	if err != nil {
		sender.sendError("server_error", "failed to resolve recipient devices")
		return
	}
	if len(recipientDevices) == 0 {
		sender.sendError("recipient_unavailable", "recipient has no devices")
		return
	}

	sentAt := time.Now().UTC()
	clientMessageID := strings.TrimSpace(msg.MessageID)
	envelopeIDs := make(map[device.ID]string, len(recipientDevices))

	for _, dev := range recipientDevices {
		envelopeID := uuid.NewString()
		envelopeIDs[dev.ID] = envelopeID
		msgRecord := message.Message{
			ID:                message.ID(envelopeID),
			SenderID:          sender.userID,
			RecipientID:       msg.Recipient,
			RecipientDeviceID: dev.ID,
			Ciphertext:        []byte(msg.Body),
			SentAt:            sentAt,
		}
		if err := h.messages.Save(ctx, msgRecord); err != nil {
			sender.sendError("server_error", "failed to store message")
			return
		}
	}

	if recipients := h.byUser[msg.Recipient]; recipients != nil {
		for client := range recipients {
			envelopeID := envelopeIDs[client.deviceID]
			if envelopeID == "" {
				envelopeID = uuid.NewString()
			}
			client.sendEvent(outboundMessage{
				Type:      "message.new",
				MessageID: envelopeID,
				Sender:    sender.userID,
				Body:      msg.Body,
				SentAt:    sentAt.Format(time.RFC3339Nano),
			})
		}
	}

	ackID := ""
	for _, id := range envelopeIDs {
		ackID = id
		break
	}
	if ackID == "" {
		ackID = clientMessageID
		if ackID == "" {
			ackID = uuid.NewString()
		}
	}
	sender.sendEvent(outboundMessage{
		Type:      "message.new",
		MessageID: ackID,
		Sender:    sender.userID,
		Body:      msg.Body,
		SentAt:    sentAt.Format(time.RFC3339Nano),
	})
}

func (h *Hub) sendHistory(ctx context.Context, client *Client) {
	if client == nil || h.messages == nil {
		return
	}

	msgs, err := h.messages.ListForRecipientDevice(ctx, client.deviceID, 100)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return
		}
		client.sendError("server_error", "failed to load history")
		return
	}

	for _, msg := range msgs {
		client.sendEvent(outboundMessage{
			Type:      "message.history",
			MessageID: string(msg.ID),
			Sender:    msg.SenderID,
			Body:      string(msg.Ciphertext),
			SentAt:    msg.SentAt.UTC().Format(time.RFC3339Nano),
		})
	}
}
