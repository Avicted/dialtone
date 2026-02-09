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
	"github.com/Avicted/dialtone/internal/room"
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
	broadcasts message.BroadcastRepository
	devices    device.Repository
	rooms      room.Repository
	mu         sync.RWMutex
	count      atomic.Int64
}

func NewHub(messages message.Repository, broadcasts message.BroadcastRepository, devices device.Repository, rooms room.Repository) *Hub {
	return &Hub{
		register:   make(chan *Client),
		unregister: make(chan *Client),
		incoming:   make(chan incomingMessage, 256),
		clients:    make(map[*Client]struct{}),
		byDevice:   make(map[deviceKey]*Client),
		byUser:     make(map[user.ID]map[*Client]struct{}),
		messages:   messages,
		broadcasts: broadcasts,
		devices:    devices,
		rooms:      rooms,
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
			h.mu.Lock()
			h.clients[c] = struct{}{}
			h.byDevice[c.deviceKey()] = c
			if h.byUser[c.userID] == nil {
				h.byUser[c.userID] = make(map[*Client]struct{})
			}
			h.byUser[c.userID][c] = struct{}{}
			h.mu.Unlock()
			h.count.Add(1)
		case c := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[c]; !ok {
				h.mu.Unlock()
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
			h.mu.Unlock()
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

func (h *Hub) IsOnline(userID user.ID) bool {
	if userID == "" {
		return false
	}
	h.mu.RLock()
	clients := h.byUser[userID]
	online := len(clients) > 0
	h.mu.RUnlock()
	return online
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

	ctx, cancel := context.WithCancel(context.Background())
	client := &Client{
		conn:     conn,
		hub:      h,
		ctx:      ctx,
		cancel:   cancel,
		send:     make(chan []byte, sendBuffer),
		userID:   clientSession.UserID,
		deviceID: clientSession.DeviceID,
		username: clientSession.Username,
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
	username  string
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
	Type          string            `json:"type"`
	Recipient     user.ID           `json:"recipient"`
	RoomID        room.ID           `json:"room_id"`
	Body          string            `json:"body"`
	MessageID     string            `json:"message_id"`
	ClientTime    string            `json:"client_time"`
	PublicKey     string            `json:"public_key"`
	SenderNameEnc string            `json:"sender_name_enc,omitempty"`
	Envelopes     map[string]string `json:"key_envelopes,omitempty"`
}

type outboundMessage struct {
	Type            string  `json:"type"`
	MessageID       string  `json:"message_id"`
	Sender          user.ID `json:"sender"`
	SenderName      string  `json:"sender_name"`
	SenderNameEnc   string  `json:"sender_name_enc,omitempty"`
	RoomID          room.ID `json:"room_id,omitempty"`
	SenderPublicKey string  `json:"sender_public_key,omitempty"`
	KeyEnvelope     string  `json:"key_envelope,omitempty"`
	Body            string  `json:"body"`
	SentAt          string  `json:"sent_at"`
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
	switch msg.Type {
	case "message.send":
		if msg.Recipient == "" || msg.Body == "" {
			return inboundMessage{}, errors.New("recipient and body are required")
		}
	case "message.broadcast":
		if msg.Body == "" || strings.TrimSpace(msg.SenderNameEnc) == "" {
			return inboundMessage{}, errors.New("body and sender_name_enc are required")
		}
	case "room.message.send":
		if msg.RoomID == "" || msg.Body == "" {
			return inboundMessage{}, errors.New("room_id and body are required")
		}
	}
	return msg, nil
}

func (h *Hub) handleIncoming(ctx context.Context, incoming incomingMessage) {
	switch incoming.msg.Type {
	case "message.send":
		h.handleSend(ctx, incoming.client, incoming.msg)
	case "message.broadcast":
		if incoming.client != nil {
			incoming.client.sendError("rooms_only", "global chat is disabled; join a room")
		}
	case "room.message.send":
		h.handleRoomMessage(ctx, incoming.client, incoming.msg)
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

	h.mu.RLock()
	recipients := h.byUser[msg.Recipient]
	clients := make([]*Client, 0, len(recipients))
	for client := range recipients {
		clients = append(clients, client)
	}
	h.mu.RUnlock()
	for _, client := range clients {
		envelopeID := envelopeIDs[client.deviceID]
		if envelopeID == "" {
			envelopeID = uuid.NewString()
		}
		client.sendEvent(outboundMessage{
			Type:       "message.new",
			MessageID:  envelopeID,
			Sender:     sender.userID,
			SenderName: sender.username,
			Body:       msg.Body,
			SentAt:     sentAt.Format(time.RFC3339Nano),
		})
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
		Type:       "message.new",
		MessageID:  ackID,
		Sender:     sender.userID,
		SenderName: sender.username,
		Body:       msg.Body,
		SentAt:     sentAt.Format(time.RFC3339Nano),
	})
}

func (h *Hub) handleBroadcast(ctx context.Context, sender *Client, msg inboundMessage) {
	if sender == nil || sender.userID == "" {
		return
	}
	if msg.Body == "" || strings.TrimSpace(msg.SenderNameEnc) == "" {
		sender.sendError("invalid_message", "body and sender_name_enc are required")
		return
	}
	if strings.TrimSpace(msg.PublicKey) == "" {
		sender.sendError("invalid_message", "public_key is required")
		return
	}
	if len(msg.Envelopes) == 0 {
		sender.sendError("invalid_message", "key_envelopes are required")
		return
	}

	sentAt := time.Now().UTC()
	msgID := uuid.NewString()

	if h.broadcasts != nil {
		record := message.BroadcastMessage{
			ID:              message.ID(msgID),
			SenderID:        sender.userID,
			SenderNameEnc:   strings.TrimSpace(msg.SenderNameEnc),
			SenderPublicKey: msg.PublicKey,
			Body:            msg.Body,
			Envelopes:       msg.Envelopes,
			SentAt:          sentAt,
		}
		if err := h.broadcasts.Save(ctx, record); err != nil {
			sender.sendError("server_error", "failed to store message")
			return
		}
	}

	out := outboundMessage{
		Type:            "message.broadcast",
		MessageID:       msgID,
		Sender:          sender.userID,
		SenderNameEnc:   strings.TrimSpace(msg.SenderNameEnc),
		SenderPublicKey: msg.PublicKey,
		Body:            msg.Body,
		SentAt:          sentAt.Format(time.RFC3339Nano),
	}

	h.mu.RLock()
	clients := make([]*Client, 0, len(h.clients))
	for client := range h.clients {
		clients = append(clients, client)
	}
	h.mu.RUnlock()
	for _, client := range clients {
		perClient := out
		if msg.Envelopes != nil {
			perClient.KeyEnvelope = msg.Envelopes[string(client.deviceID)]
		}
		client.sendEvent(perClient)
	}
}

func (h *Hub) handleRoomMessage(ctx context.Context, sender *Client, msg inboundMessage) {
	if sender == nil || sender.userID == "" {
		return
	}
	if msg.RoomID == "" || msg.Body == "" {
		sender.sendError("invalid_message", "room_id and body are required")
		return
	}
	if h.rooms == nil {
		sender.sendError("server_error", "room storage unavailable")
		return
	}

	isMember, err := h.rooms.IsMember(ctx, msg.RoomID, sender.userID)
	if err != nil {
		sender.sendError("server_error", "failed to check membership")
		return
	}
	if !isMember {
		sender.sendError("room_forbidden", "not a room member")
		return
	}

	senderNameEnc, err := h.rooms.GetMemberDisplayNameEnc(ctx, msg.RoomID, sender.userID)
	if err != nil {
		sender.sendError("server_error", "failed to resolve display name")
		return
	}

	sentAt := time.Now().UTC()
	msgID := uuid.NewString()
	record := room.Message{
		ID:            msgID,
		RoomID:        msg.RoomID,
		SenderID:      sender.userID,
		SenderNameEnc: senderNameEnc,
		Body:          msg.Body,
		SentAt:        sentAt,
	}
	if err := h.rooms.SaveMessage(ctx, record); err != nil {
		sender.sendError("server_error", "failed to store room message")
		return
	}

	members, err := h.rooms.ListMembers(ctx, msg.RoomID)
	if err != nil {
		sender.sendError("server_error", "failed to list room members")
		return
	}

	out := outboundMessage{
		Type:          "room.message.new",
		MessageID:     msgID,
		RoomID:        msg.RoomID,
		Sender:        sender.userID,
		SenderNameEnc: senderNameEnc,
		Body:          msg.Body,
		SentAt:        sentAt.Format(time.RFC3339Nano),
	}

	for _, member := range members {
		h.mu.RLock()
		recipients := h.byUser[member.UserID]
		clients := make([]*Client, 0, len(recipients))
		for client := range recipients {
			clients = append(clients, client)
		}
		h.mu.RUnlock()
		for _, client := range clients {
			client.sendEvent(out)
		}
	}
}

func (h *Hub) sendHistory(ctx context.Context, client *Client) {
	if client == nil {
		return
	}
}
