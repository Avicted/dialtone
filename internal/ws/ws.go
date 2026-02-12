package ws

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Avicted/dialtone/internal/auth"
	"github.com/Avicted/dialtone/internal/channel"
	"github.com/Avicted/dialtone/internal/device"
	"github.com/Avicted/dialtone/internal/message"
	"github.com/Avicted/dialtone/internal/securelog"
	"github.com/Avicted/dialtone/internal/storage"
	"github.com/Avicted/dialtone/internal/user"
	"github.com/google/uuid"
	"nhooyr.io/websocket"
)

const (
	sendBuffer    = 64
	writeTimeout  = 5 * time.Second
	pingInterval  = 25 * time.Second
	maxMessageLen = 16384
)

type Hub struct {
	register   chan *Client
	unregister chan *Client
	incoming   chan incomingMessage
	clients    map[*Client]struct{}
	byDevice   map[deviceKey]*Client
	byUser     map[user.ID]map[*Client]struct{}
	voiceRooms map[channel.ID]map[*Client]struct{}
	voiceRoom  map[*Client]channel.ID
	broadcasts message.BroadcastRepository
	devices    device.Repository
	channels   channel.Repository
	mu         sync.RWMutex
	count      atomic.Int64
}

func NewHub(broadcasts message.BroadcastRepository, devices device.Repository, channels channel.Repository) *Hub {
	return &Hub{
		register:   make(chan *Client),
		unregister: make(chan *Client),
		incoming:   make(chan incomingMessage, 256),
		clients:    make(map[*Client]struct{}),
		byDevice:   make(map[deviceKey]*Client),
		byUser:     make(map[user.ID]map[*Client]struct{}),
		voiceRooms: make(map[channel.ID]map[*Client]struct{}),
		voiceRoom:  make(map[*Client]channel.ID),
		broadcasts: broadcasts,
		devices:    devices,
		channels:   channels,
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
			var leftRoom channel.ID
			var leftPeers []*Client
			h.mu.Lock()
			if _, ok := h.clients[c]; !ok {
				h.mu.Unlock()
				continue
			}
			delete(h.clients, c)
			delete(h.byDevice, c.deviceKey())
			leftRoom = h.voiceRoom[c]
			leftPeers = h.removeFromVoiceRoomLocked(c)
			if clients := h.byUser[c.userID]; clients != nil {
				delete(clients, c)
				if len(clients) == 0 {
					delete(h.byUser, c.userID)
				}
			}
			h.mu.Unlock()
			h.count.Add(-1)
			if leftRoom != "" && len(leftPeers) > 0 {
				event := voiceSignalEvent{Type: "voice_leave", ChannelID: leftRoom, Sender: c.userID}
				for _, peer := range leftPeers {
					peer.sendEvent(event)
				}
			}
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
	if h.devices == nil {
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
		securelog.Error("ws.accept", err)
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
	h.notifyDeviceJoined(client.userID, client.deviceID)

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
			if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
				return
			}
			if isExpectedDisconnectError(err) {
				return
			}
			status := websocket.CloseStatus(err)
			if status == websocket.StatusNormalClosure || status == websocket.StatusGoingAway || status == websocket.StatusNoStatusRcvd {
				return
			}
			if status == -1 {
				securelog.Error("ws.read", err)
			}
			return
		}
		msg, err := decodeIncoming(data)
		if err != nil {
			securelog.Error("ws.decodeIncoming", err)
			c.sendError("invalid_message", err.Error())
			continue
		}
		c.hub.incoming <- incomingMessage{client: c, msg: msg}
	}
}

func isExpectedDisconnectError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "use of closed network connection")
}

func (c *Client) writeLoop() {
	pingTicker := time.NewTicker(pingInterval)
	defer pingTicker.Stop()
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
				if websocket.CloseStatus(err) == -1 {
					securelog.Error("ws.write", err)
				}
				c.hub.unregister <- c
				return
			}
		case <-pingTicker.C:
			ctx, cancel := context.WithTimeout(c.ctx, writeTimeout)
			err := c.conn.Ping(ctx)
			cancel()
			if err != nil {
				if websocket.CloseStatus(err) == -1 {
					securelog.Error("ws.ping", err)
				}
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
	ChannelID     channel.ID        `json:"channel_id"`
	Body          string            `json:"body"`
	MessageID     string            `json:"message_id"`
	ClientTime    string            `json:"client_time"`
	PublicKey     string            `json:"public_key"`
	SenderNameEnc string            `json:"sender_name_enc,omitempty"`
	Envelopes     map[string]string `json:"key_envelopes,omitempty"`
	SDP           string            `json:"sdp,omitempty"`
	Candidate     string            `json:"candidate,omitempty"`
}

type outboundMessage struct {
	Type            string     `json:"type"`
	MessageID       string     `json:"message_id"`
	Sender          user.ID    `json:"sender"`
	SenderName      string     `json:"sender_name"`
	SenderNameEnc   string     `json:"sender_name_enc,omitempty"`
	ChannelID       channel.ID `json:"channel_id,omitempty"`
	ChannelNameEnc  string     `json:"channel_name_enc,omitempty"`
	SenderPublicKey string     `json:"sender_public_key,omitempty"`
	KeyEnvelope     string     `json:"key_envelope,omitempty"`
	DeviceID        device.ID  `json:"device_id,omitempty"`
	Body            string     `json:"body"`
	SentAt          string     `json:"sent_at"`
}

type errorEvent struct {
	Type    string `json:"type"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

type voiceSignalEvent struct {
	Type      string     `json:"type"`
	ChannelID channel.ID `json:"channel_id"`
	Sender    user.ID    `json:"sender"`
	Users     []user.ID  `json:"users,omitempty"`
	Recipient user.ID    `json:"recipient,omitempty"`
	SDP       string     `json:"sdp,omitempty"`
	Candidate string     `json:"candidate,omitempty"`
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
	case "channel.message.send":
		if msg.ChannelID == "" || msg.Body == "" {
			return inboundMessage{}, errors.New("channel_id and body are required")
		}
		if len(msg.Body) > maxMessageLen {
			return inboundMessage{}, errors.New("message exceeds maximum length")
		}
		if strings.TrimSpace(msg.SenderNameEnc) == "" {
			return inboundMessage{}, errors.New("sender_name_enc is required")
		}
	case "voice_join":
		if msg.ChannelID == "" {
			return inboundMessage{}, errors.New("channel_id is required")
		}
	case "voice_leave":
		if msg.ChannelID == "" {
			return inboundMessage{}, errors.New("channel_id is required")
		}
	case "webrtc_offer", "webrtc_answer":
		if msg.ChannelID == "" || strings.TrimSpace(msg.SDP) == "" || msg.Recipient == "" {
			return inboundMessage{}, errors.New("channel_id, recipient, and sdp are required")
		}
	case "ice_candidate":
		if msg.ChannelID == "" || strings.TrimSpace(msg.Candidate) == "" || msg.Recipient == "" {
			return inboundMessage{}, errors.New("channel_id, recipient, and candidate are required")
		}
	}
	return msg, nil
}

func (h *Hub) handleIncoming(ctx context.Context, incoming incomingMessage) {
	switch incoming.msg.Type {
	case "message.send":
		if incoming.client != nil {
			incoming.client.sendError("channels_only", "direct messages are disabled; select a channel")
		}
	case "message.broadcast":
		if incoming.client != nil {
			incoming.client.sendError("channels_only", "global chat is disabled; select a channel")
		}
	case "channel.message.send":
		h.handleChannelMessage(ctx, incoming.client, incoming.msg)
	case "voice_join":
		h.handleVoiceJoin(ctx, incoming.client, incoming.msg)
	case "voice_leave":
		h.handleVoiceLeave(incoming.client, incoming.msg)
	case "webrtc_offer", "webrtc_answer", "ice_candidate":
		h.handleVoiceSignal(incoming.client, incoming.msg)
	default:
		incoming.client.sendError("unsupported_type", "unsupported message type")
	}
}

func (h *Hub) handleVoiceJoin(ctx context.Context, client *Client, msg inboundMessage) {
	if client == nil || client.userID == "" {
		return
	}
	log.Printf("ws.voice_join channel=%s", msg.ChannelID)
	if msg.ChannelID == "" {
		client.sendError("invalid_message", "channel_id is required")
		return
	}
	if h.channels == nil {
		client.sendError("server_error", "channel storage unavailable")
		return
	}
	if _, err := h.channels.GetChannel(ctx, msg.ChannelID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			client.sendError("channel_not_found", "channel does not exist")
			return
		}
		securelog.Error("ws.getChannel", err)
		client.sendError("server_error", "failed to resolve channel")
		return
	}

	h.mu.Lock()
	h.removeFromVoiceRoomLocked(client)
	clients := h.voiceRooms[msg.ChannelID]
	if clients == nil {
		clients = make(map[*Client]struct{})
		h.voiceRooms[msg.ChannelID] = clients
	}
	clients[client] = struct{}{}
	h.voiceRoom[client] = msg.ChannelID
	peers := make([]*Client, 0, len(clients))
	roster := make([]user.ID, 0, len(clients))
	for peer := range clients {
		peers = append(peers, peer)
		if peer.userID != "" {
			roster = append(roster, peer.userID)
		}
	}
	h.mu.Unlock()

	sort.Slice(roster, func(i, j int) bool {
		return roster[i] < roster[j]
	})
	client.sendEvent(voiceSignalEvent{Type: "voice_roster", ChannelID: msg.ChannelID, Users: roster})

	event := voiceSignalEvent{
		Type:      "voice_join",
		ChannelID: msg.ChannelID,
		Sender:    client.userID,
	}
	for _, peer := range peers {
		peer.sendEvent(event)
	}
}

func (h *Hub) handleVoiceLeave(client *Client, msg inboundMessage) {
	if client == nil || client.userID == "" {
		return
	}
	log.Printf("ws.voice_leave channel=%s", msg.ChannelID)
	if msg.ChannelID == "" {
		client.sendError("invalid_message", "channel_id is required")
		return
	}

	var peers []*Client
	h.mu.Lock()
	roomID, ok := h.voiceRoom[client]
	if ok && roomID == msg.ChannelID {
		peers = h.removeFromVoiceRoomLocked(client)
	}
	h.mu.Unlock()

	if len(peers) == 0 {
		return
	}
	event := voiceSignalEvent{
		Type:      "voice_leave",
		ChannelID: msg.ChannelID,
		Sender:    client.userID,
	}
	for _, peer := range peers {
		peer.sendEvent(event)
	}
}

func (h *Hub) handleVoiceSignal(client *Client, msg inboundMessage) {
	if client == nil || client.userID == "" {
		return
	}
	log.Printf("ws.voice_signal type=%s channel=%s", msg.Type, msg.ChannelID)
	if msg.ChannelID == "" {
		client.sendError("invalid_message", "channel_id is required")
		return
	}

	h.mu.RLock()
	roomID := h.voiceRoom[client]
	clients := h.voiceRooms[msg.ChannelID]
	var peers []*Client
	if roomID == msg.ChannelID {
		if msg.Recipient != "" {
			if targets := h.byUser[msg.Recipient]; targets != nil {
				for peer := range targets {
					if peer != client {
						if _, ok := clients[peer]; ok {
							peers = append(peers, peer)
						}
					}
				}
			}
		} else {
			for peer := range clients {
				if peer != client {
					peers = append(peers, peer)
				}
			}
		}
	}
	h.mu.RUnlock()
	if roomID != msg.ChannelID {
		client.sendError("voice_not_joined", "join voice before signaling")
		return
	}

	event := voiceSignalEvent{
		Type:      msg.Type,
		ChannelID: msg.ChannelID,
		Sender:    client.userID,
		Recipient: msg.Recipient,
		SDP:       msg.SDP,
		Candidate: msg.Candidate,
	}
	for _, peer := range peers {
		peer.sendEvent(event)
	}
}

func (h *Hub) removeFromVoiceRoomLocked(client *Client) []*Client {
	roomID, ok := h.voiceRoom[client]
	if !ok {
		return nil
	}
	clients := h.voiceRooms[roomID]
	delete(h.voiceRoom, client)
	if clients != nil {
		delete(clients, client)
		if len(clients) == 0 {
			delete(h.voiceRooms, roomID)
			return nil
		}
		peers := make([]*Client, 0, len(clients))
		for peer := range clients {
			peers = append(peers, peer)
		}
		return peers
	}
	return nil
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

func (h *Hub) handleChannelMessage(ctx context.Context, sender *Client, msg inboundMessage) {
	if sender == nil || sender.userID == "" {
		return
	}
	if msg.ChannelID == "" || msg.Body == "" {
		sender.sendError("invalid_message", "channel_id and body are required")
		return
	}
	if h.channels == nil {
		sender.sendError("server_error", "channel storage unavailable")
		return
	}

	if _, err := h.channels.GetChannel(ctx, msg.ChannelID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			sender.sendError("channel_not_found", "channel does not exist")
			return
		}
		securelog.Error("ws.getChannel", err)
		sender.sendError("server_error", "failed to resolve channel")
		return
	}

	senderNameEnc := strings.TrimSpace(msg.SenderNameEnc)

	sentAt := time.Now().UTC()
	msgID := uuid.NewString()
	record := channel.Message{
		ID:            msgID,
		ChannelID:     msg.ChannelID,
		SenderID:      sender.userID,
		SenderNameEnc: senderNameEnc,
		Body:          msg.Body,
		SentAt:        sentAt,
	}
	if err := h.channels.SaveMessage(ctx, record); err != nil {
		securelog.Error("ws.saveMessage", err)
		sender.sendError("server_error", "failed to store channel message")
		return
	}

	out := outboundMessage{
		Type:          "channel.message.new",
		MessageID:     msgID,
		ChannelID:     msg.ChannelID,
		Sender:        sender.userID,
		SenderNameEnc: senderNameEnc,
		Body:          msg.Body,
		SentAt:        sentAt.Format(time.RFC3339Nano),
	}

	h.mu.RLock()
	clients := make([]*Client, 0, len(h.clients))
	for client := range h.clients {
		clients = append(clients, client)
	}
	h.mu.RUnlock()
	for _, client := range clients {
		client.sendEvent(out)
	}
}

func (h *Hub) sendHistory(ctx context.Context, client *Client) {
	if client == nil {
		return
	}
}

func (h *Hub) NotifyChannelUpdated(ch channel.Channel) {
	if h == nil || ch.ID == "" {
		return
	}
	out := outboundMessage{
		Type:           "channel.updated",
		ChannelID:      ch.ID,
		ChannelNameEnc: ch.NameEnc,
	}
	h.mu.RLock()
	clients := make([]*Client, 0, len(h.clients))
	for client := range h.clients {
		clients = append(clients, client)
	}
	h.mu.RUnlock()
	for _, client := range clients {
		client.sendEvent(out)
	}
}

func (h *Hub) NotifyChannelDeleted(id channel.ID) {
	if h == nil || id == "" {
		return
	}
	out := outboundMessage{
		Type:      "channel.deleted",
		ChannelID: id,
	}
	h.mu.RLock()
	clients := make([]*Client, 0, len(h.clients))
	for client := range h.clients {
		clients = append(clients, client)
	}
	h.mu.RUnlock()
	for _, client := range clients {
		client.sendEvent(out)
	}
}

func (h *Hub) NotifyUserProfileUpdated(id user.ID) {
	if h == nil || id == "" {
		return
	}
	out := outboundMessage{
		Type:   "user.profile.updated",
		Sender: id,
	}
	h.mu.RLock()
	clients := make([]*Client, 0, len(h.clients))
	for client := range h.clients {
		clients = append(clients, client)
	}
	h.mu.RUnlock()
	for _, client := range clients {
		client.sendEvent(out)
	}
}

func (h *Hub) notifyDeviceJoined(userID user.ID, deviceID device.ID) {
	if h == nil || userID == "" || deviceID == "" {
		return
	}
	out := outboundMessage{
		Type:     "device.joined",
		Sender:   userID,
		DeviceID: deviceID,
	}
	h.mu.RLock()
	clients := make([]*Client, 0, len(h.clients))
	for client := range h.clients {
		clients = append(clients, client)
	}
	h.mu.RUnlock()
	for _, client := range clients {
		client.sendEvent(out)
	}
}
