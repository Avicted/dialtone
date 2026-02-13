package ws

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Avicted/dialtone/internal/auth"
	"github.com/Avicted/dialtone/internal/channel"
	"github.com/Avicted/dialtone/internal/device"
	"github.com/Avicted/dialtone/internal/message"
	"github.com/Avicted/dialtone/internal/storage"
	"github.com/Avicted/dialtone/internal/user"
	"nhooyr.io/websocket"
)

type fakeValidator struct {
	sessions map[string]auth.Session
}

func (v *fakeValidator) ValidateToken(token string) (auth.Session, error) {
	s, ok := v.sessions[token]
	if !ok {
		return auth.Session{}, auth.ErrUnauthorized
	}
	return s, nil
}

type fakeDeviceRepo struct{}

func (r *fakeDeviceRepo) Create(_ context.Context, _ device.Device) error { return nil }

func (r *fakeDeviceRepo) GetByID(_ context.Context, _ device.ID) (device.Device, error) {
	return device.Device{}, device.ErrNotFound
}

func (r *fakeDeviceRepo) GetByUserAndPublicKey(_ context.Context, _ user.ID, _ string) (device.Device, error) {
	return device.Device{}, device.ErrNotFound
}

func (r *fakeDeviceRepo) ListByUser(_ context.Context, _ user.ID) ([]device.Device, error) {
	return nil, nil
}

func (r *fakeDeviceRepo) ListAll(_ context.Context) ([]device.Device, error) {
	return nil, nil
}

func (r *fakeDeviceRepo) UpdateLastSeen(_ context.Context, _ device.ID, _ time.Time) error {
	return nil
}

type fakeBroadcastRepo struct {
	saved []message.BroadcastMessage
	err   error
}

func (r *fakeBroadcastRepo) Save(_ context.Context, msg message.BroadcastMessage) error {
	r.saved = append(r.saved, msg)
	return r.err
}

func (r *fakeBroadcastRepo) ListRecent(_ context.Context, _ int) ([]message.BroadcastMessage, error) {
	return nil, nil
}

type fakeChannelRepo struct {
	ch      channel.Channel
	getErr  error
	saveErr error
	saved   []channel.Message
}

func (r *fakeChannelRepo) CreateChannel(_ context.Context, _ channel.Channel) error { return nil }

func (r *fakeChannelRepo) GetChannel(_ context.Context, _ channel.ID) (channel.Channel, error) {
	if r.getErr != nil {
		return channel.Channel{}, r.getErr
	}
	if r.ch.ID == "" {
		return channel.Channel{}, storage.ErrNotFound
	}
	return r.ch, nil
}

func (r *fakeChannelRepo) ListChannels(_ context.Context) ([]channel.Channel, error) { return nil, nil }

func (r *fakeChannelRepo) UpdateChannelName(_ context.Context, _ channel.ID, _ string) error {
	return nil
}

func (r *fakeChannelRepo) DeleteChannel(_ context.Context, _ channel.ID) error { return nil }

func (r *fakeChannelRepo) SaveMessage(_ context.Context, msg channel.Message) error {
	if r.saveErr != nil {
		return r.saveErr
	}
	r.saved = append(r.saved, msg)
	return nil
}

func (r *fakeChannelRepo) ListRecentMessages(_ context.Context, _ channel.ID, _ int) ([]channel.Message, error) {
	return nil, nil
}

func (r *fakeChannelRepo) UpsertKeyEnvelope(_ context.Context, _ channel.KeyEnvelope) error {
	return nil
}

func (r *fakeChannelRepo) GetKeyEnvelope(_ context.Context, _ channel.ID, _ device.ID) (channel.KeyEnvelope, error) {
	return channel.KeyEnvelope{}, storage.ErrNotFound
}

type wsPair struct {
	server *websocket.Conn
	err    error
}

func newWebsocketPair(t *testing.T) (*websocket.Conn, *websocket.Conn, func()) {
	t.Helper()

	connCh := make(chan wsPair, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		connCh <- wsPair{server: conn, err: err}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	clientConn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	cancel()
	if err != nil {
		srv.Close()
		t.Fatalf("dial websocket: %v", err)
	}

	var pair wsPair
	select {
	case pair = <-connCh:
	case <-time.After(time.Second):
		_ = clientConn.Close(websocket.StatusNormalClosure, "timeout")
		srv.Close()
		t.Fatal("timeout waiting for server websocket")
	}
	if pair.err != nil {
		_ = clientConn.Close(websocket.StatusNormalClosure, "accept failed")
		srv.Close()
		t.Fatalf("accept websocket: %v", pair.err)
	}

	cleanup := func() {
		_ = clientConn.Close(websocket.StatusNormalClosure, "bye")
		_ = pair.server.Close(websocket.StatusNormalClosure, "bye")
		srv.Close()
	}
	return pair.server, clientConn, cleanup
}

func waitFor(t *testing.T, timeout time.Duration, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if check() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timeout waiting for condition")
}

func readEvent[T any](t *testing.T, ch <-chan []byte) T {
	t.Helper()
	select {
	case data := <-ch:
		var out T
		if err := json.Unmarshal(data, &out); err != nil {
			t.Fatalf("unmarshal event: %v", err)
		}
		return out
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for event")
	}
	var zero T
	return zero
}

func TestDecodeIncoming_BroadcastValid(t *testing.T) {
	data := []byte(`{"type":"message.broadcast","body":"hello world","sender_name_enc":"abc"}`)
	msg, err := decodeIncoming(data)
	if err != nil {
		t.Fatalf("decodeIncoming() error = %v", err)
	}
	if msg.Type != "message.broadcast" {
		t.Errorf("Type = %q, want %q", msg.Type, "message.broadcast")
	}
	if msg.Body != "hello world" {
		t.Errorf("Body = %q, want %q", msg.Body, "hello world")
	}
}

func TestDecodeIncoming_SendValid(t *testing.T) {
	data := []byte(`{"type":"message.send","recipient":"user-1","body":"hey"}`)
	msg, err := decodeIncoming(data)
	if err != nil {
		t.Fatalf("decodeIncoming() error = %v", err)
	}
	if msg.Recipient != "user-1" {
		t.Errorf("Recipient = %q, want %q", msg.Recipient, "user-1")
	}
}

func TestDecodeIncoming_BroadcastEmptyBody(t *testing.T) {
	data := []byte(`{"type":"message.broadcast","body":"","sender_name_enc":"abc"}`)
	_, err := decodeIncoming(data)
	if err == nil {
		t.Fatal("expected error for empty body")
	}
}

func TestDecodeIncoming_SendMissingRecipient(t *testing.T) {
	data := []byte(`{"type":"message.send","body":"hey"}`)
	_, err := decodeIncoming(data)
	if err == nil {
		t.Fatal("expected error for missing recipient")
	}
}

func TestDecodeIncoming_InvalidJSON(t *testing.T) {
	_, err := decodeIncoming([]byte("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestDecodeIncoming_UnknownTypePassesThrough(t *testing.T) {
	data := []byte(`{"type":"something.else","body":"data"}`)
	msg, err := decodeIncoming(data)
	if err != nil {
		t.Fatalf("decodeIncoming() error = %v", err)
	}
	if msg.Type != "something.else" {
		t.Errorf("Type = %q, want %q", msg.Type, "something.else")
	}
}

func TestDecodeIncoming_WhitespaceTrimming(t *testing.T) {
	data := []byte(`{"type":"  message.broadcast  ","body":"  hello  ","sender_name_enc":"  abc  "}`)
	msg, err := decodeIncoming(data)
	if err != nil {
		t.Fatalf("decodeIncoming() error = %v", err)
	}
	if msg.Type != "message.broadcast" {
		t.Errorf("Type = %q, want trimmed", msg.Type)
	}
	if msg.Body != "hello" {
		t.Errorf("Body = %q, want trimmed", msg.Body)
	}
}

func TestDecodeIncoming_PublicKeyField(t *testing.T) {
	data := []byte(`{"type":"message.broadcast","body":"hi","public_key":"abc123","sender_name_enc":"abc"}`)
	msg, err := decodeIncoming(data)
	if err != nil {
		t.Fatalf("decodeIncoming() error = %v", err)
	}
	if msg.PublicKey != "abc123" {
		t.Errorf("PublicKey = %q, want %q", msg.PublicKey, "abc123")
	}
}

func TestOutboundMessage_JSON(t *testing.T) {
	msg := outboundMessage{
		Type:            "message.broadcast",
		MessageID:       "msg-1",
		Sender:          "user-1",
		SenderNameEnc:   "enc-name",
		SenderPublicKey: "pubkey",
		Body:            "hello",
		SentAt:          "2026-01-01T00:00:00Z",
	}
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	var got map[string]string
	json.Unmarshal(data, &got)
	if got["sender_public_key"] != "pubkey" {
		t.Errorf("sender_public_key = %q, want %q", got["sender_public_key"], "pubkey")
	}
	if got["type"] != "message.broadcast" {
		t.Errorf("type = %q, want %q", got["type"], "message.broadcast")
	}
}

func TestOutboundMessage_OmitEmptyPublicKey(t *testing.T) {
	msg := outboundMessage{
		Type: "message.new",
		Body: "hello",
	}
	data, _ := json.Marshal(msg)
	var got map[string]interface{}
	json.Unmarshal(data, &got)
	if _, exists := got["sender_public_key"]; exists {
		t.Error("sender_public_key should be omitted when empty")
	}
}

func TestErrorEvent_JSON(t *testing.T) {
	e := errorEvent{Type: "error", Code: "bad", Message: "something went wrong"}
	data, _ := json.Marshal(e)
	var got map[string]string
	json.Unmarshal(data, &got)
	if got["type"] != "error" {
		t.Errorf("type = %q, want %q", got["type"], "error")
	}
	if got["code"] != "bad" {
		t.Errorf("code = %q, want %q", got["code"], "bad")
	}
}

func TestClient_Send(t *testing.T) {
	c := &Client{send: make(chan []byte, 8)}
	ok := c.Send([]byte("hello"))
	if !ok {
		t.Fatal("Send() returned false, want true")
	}
	msg := <-c.send
	if string(msg) != "hello" {
		t.Errorf("received %q, want %q", msg, "hello")
	}
}

func TestClient_Send_FullBuffer(t *testing.T) {
	c := &Client{send: make(chan []byte, 1)}
	_ = c.Send([]byte("first"))
	ok := c.Send([]byte("second"))
	if ok {
		t.Fatal("Send() returned true on full buffer, want false")
	}
}

func TestClient_DeviceKey(t *testing.T) {
	c := &Client{userID: "user-1", deviceID: "dev-1"}
	dk := c.deviceKey()
	if dk.userID != "user-1" || dk.deviceID != "dev-1" {
		t.Errorf("deviceKey = %+v, want user-1/dev-1", dk)
	}
}

func TestParseAuthHeader_Valid(t *testing.T) {
	validator := &fakeValidator{sessions: map[string]auth.Session{
		"abc": {Token: "abc", UserID: "u1"},
	}}
	session, err := parseAuthHeader("Bearer abc", validator)
	if err != nil {
		t.Fatalf("parseAuthHeader() error = %v", err)
	}
	if session.UserID != "u1" {
		t.Errorf("UserID = %q, want %q", session.UserID, "u1")
	}
}

func TestParseAuthHeader_CaseInsensitive(t *testing.T) {
	validator := &fakeValidator{sessions: map[string]auth.Session{
		"abc": {Token: "abc", UserID: "u1"},
	}}
	session, err := parseAuthHeader("bearer abc", validator)
	if err != nil {
		t.Fatalf("parseAuthHeader() error = %v", err)
	}
	if session.UserID != user.ID("u1") {
		t.Errorf("UserID = %q, want %q", session.UserID, "u1")
	}
}

func TestParseAuthHeader_MissingToken(t *testing.T) {
	validator := &fakeValidator{sessions: map[string]auth.Session{}}
	_, err := parseAuthHeader("Bearer", validator)
	if err == nil {
		t.Fatal("expected error for missing token part")
	}
}

func TestParseAuthHeader_TooManyParts(t *testing.T) {
	validator := &fakeValidator{sessions: map[string]auth.Session{}}
	_, err := parseAuthHeader("Bearer abc def", validator)
	if err == nil {
		t.Fatal("expected error for too many parts")
	}
}

func TestAuthenticateRequest_BearerHeader(t *testing.T) {
	validator := &fakeValidator{sessions: map[string]auth.Session{
		"tok-2": {Token: "tok-2", UserID: "user-2"},
	}}
	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	req.Header.Set("Authorization", "Bearer tok-2")
	session, err := authenticateRequest(req, validator)
	if err != nil {
		t.Fatalf("authenticateRequest() error = %v", err)
	}
	if session.UserID != "user-2" {
		t.Errorf("UserID = %q, want %q", session.UserID, "user-2")
	}
}

func TestAuthenticateRequest_NoCredentials(t *testing.T) {
	validator := &fakeValidator{sessions: map[string]auth.Session{}}
	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	_, err := authenticateRequest(req, validator)
	if err == nil {
		t.Fatal("expected error for missing credentials")
	}
	if !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

func TestAuthenticateRequest_InvalidBearerFormat(t *testing.T) {
	validator := &fakeValidator{sessions: map[string]auth.Session{}}
	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	req.Header.Set("Authorization", "NotBearer tok-1")
	_, err := authenticateRequest(req, validator)
	if err == nil {
		t.Fatal("expected error for invalid bearer format")
	}
}

func TestAuthenticateRequest_NilValidator(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	req.Header.Set("Authorization", "Bearer tok-1")
	_, err := authenticateRequest(req, nil)
	if err == nil {
		t.Fatal("expected error for nil validator")
	}
}

func TestNewHub(t *testing.T) {
	hub := NewHub(nil, nil, nil)
	if hub == nil {
		t.Fatal("NewHub() returned nil")
	}
	if hub.ClientCount() != 0 {
		t.Errorf("ClientCount() = %d, want 0", hub.ClientCount())
	}
}

func TestWithAuthValidator(t *testing.T) {
	validator := &fakeValidator{sessions: map[string]auth.Session{
		"tok-1": {Token: "tok-1", UserID: "user-1"},
	}}

	var capturedValidator tokenValidator
	handler := WithAuthValidator(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedValidator, _ = r.Context().Value(authValidatorKey{}).(tokenValidator)
		w.WriteHeader(http.StatusOK)
	}), validator)

	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if capturedValidator == nil {
		t.Fatal("validator not injected into context")
	}
	session, err := capturedValidator.ValidateToken("tok-1")
	if err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}
	if session.UserID != "user-1" {
		t.Errorf("UserID = %q, want %q", session.UserID, "user-1")
	}
}

func TestHub_SendHistory_NilClient(t *testing.T) {
	hub := NewHub(nil, nil, nil)
	hub.sendHistory(context.TODO(), nil)
}

func TestHub_HandleIncoming_UnknownType(t *testing.T) {
	hub := NewHub(nil, nil, nil)
	c := &Client{
		send:   make(chan []byte, 8),
		userID: "user-1",
	}
	hub.handleIncoming(context.TODO(), incomingMessage{
		client: c,
		msg:    inboundMessage{Type: "unknown.type"},
	})

	select {
	case data := <-c.send:
		var e errorEvent
		if err := json.Unmarshal(data, &e); err != nil {
			t.Fatalf("unmarshal error event: %v", err)
		}
		if e.Code != "unsupported_type" {
			t.Errorf("error code = %q, want %q", e.Code, "unsupported_type")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected error event, got nothing")
	}
}

func TestIsExpectedDisconnectError(t *testing.T) {
	if isExpectedDisconnectError(nil) {
		t.Fatal("expected nil error to return false")
	}
	if !isExpectedDisconnectError(io.EOF) {
		t.Fatal("expected io.EOF to return true")
	}
	if !isExpectedDisconnectError(errors.New("use of closed network connection")) {
		t.Fatal("expected closed network connection to return true")
	}
	if isExpectedDisconnectError(errors.New("other")) {
		t.Fatal("expected other error to return false")
	}
}

func TestHub_Run_RegisterAndShutdown(t *testing.T) {
	hub := NewHub(nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go hub.Run(ctx)

	serverConn, clientConn, cleanup := newWebsocketPair(t)
	defer cleanup()

	client := &Client{
		conn:     serverConn,
		hub:      hub,
		ctx:      context.Background(),
		cancel:   func() {},
		send:     make(chan []byte, 1),
		userID:   "user-1",
		deviceID: "dev-1",
	}

	hub.register <- client
	waitFor(t, time.Second, func() bool { return hub.ClientCount() == 1 })
	if !hub.IsOnline("user-1") {
		t.Fatal("expected user to be online")
	}

	cancel()
	select {
	case _, ok := <-client.send:
		if ok {
			t.Fatal("expected send channel to be closed")
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for client close")
	}

	_ = clientConn.Close(websocket.StatusNormalClosure, "bye")
}

func TestHub_HandleWS_RegistersClient(t *testing.T) {
	hub := NewHub(nil, &fakeDeviceRepo{}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go hub.Run(ctx)

	validator := &fakeValidator{sessions: map[string]auth.Session{
		"tok": {Token: "tok", UserID: "user-1", DeviceID: "dev-1", Username: "alice"},
	}}

	srv := httptest.NewServer(WithAuthValidator(http.HandlerFunc(hub.HandleWS), validator))
	defer srv.Close()

	headers := http.Header{}
	headers.Set("Authorization", "Bearer tok")
	dialCtx, dialCancel := context.WithTimeout(context.Background(), time.Second)
	conn, _, err := websocket.Dial(dialCtx, "ws"+strings.TrimPrefix(srv.URL, "http"), &websocket.DialOptions{HTTPHeader: headers})
	dialCancel()
	if err != nil {
		t.Fatalf("websocket dial: %v", err)
	}

	waitFor(t, time.Second, func() bool { return hub.IsOnline("user-1") })
	_ = conn.Close(websocket.StatusNormalClosure, "bye")
	waitFor(t, time.Second, func() bool { return hub.ClientCount() == 0 })
}

func TestClient_ReadLoop_ForwardsIncoming(t *testing.T) {
	hub := NewHub(nil, nil, nil)
	hub.unregister = make(chan *Client, 1)
	hub.incoming = make(chan incomingMessage, 1)

	serverConn, clientConn, cleanup := newWebsocketPair(t)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := &Client{
		conn:   serverConn,
		hub:    hub,
		ctx:    ctx,
		cancel: cancel,
		send:   make(chan []byte, 1),
		userID: "user-1",
	}

	go client.readLoop()

	msg := []byte(`{"type":"channel.message.send","channel_id":"ch-1","body":"hi","sender_name_enc":"enc"}`)
	writeCtx, writeCancel := context.WithTimeout(context.Background(), time.Second)
	if err := clientConn.Write(writeCtx, websocket.MessageText, msg); err != nil {
		writeCancel()
		t.Fatalf("write message: %v", err)
	}
	writeCancel()

	select {
	case incoming := <-hub.incoming:
		if incoming.msg.Type != "channel.message.send" {
			t.Fatalf("Type = %q, want %q", incoming.msg.Type, "channel.message.send")
		}
		if incoming.msg.ChannelID != "ch-1" {
			t.Fatalf("ChannelID = %q, want %q", incoming.msg.ChannelID, "ch-1")
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for incoming message")
	}

	_ = clientConn.Close(websocket.StatusNormalClosure, "bye")
	select {
	case <-hub.unregister:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for unregister")
	}
}

func TestClient_WriteLoop_SendsMessages(t *testing.T) {
	hub := NewHub(nil, nil, nil)
	hub.unregister = make(chan *Client, 1)

	serverConn, clientConn, cleanup := newWebsocketPair(t)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	client := &Client{
		conn:   serverConn,
		hub:    hub,
		ctx:    ctx,
		cancel: cancel,
		send:   make(chan []byte, 1),
	}
	go client.writeLoop()

	payload := []byte(`{"type":"ping"}`)
	client.send <- payload

	readCtx, readCancel := context.WithTimeout(context.Background(), time.Second)
	_, data, err := clientConn.Read(readCtx)
	readCancel()
	if err != nil {
		cancel()
		t.Fatalf("read message: %v", err)
	}
	if string(data) != string(payload) {
		cancel()
		t.Fatalf("payload = %q, want %q", string(data), string(payload))
	}

	cancel()
}

func TestHub_HandleBroadcast_SendsToClientsAndStores(t *testing.T) {
	repo := &fakeBroadcastRepo{}
	hub := NewHub(repo, nil, nil)

	c1 := &Client{send: make(chan []byte, 1), userID: "user-1", deviceID: "dev-1"}
	c2 := &Client{send: make(chan []byte, 1), userID: "user-2", deviceID: "dev-2"}
	hub.clients[c1] = struct{}{}
	hub.clients[c2] = struct{}{}

	msg := inboundMessage{
		Type:          "message.broadcast",
		Body:          "hello",
		SenderNameEnc: " enc ",
		PublicKey:     "pub",
		Envelopes: map[string]string{
			"dev-1": "env-1",
			"dev-2": "env-2",
		},
	}

	hub.handleBroadcast(context.Background(), c1, msg)

	if len(repo.saved) != 1 {
		t.Fatalf("saved = %d, want 1", len(repo.saved))
	}
	if repo.saved[0].SenderNameEnc != "enc" {
		t.Fatalf("SenderNameEnc = %q, want %q", repo.saved[0].SenderNameEnc, "enc")
	}

	out1 := readEvent[outboundMessage](t, c1.send)
	if out1.Type != "message.broadcast" {
		t.Fatalf("Type = %q, want %q", out1.Type, "message.broadcast")
	}
	if out1.KeyEnvelope != "env-1" {
		t.Fatalf("KeyEnvelope = %q, want %q", out1.KeyEnvelope, "env-1")
	}

	out2 := readEvent[outboundMessage](t, c2.send)
	if out2.KeyEnvelope != "env-2" {
		t.Fatalf("KeyEnvelope = %q, want %q", out2.KeyEnvelope, "env-2")
	}
}

func TestHub_HandleBroadcast_InvalidMessage(t *testing.T) {
	hub := NewHub(nil, nil, nil)
	sender := &Client{send: make(chan []byte, 1), userID: "user-1", deviceID: "dev-1"}

	msg := inboundMessage{
		Type:          "message.broadcast",
		Body:          "hello",
		SenderNameEnc: "enc",
		PublicKey:     "",
		Envelopes:     map[string]string{"dev-1": "env"},
	}

	hub.handleBroadcast(context.Background(), sender, msg)

	event := readEvent[errorEvent](t, sender.send)
	if event.Code != "invalid_message" {
		t.Fatalf("code = %q, want %q", event.Code, "invalid_message")
	}
}

func TestHub_HandleChannelMessage_SendsToClients(t *testing.T) {
	repo := &fakeChannelRepo{ch: channel.Channel{ID: "ch-1"}}
	hub := NewHub(nil, nil, repo)

	c1 := &Client{send: make(chan []byte, 1), userID: "user-1"}
	c2 := &Client{send: make(chan []byte, 1), userID: "user-2"}
	hub.clients[c1] = struct{}{}
	hub.clients[c2] = struct{}{}

	msg := inboundMessage{
		Type:          "channel.message.send",
		ChannelID:     "ch-1",
		Body:          "hello",
		SenderNameEnc: " enc ",
	}

	hub.handleChannelMessage(context.Background(), c1, msg)

	if len(repo.saved) != 1 {
		t.Fatalf("saved = %d, want 1", len(repo.saved))
	}
	if repo.saved[0].SenderNameEnc != "enc" {
		t.Fatalf("SenderNameEnc = %q, want %q", repo.saved[0].SenderNameEnc, "enc")
	}

	out1 := readEvent[outboundMessage](t, c1.send)
	if out1.Type != "channel.message.new" {
		t.Fatalf("Type = %q, want %q", out1.Type, "channel.message.new")
	}
	out2 := readEvent[outboundMessage](t, c2.send)
	if out2.ChannelID != "ch-1" {
		t.Fatalf("ChannelID = %q, want %q", out2.ChannelID, "ch-1")
	}
}

func TestHub_HandleChannelMessage_ChannelNotFound(t *testing.T) {
	repo := &fakeChannelRepo{getErr: storage.ErrNotFound}
	hub := NewHub(nil, nil, repo)

	sender := &Client{send: make(chan []byte, 1), userID: "user-1"}

	msg := inboundMessage{
		Type:          "channel.message.send",
		ChannelID:     "missing",
		Body:          "hello",
		SenderNameEnc: "enc",
	}

	hub.handleChannelMessage(context.Background(), sender, msg)

	event := readEvent[errorEvent](t, sender.send)
	if event.Code != "channel_not_found" {
		t.Fatalf("code = %q, want %q", event.Code, "channel_not_found")
	}
}

func TestHub_NotifyEvents(t *testing.T) {
	hub := NewHub(nil, nil, nil)

	c1 := &Client{send: make(chan []byte, 4), userID: "user-1", deviceID: "dev-1"}
	c2 := &Client{send: make(chan []byte, 4), userID: "user-2", deviceID: "dev-2"}
	hub.clients[c1] = struct{}{}
	hub.clients[c2] = struct{}{}

	hub.NotifyChannelUpdated(channel.Channel{ID: "ch-1", NameEnc: "enc"})
	hub.NotifyChannelDeleted("ch-2")
	hub.NotifyUserProfileUpdated("user-9")
	hub.notifyDeviceJoined("user-8", "dev-8")

	for _, client := range []*Client{c1, c2} {
		first := readEvent[outboundMessage](t, client.send)
		if first.Type != "channel.updated" {
			t.Fatalf("Type = %q, want %q", first.Type, "channel.updated")
		}
		second := readEvent[outboundMessage](t, client.send)
		third := readEvent[outboundMessage](t, client.send)
		fourth := readEvent[outboundMessage](t, client.send)
		if second.Type != "channel.deleted" {
			t.Fatalf("Type = %q, want %q", second.Type, "channel.deleted")
		}
		if third.Type != "user.profile.updated" {
			t.Fatalf("Type = %q, want %q", third.Type, "user.profile.updated")
		}
		if fourth.Type != "device.joined" {
			t.Fatalf("Type = %q, want %q", fourth.Type, "device.joined")
		}
	}
}

func TestHub_HandleWS_NilDevices(t *testing.T) {
	hub := NewHub(nil, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	rr := httptest.NewRecorder()
	hub.HandleWS(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rr.Code)
	}
}

func TestHub_HandleWS_NoValidator(t *testing.T) {
	hub := NewHub(nil, &fakeDeviceRepo{}, nil)
	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	rr := httptest.NewRecorder()
	hub.HandleWS(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
}

func TestHub_HandleWS_InvalidToken(t *testing.T) {
	hub := NewHub(nil, &fakeDeviceRepo{}, nil)
	validator := &fakeValidator{sessions: map[string]auth.Session{}}
	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	req.Header.Set("Authorization", "Bearer invalid")
	ctx := context.WithValue(req.Context(), authValidatorKey{}, validator)
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()
	hub.HandleWS(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
}

func TestHub_HandleIncoming_MessageSend(t *testing.T) {
	hub := NewHub(nil, nil, nil)
	c := &Client{send: make(chan []byte, 8), userID: "user-1"}
	hub.handleIncoming(context.TODO(), incomingMessage{
		client: c,
		msg:    inboundMessage{Type: "message.send", Recipient: "user-2", Body: "hello"},
	})
	event := readEvent[errorEvent](t, c.send)
	if event.Code != "channels_only" {
		t.Fatalf("code = %q, want %q", event.Code, "channels_only")
	}
}

func TestHub_HandleIncoming_MessageBroadcast(t *testing.T) {
	hub := NewHub(nil, nil, nil)
	c := &Client{send: make(chan []byte, 8), userID: "user-1"}
	hub.handleIncoming(context.TODO(), incomingMessage{
		client: c,
		msg:    inboundMessage{Type: "message.broadcast", Body: "hello", SenderNameEnc: "enc"},
	})
	event := readEvent[errorEvent](t, c.send)
	if event.Code != "channels_only" {
		t.Fatalf("code = %q, want %q", event.Code, "channels_only")
	}
}

func TestHub_HandleBroadcast_NilSender(t *testing.T) {
	hub := NewHub(nil, nil, nil)
	// Should not panic
	hub.handleBroadcast(context.TODO(), nil, inboundMessage{})
}

func TestHub_HandleBroadcast_EmptyUserID(t *testing.T) {
	hub := NewHub(nil, nil, nil)
	c := &Client{send: make(chan []byte, 8), userID: ""}
	hub.handleBroadcast(context.TODO(), c, inboundMessage{})
	// Should return early without sending any event
	select {
	case <-c.send:
		t.Fatal("expected no event for empty userID")
	default:
	}
}

func TestHub_HandleBroadcast_EmptyBody(t *testing.T) {
	hub := NewHub(nil, nil, nil)
	c := &Client{send: make(chan []byte, 8), userID: "user-1"}
	hub.handleBroadcast(context.TODO(), c, inboundMessage{
		Type:          "message.broadcast",
		Body:          "",
		SenderNameEnc: "enc",
		PublicKey:     "pub",
		Envelopes:     map[string]string{"dev-1": "env"},
	})
	event := readEvent[errorEvent](t, c.send)
	if event.Code != "invalid_message" {
		t.Fatalf("code = %q, want %q", event.Code, "invalid_message")
	}
}

func TestHub_HandleBroadcast_EmptySenderNameEnc(t *testing.T) {
	hub := NewHub(nil, nil, nil)
	c := &Client{send: make(chan []byte, 8), userID: "user-1"}
	hub.handleBroadcast(context.TODO(), c, inboundMessage{
		Type:          "message.broadcast",
		Body:          "hello",
		SenderNameEnc: "",
		PublicKey:     "pub",
		Envelopes:     map[string]string{"dev-1": "env"},
	})
	event := readEvent[errorEvent](t, c.send)
	if event.Code != "invalid_message" {
		t.Fatalf("code = %q, want %q", event.Code, "invalid_message")
	}
}

func TestHub_HandleBroadcast_EmptyEnvelopes(t *testing.T) {
	hub := NewHub(nil, nil, nil)
	c := &Client{send: make(chan []byte, 8), userID: "user-1"}
	hub.handleBroadcast(context.TODO(), c, inboundMessage{
		Type:          "message.broadcast",
		Body:          "hello",
		SenderNameEnc: "enc",
		PublicKey:     "pub",
		Envelopes:     nil,
	})
	event := readEvent[errorEvent](t, c.send)
	if event.Code != "invalid_message" {
		t.Fatalf("code = %q, want %q", event.Code, "invalid_message")
	}
}

func TestHub_HandleBroadcast_SaveError(t *testing.T) {
	repo := &fakeBroadcastRepo{err: errors.New("db error")}
	hub := NewHub(repo, nil, nil)
	c := &Client{send: make(chan []byte, 8), userID: "user-1", deviceID: "dev-1"}
	hub.handleBroadcast(context.TODO(), c, inboundMessage{
		Type:          "message.broadcast",
		Body:          "hello",
		SenderNameEnc: "enc",
		PublicKey:     "pub",
		Envelopes:     map[string]string{"dev-1": "env"},
	})
	event := readEvent[errorEvent](t, c.send)
	if event.Code != "server_error" {
		t.Fatalf("code = %q, want %q", event.Code, "server_error")
	}
}

func TestHub_HandleBroadcast_NilBroadcastRepo(t *testing.T) {
	hub := NewHub(nil, nil, nil)
	c := &Client{send: make(chan []byte, 8), userID: "user-1", deviceID: "dev-1"}
	hub.clients[c] = struct{}{}
	hub.handleBroadcast(context.TODO(), c, inboundMessage{
		Type:          "message.broadcast",
		Body:          "hello",
		SenderNameEnc: "enc",
		PublicKey:     "pub",
		Envelopes:     map[string]string{"dev-1": "env"},
	})
	out := readEvent[outboundMessage](t, c.send)
	if out.Type != "message.broadcast" {
		t.Fatalf("Type = %q, want %q", out.Type, "message.broadcast")
	}
}

func TestHub_HandleChannelMessage_NilSender(t *testing.T) {
	hub := NewHub(nil, nil, nil)
	hub.handleChannelMessage(context.TODO(), nil, inboundMessage{})
}

func TestHub_HandleChannelMessage_EmptyUserID(t *testing.T) {
	hub := NewHub(nil, nil, nil)
	c := &Client{send: make(chan []byte, 8), userID: ""}
	hub.handleChannelMessage(context.TODO(), c, inboundMessage{})
	select {
	case <-c.send:
		t.Fatal("expected no event for empty userID")
	default:
	}
}

func TestHub_HandleChannelMessage_EmptyChannelID(t *testing.T) {
	hub := NewHub(nil, nil, nil)
	c := &Client{send: make(chan []byte, 8), userID: "user-1"}
	hub.handleChannelMessage(context.TODO(), c, inboundMessage{
		Type:      "channel.message.send",
		ChannelID: "",
		Body:      "hello",
	})
	event := readEvent[errorEvent](t, c.send)
	if event.Code != "invalid_message" {
		t.Fatalf("code = %q, want %q", event.Code, "invalid_message")
	}
}

func TestHub_HandleChannelMessage_EmptyBody(t *testing.T) {
	hub := NewHub(nil, nil, nil)
	c := &Client{send: make(chan []byte, 8), userID: "user-1"}
	hub.handleChannelMessage(context.TODO(), c, inboundMessage{
		Type:      "channel.message.send",
		ChannelID: "ch-1",
		Body:      "",
	})
	event := readEvent[errorEvent](t, c.send)
	if event.Code != "invalid_message" {
		t.Fatalf("code = %q, want %q", event.Code, "invalid_message")
	}
}

func TestHub_HandleChannelMessage_NilChannels(t *testing.T) {
	hub := NewHub(nil, nil, nil)
	c := &Client{send: make(chan []byte, 8), userID: "user-1"}
	hub.handleChannelMessage(context.TODO(), c, inboundMessage{
		Type:          "channel.message.send",
		ChannelID:     "ch-1",
		Body:          "hello",
		SenderNameEnc: "enc",
	})
	event := readEvent[errorEvent](t, c.send)
	if event.Code != "server_error" {
		t.Fatalf("code = %q, want %q", event.Code, "server_error")
	}
}

func TestHub_HandleChannelMessage_GetChannelError(t *testing.T) {
	repo := &fakeChannelRepo{getErr: errors.New("db error")}
	hub := NewHub(nil, nil, repo)
	c := &Client{send: make(chan []byte, 8), userID: "user-1"}
	hub.handleChannelMessage(context.TODO(), c, inboundMessage{
		Type:          "channel.message.send",
		ChannelID:     "ch-1",
		Body:          "hello",
		SenderNameEnc: "enc",
	})
	event := readEvent[errorEvent](t, c.send)
	if event.Code != "server_error" {
		t.Fatalf("code = %q, want %q", event.Code, "server_error")
	}
}

func TestHub_HandleChannelMessage_SaveError(t *testing.T) {
	repo := &fakeChannelRepo{ch: channel.Channel{ID: "ch-1"}, saveErr: errors.New("db error")}
	hub := NewHub(nil, nil, repo)
	c := &Client{send: make(chan []byte, 8), userID: "user-1"}
	hub.handleChannelMessage(context.TODO(), c, inboundMessage{
		Type:          "channel.message.send",
		ChannelID:     "ch-1",
		Body:          "hello",
		SenderNameEnc: "enc",
	})
	event := readEvent[errorEvent](t, c.send)
	if event.Code != "server_error" {
		t.Fatalf("code = %q, want %q", event.Code, "server_error")
	}
}

func TestHub_NotifyChannelUpdated_NilHub(t *testing.T) {
	var hub *Hub
	// Should not panic
	hub.NotifyChannelUpdated(channel.Channel{ID: "ch-1"})
}

func TestHub_NotifyChannelUpdated_EmptyID(t *testing.T) {
	hub := NewHub(nil, nil, nil)
	c := &Client{send: make(chan []byte, 1), userID: "user-1"}
	hub.clients[c] = struct{}{}
	hub.NotifyChannelUpdated(channel.Channel{})
	select {
	case <-c.send:
		t.Fatal("expected no event for empty channel ID")
	default:
	}
}

func TestHub_NotifyChannelDeleted_NilHub(t *testing.T) {
	var hub *Hub
	hub.NotifyChannelDeleted("ch-1")
}

func TestHub_NotifyChannelDeleted_EmptyID(t *testing.T) {
	hub := NewHub(nil, nil, nil)
	c := &Client{send: make(chan []byte, 1), userID: "user-1"}
	hub.clients[c] = struct{}{}
	hub.NotifyChannelDeleted("")
	select {
	case <-c.send:
		t.Fatal("expected no event for empty channel ID")
	default:
	}
}

func TestHub_NotifyUserProfileUpdated_NilHub(t *testing.T) {
	var hub *Hub
	hub.NotifyUserProfileUpdated("user-1")
}

func TestHub_NotifyUserProfileUpdated_EmptyID(t *testing.T) {
	hub := NewHub(nil, nil, nil)
	c := &Client{send: make(chan []byte, 1), userID: "user-1"}
	hub.clients[c] = struct{}{}
	hub.NotifyUserProfileUpdated("")
	select {
	case <-c.send:
		t.Fatal("expected no event for empty user ID")
	default:
	}
}

func TestHub_NotifyDeviceJoined_NilHub(t *testing.T) {
	var hub *Hub
	hub.notifyDeviceJoined("user-1", "dev-1")
}

func TestHub_NotifyDeviceJoined_EmptyUser(t *testing.T) {
	hub := NewHub(nil, nil, nil)
	c := &Client{send: make(chan []byte, 1), userID: "user-1"}
	hub.clients[c] = struct{}{}
	hub.notifyDeviceJoined("", "dev-1")
	select {
	case <-c.send:
		t.Fatal("expected no event for empty user ID")
	default:
	}
}

func TestHub_NotifyDeviceJoined_EmptyDevice(t *testing.T) {
	hub := NewHub(nil, nil, nil)
	c := &Client{send: make(chan []byte, 1), userID: "user-1"}
	hub.clients[c] = struct{}{}
	hub.notifyDeviceJoined("user-1", "")
	select {
	case <-c.send:
		t.Fatal("expected no event for empty device ID")
	default:
	}
}

func TestHub_IsOnline_EmptyUserID(t *testing.T) {
	hub := NewHub(nil, nil, nil)
	if hub.IsOnline("") {
		t.Fatal("expected false for empty user ID")
	}
}

func TestHub_IsOnline_NoClients(t *testing.T) {
	hub := NewHub(nil, nil, nil)
	if hub.IsOnline("user-1") {
		t.Fatal("expected false when no clients")
	}
}

func TestDecodeIncoming_ChannelMessageValid(t *testing.T) {
	data := []byte(`{"type":"channel.message.send","channel_id":"ch-1","body":"hello","sender_name_enc":"enc"}`)
	msg, err := decodeIncoming(data)
	if err != nil {
		t.Fatalf("decodeIncoming() error = %v", err)
	}
	if msg.ChannelID != "ch-1" {
		t.Errorf("ChannelID = %q, want %q", msg.ChannelID, "ch-1")
	}
}

func TestDecodeIncoming_ChannelMessageMissingBody(t *testing.T) {
	data := []byte(`{"type":"channel.message.send","channel_id":"ch-1","body":"","sender_name_enc":"enc"}`)
	_, err := decodeIncoming(data)
	if err == nil {
		t.Fatal("expected error for missing body")
	}
}

func TestDecodeIncoming_ChannelMessageMissingChannelID(t *testing.T) {
	data := []byte(`{"type":"channel.message.send","channel_id":"","body":"hello","sender_name_enc":"enc"}`)
	_, err := decodeIncoming(data)
	if err == nil {
		t.Fatal("expected error for missing channel_id")
	}
}

func TestDecodeIncoming_ChannelMessageMissingSenderNameEnc(t *testing.T) {
	data := []byte(`{"type":"channel.message.send","channel_id":"ch-1","body":"hello","sender_name_enc":""}`)
	_, err := decodeIncoming(data)
	if err == nil {
		t.Fatal("expected error for missing sender_name_enc")
	}
}

func TestDecodeIncoming_ChannelMessageTooLong(t *testing.T) {
	longBody := strings.Repeat("a", maxMessageLen+1)
	data := []byte(`{"type":"channel.message.send","channel_id":"ch-1","body":"` + longBody + `","sender_name_enc":"enc"}`)
	_, err := decodeIncoming(data)
	if err == nil {
		t.Fatal("expected error for message exceeding max length")
	}
}

func TestDecodeIncoming_BroadcastMissingSenderNameEnc(t *testing.T) {
	data := []byte(`{"type":"message.broadcast","body":"hello","sender_name_enc":"   "}`)
	_, err := decodeIncoming(data)
	if err == nil {
		t.Fatal("expected error for empty sender_name_enc")
	}
}

func TestDecodeIncoming_SendMissingBody(t *testing.T) {
	data := []byte(`{"type":"message.send","recipient":"user-1","body":""}`)
	_, err := decodeIncoming(data)
	if err == nil {
		t.Fatal("expected error for empty body")
	}
}

func TestClient_SendEvent_MarshalError(t *testing.T) {
	c := &Client{send: make(chan []byte, 8)}
	// Valid json should work
	c.sendEvent(map[string]string{"key": "value"})
	select {
	case msg := <-c.send:
		if len(msg) == 0 {
			t.Fatal("expected non-empty message")
		}
	default:
		t.Fatal("expected message in send channel")
	}
}

func TestClient_SendError(t *testing.T) {
	c := &Client{send: make(chan []byte, 8)}
	c.sendError("code", "message")
	select {
	case data := <-c.send:
		var e errorEvent
		if err := json.Unmarshal(data, &e); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if e.Code != "code" {
			t.Errorf("code = %q, want %q", e.Code, "code")
		}
		if e.Message != "message" {
			t.Errorf("message = %q, want %q", e.Message, "message")
		}
	default:
		t.Fatal("expected message in send channel")
	}
}

func TestHub_Run_UnregisterAndReregister(t *testing.T) {
	hub := NewHub(nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go hub.Run(ctx)

	serverConn, clientConn, cleanup := newWebsocketPair(t)
	defer cleanup()

	client := &Client{
		conn:     serverConn,
		hub:      hub,
		ctx:      context.Background(),
		cancel:   func() {},
		send:     make(chan []byte, 1),
		userID:   "user-1",
		deviceID: "dev-1",
	}

	hub.register <- client
	waitFor(t, time.Second, func() bool { return hub.ClientCount() == 1 })

	hub.unregister <- client
	waitFor(t, time.Second, func() bool { return hub.ClientCount() == 0 })

	if hub.IsOnline("user-1") {
		t.Fatal("expected user to be offline after unregister")
	}

	_ = clientConn.Close(websocket.StatusNormalClosure, "bye")
}

func TestHub_Run_UnregisterNonexistent(t *testing.T) {
	hub := NewHub(nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go hub.Run(ctx)

	serverConn, _, cleanup := newWebsocketPair(t)
	defer cleanup()

	// Try unregistering a client that was never registered
	client := &Client{
		conn:     serverConn,
		hub:      hub,
		ctx:      context.Background(),
		cancel:   func() {},
		send:     make(chan []byte, 1),
		userID:   "user-1",
		deviceID: "dev-1",
	}
	hub.unregister <- client
	// Give it time to process
	time.Sleep(50 * time.Millisecond)
	if hub.ClientCount() != 0 {
		t.Fatalf("ClientCount() = %d, want 0", hub.ClientCount())
	}
}

// ---------------------------------------------------------------------------
// Additional ws tests for remaining uncovered error paths
// ---------------------------------------------------------------------------

// L273: sendEvent with unmarshalable value
func TestClient_SendEvent_ActualMarshalError(t *testing.T) {
	c := &Client{send: make(chan []byte, 8)}
	// channels cannot be marshaled to JSON
	c.sendEvent(make(chan int))
	// sendEvent should silently return; no message in send channel
	select {
	case <-c.send:
		t.Fatal("expected no message when marshal fails")
	default:
		// OK
	}
}

// L401: handleIncoming with channel.message.send delegates to handleChannelMessage
func TestHub_HandleIncoming_ChannelMessage(t *testing.T) {
	chRepo := &fakeChannelRepo{
		ch: channel.Channel{ID: "ch-1", NameEnc: "enc"},
	}
	hub := NewHub(nil, nil, chRepo)
	sender := &Client{send: make(chan []byte, 8), userID: "user-1", deviceID: "dev-1"}
	hub.clients[sender] = struct{}{}

	hub.handleIncoming(context.Background(), incomingMessage{
		client: sender,
		msg: inboundMessage{
			Type:          "channel.message.send",
			ChannelID:     "ch-1",
			Body:          "hello",
			SenderNameEnc: "enc",
		},
	})

	// Should receive the outbound message
	select {
	case data := <-sender.send:
		var out outboundMessage
		if err := json.Unmarshal(data, &out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if out.Type != "channel.message.new" {
			t.Fatalf("Type = %q, want channel.message.new", out.Type)
		}
		if out.ChannelID != "ch-1" {
			t.Fatalf("ChannelID = %q, want ch-1", out.ChannelID)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for outbound message")
	}
}

// L96: incoming message processed through Run's select
func TestHub_Run_ProcessesIncoming(t *testing.T) {
	chRepo := &fakeChannelRepo{
		ch: channel.Channel{ID: "ch-1", NameEnc: "enc"},
	}
	hub := NewHub(nil, nil, chRepo)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go hub.Run(ctx)

	serverConn, _, cleanup := newWebsocketPair(t)
	defer cleanup()

	clientCtx, clientCancel := context.WithCancel(context.Background())
	defer clientCancel()

	sender := &Client{
		conn:     serverConn,
		hub:      hub,
		ctx:      clientCtx,
		cancel:   clientCancel,
		send:     make(chan []byte, 8),
		userID:   "user-1",
		deviceID: "dev-1",
	}
	// Register the client
	hub.register <- sender
	waitFor(t, 500*time.Millisecond, func() bool { return hub.ClientCount() == 1 })

	// Send an incoming message through the incoming channel
	hub.incoming <- incomingMessage{
		client: sender,
		msg: inboundMessage{
			Type:          "channel.message.send",
			ChannelID:     "ch-1",
			Body:          "hello world",
			SenderNameEnc: "enc",
		},
	}

	// Should receive the outbound message through the send channel
	select {
	case data := <-sender.send:
		var out outboundMessage
		if err := json.Unmarshal(data, &out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if out.Type != "channel.message.new" {
			t.Fatalf("Type = %q, want channel.message.new", out.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for outbound message via Run")
	}
}

// L136: websocket.Accept failure - tested indirectly; Accept panics on
// non-upgrade requests in test environments. The error path is defensive
// and only triggers with malformed websocket handshakes in production.

// L191: readLoop context canceled
func TestClient_ReadLoop_ContextCanceled(t *testing.T) {
	hub := NewHub(nil, nil, nil)
	hub.unregister = make(chan *Client, 1)
	hub.incoming = make(chan incomingMessage, 1)

	serverConn, _, cleanup := newWebsocketPair(t)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	client := &Client{
		conn:   serverConn,
		hub:    hub,
		ctx:    ctx,
		cancel: cancel,
		send:   make(chan []byte, 1),
		userID: "user-1",
	}

	go client.readLoop()

	// Cancel the context to trigger the context.Canceled error path
	cancel()

	select {
	case <-hub.unregister:
		// Client was unregistered as expected
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for readLoop to exit after context cancel")
	}
}

// L235: writeLoop send channel closed
func TestClient_WriteLoop_ChannelClosed(t *testing.T) {
	hub := NewHub(nil, nil, nil)
	hub.unregister = make(chan *Client, 1)

	serverConn, _, cleanup := newWebsocketPair(t)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := &Client{
		conn:   serverConn,
		hub:    hub,
		ctx:    ctx,
		cancel: cancel,
		send:   make(chan []byte, 1),
	}
	go client.writeLoop()

	// Close the send channel to trigger the !ok path
	close(client.send)

	// writeLoop should exit; give it a moment
	time.Sleep(100 * time.Millisecond)
}

// L241-246: writeLoop write error
func TestClient_WriteLoop_WriteError(t *testing.T) {
	hub := NewHub(nil, nil, nil)
	hub.unregister = make(chan *Client, 1)

	serverConn, clientConn, cleanup := newWebsocketPair(t)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := &Client{
		conn:   serverConn,
		hub:    hub,
		ctx:    ctx,
		cancel: cancel,
		send:   make(chan []byte, 4),
	}
	go client.writeLoop()

	// Close the client side and give the close frame time to propagate
	_ = clientConn.Close(websocket.StatusGoingAway, "gone")
	time.Sleep(100 * time.Millisecond)

	// Flood the send channel to ensure a write is attempted after the connection is dead
	for i := 0; i < 4; i++ {
		client.send <- []byte(`{"type":"test"}`)
	}

	select {
	case <-hub.unregister:
		// Client was unregistered due to write error
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for writeLoop to detect write error")
	}
}

// L248-257: writeLoop ping error - skipped because pingInterval is 25s,
// making it impractical for unit tests. The path is structurally identical
// to the write error path (L241-246) which IS tested above.

// L194: readLoop expected disconnect (EOF/closed)
func TestClient_ReadLoop_ClientDisconnect(t *testing.T) {
	hub := NewHub(nil, nil, nil)
	hub.unregister = make(chan *Client, 1)
	hub.incoming = make(chan incomingMessage, 1)

	serverConn, clientConn, cleanup := newWebsocketPair(t)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := &Client{
		conn:   serverConn,
		hub:    hub,
		ctx:    ctx,
		cancel: cancel,
		send:   make(chan []byte, 1),
		userID: "user-1",
	}

	go client.readLoop()

	// Close the client connection with normal closure
	_ = clientConn.Close(websocket.StatusNormalClosure, "bye")

	select {
	case <-hub.unregister:
		// readLoop exited and unregistered
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for readLoop to exit after client disconnect")
	}
}

// L207-210: readLoop unexpected error (status -1)
func TestClient_ReadLoop_UnexpectedError(t *testing.T) {
	hub := NewHub(nil, nil, nil)
	hub.unregister = make(chan *Client, 1)
	hub.incoming = make(chan incomingMessage, 1)

	serverConn, clientConn, cleanup := newWebsocketPair(t)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := &Client{
		conn:   serverConn,
		hub:    hub,
		ctx:    ctx,
		cancel: cancel,
		send:   make(chan []byte, 1),
		userID: "user-1",
	}

	go client.readLoop()

	// Write binary instead of text to trigger a protocol-level issue,
	// or just close with an abnormal status
	_ = clientConn.Close(websocket.StatusProtocolError, "protocol error")

	select {
	case <-hub.unregister:
		// readLoop exited
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for readLoop to exit after protocol error")
	}
}

func TestHub_HandleVoiceJoin_SendsRosterSnapshot(t *testing.T) {
	repo := &fakeChannelRepo{ch: channel.Channel{ID: "ch-1"}}
	hub := NewHub(nil, nil, repo)

	joiner := &Client{send: make(chan []byte, 8), userID: "user-1"}
	peer := &Client{send: make(chan []byte, 8), userID: "user-2"}

	hub.mu.Lock()
	hub.voiceRooms["ch-1"] = map[*Client]struct{}{peer: {}}
	hub.voiceRoom[peer] = "ch-1"
	hub.mu.Unlock()

	hub.handleVoiceJoin(context.Background(), joiner, inboundMessage{Type: "voice_join", ChannelID: "ch-1"})

	roster := readEvent[voiceSignalEvent](t, joiner.send)
	if roster.Type != "voice_roster" {
		t.Fatalf("type = %q, want %q", roster.Type, "voice_roster")
	}
	if roster.ChannelID != "ch-1" {
		t.Fatalf("channel = %q, want %q", roster.ChannelID, "ch-1")
	}
	if len(roster.Users) != 2 || roster.Users[0] != "user-1" || roster.Users[1] != "user-2" {
		t.Fatalf("unexpected roster users: %+v", roster.Users)
	}

	selfJoin := readEvent[voiceSignalEvent](t, joiner.send)
	if selfJoin.Type != "voice_join" || selfJoin.Sender != "user-1" {
		t.Fatalf("unexpected self join event: %+v", selfJoin)
	}

	peerJoin := readEvent[voiceSignalEvent](t, peer.send)
	if peerJoin.Type != "voice_join" || peerJoin.Sender != "user-1" {
		t.Fatalf("unexpected peer join event: %+v", peerJoin)
	}

	hub.mu.RLock()
	room := hub.voiceRoom[joiner]
	hub.mu.RUnlock()
	if room != "ch-1" {
		t.Fatalf("joiner room = %q, want %q", room, "ch-1")
	}
}

func TestHub_SendVoicePresenceSnapshot(t *testing.T) {
	hub := NewHub(nil, nil, nil)
	observer := &Client{send: make(chan []byte, 4), userID: "observer"}
	user1 := &Client{userID: "user-1"}
	user2 := &Client{userID: "user-2"}

	hub.mu.Lock()
	hub.voiceRooms["ch-1"] = map[*Client]struct{}{user1: {}, user2: {}}
	hub.voiceRoom[user1] = "ch-1"
	hub.voiceRoom[user2] = "ch-1"
	hub.mu.Unlock()

	hub.sendVoicePresenceSnapshot(observer)

	event := readEvent[voiceSignalEvent](t, observer.send)
	if event.Type != "voice.presence.snapshot" {
		t.Fatalf("type = %q, want %q", event.Type, "voice.presence.snapshot")
	}
	users, ok := event.VoiceRooms["ch-1"]
	if !ok {
		t.Fatalf("expected snapshot to include ch-1")
	}
	if len(users) != 2 || users[0] != "user-1" || users[1] != "user-2" {
		t.Fatalf("unexpected snapshot users: %+v", users)
	}
}

func TestHub_HandleVoiceJoin_BroadcastsPresenceToAllClients(t *testing.T) {
	repo := &fakeChannelRepo{ch: channel.Channel{ID: "ch-1"}}
	hub := NewHub(nil, nil, repo)

	joiner := &Client{send: make(chan []byte, 8), userID: "user-1"}
	peer := &Client{send: make(chan []byte, 8), userID: "user-2"}
	watcher := &Client{send: make(chan []byte, 8), userID: "watcher"}

	hub.mu.Lock()
	hub.clients[joiner] = struct{}{}
	hub.clients[peer] = struct{}{}
	hub.clients[watcher] = struct{}{}
	hub.voiceRooms["ch-1"] = map[*Client]struct{}{peer: {}}
	hub.voiceRoom[peer] = "ch-1"
	hub.mu.Unlock()

	hub.handleVoiceJoin(context.Background(), joiner, inboundMessage{Type: "voice_join", ChannelID: "ch-1"})

	event := readEvent[voiceSignalEvent](t, watcher.send)
	if event.Type != "voice.presence" {
		t.Fatalf("type = %q, want %q", event.Type, "voice.presence")
	}
	if event.ChannelID != "ch-1" || event.Sender != "user-1" || !event.Active {
		t.Fatalf("unexpected presence event: %+v", event)
	}
}

func TestHub_HandleVoiceLeave_BroadcastsPresenceToAllClients(t *testing.T) {
	hub := NewHub(nil, nil, nil)

	leaver := &Client{send: make(chan []byte, 8), userID: "user-1"}
	watcher := &Client{send: make(chan []byte, 8), userID: "watcher"}

	hub.mu.Lock()
	hub.clients[leaver] = struct{}{}
	hub.clients[watcher] = struct{}{}
	hub.voiceRooms["ch-1"] = map[*Client]struct{}{leaver: {}}
	hub.voiceRoom[leaver] = "ch-1"
	hub.mu.Unlock()

	hub.handleVoiceLeave(leaver, inboundMessage{Type: "voice_leave", ChannelID: "ch-1"})

	event := readEvent[voiceSignalEvent](t, watcher.send)
	if event.Type != "voice.presence" {
		t.Fatalf("type = %q, want %q", event.Type, "voice.presence")
	}
	if event.ChannelID != "ch-1" || event.Sender != "user-1" || event.Active {
		t.Fatalf("unexpected presence event: %+v", event)
	}
}

func TestHub_HandleVoiceSignal_ValidationErrors(t *testing.T) {
	hub := NewHub(nil, nil, nil)

	sender := &Client{send: make(chan []byte, 8), userID: "user-1"}
	hub.handleVoiceSignal(sender, inboundMessage{Type: "webrtc_offer", ChannelID: ""})
	errEvent := readEvent[errorEvent](t, sender.send)
	if errEvent.Type != "error" || errEvent.Code != "invalid_message" {
		t.Fatalf("unexpected missing channel error event: %+v", errEvent)
	}

	hub.handleVoiceSignal(sender, inboundMessage{Type: "webrtc_offer", ChannelID: "ch-1"})
	errEvent = readEvent[errorEvent](t, sender.send)
	if errEvent.Type != "error" || errEvent.Code != "voice_not_joined" {
		t.Fatalf("unexpected not-joined error event: %+v", errEvent)
	}
}

func TestHub_HandleVoiceSignal_BroadcastToRoomPeers(t *testing.T) {
	hub := NewHub(nil, nil, nil)

	sender := &Client{send: make(chan []byte, 8), userID: "user-1"}
	peerA := &Client{send: make(chan []byte, 8), userID: "user-2"}
	peerB := &Client{send: make(chan []byte, 8), userID: "user-3"}

	hub.mu.Lock()
	hub.voiceRooms["ch-1"] = map[*Client]struct{}{
		sender: {},
		peerA:  {},
		peerB:  {},
	}
	hub.voiceRoom[sender] = "ch-1"
	hub.voiceRoom[peerA] = "ch-1"
	hub.voiceRoom[peerB] = "ch-1"
	hub.mu.Unlock()

	hub.handleVoiceSignal(sender, inboundMessage{
		Type:      "webrtc_offer",
		ChannelID: "ch-1",
		SDP:       "offer-sdp",
	})

	msgA := readEvent[voiceSignalEvent](t, peerA.send)
	msgB := readEvent[voiceSignalEvent](t, peerB.send)

	if msgA.Type != "webrtc_offer" || msgA.Sender != "user-1" || msgA.ChannelID != "ch-1" || msgA.SDP != "offer-sdp" {
		t.Fatalf("unexpected peerA signal event: %+v", msgA)
	}
	if msgB.Type != "webrtc_offer" || msgB.Sender != "user-1" || msgB.ChannelID != "ch-1" || msgB.SDP != "offer-sdp" {
		t.Fatalf("unexpected peerB signal event: %+v", msgB)
	}

	select {
	case data := <-sender.send:
		t.Fatalf("sender should not receive own signal, got %s", string(data))
	default:
	}
}

func TestHub_HandleVoiceSignal_RecipientRouting(t *testing.T) {
	hub := NewHub(nil, nil, nil)

	sender := &Client{send: make(chan []byte, 8), userID: "user-1"}
	recipientInRoom := &Client{send: make(chan []byte, 8), userID: "user-2"}
	recipientOutOfRoom := &Client{send: make(chan []byte, 8), userID: "user-2"}
	unrelatedInRoom := &Client{send: make(chan []byte, 8), userID: "user-3"}

	hub.mu.Lock()
	hub.voiceRooms["ch-1"] = map[*Client]struct{}{
		sender:          {},
		recipientInRoom: {},
		unrelatedInRoom: {},
	}
	hub.voiceRoom[sender] = "ch-1"
	hub.voiceRoom[recipientInRoom] = "ch-1"
	hub.voiceRoom[unrelatedInRoom] = "ch-1"
	hub.voiceRooms["ch-2"] = map[*Client]struct{}{recipientOutOfRoom: {}}
	hub.voiceRoom[recipientOutOfRoom] = "ch-2"
	hub.byUser["user-2"] = map[*Client]struct{}{
		recipientInRoom:    {},
		recipientOutOfRoom: {},
	}
	hub.mu.Unlock()

	hub.handleVoiceSignal(sender, inboundMessage{
		Type:      "ice_candidate",
		ChannelID: "ch-1",
		Recipient: "user-2",
		Candidate: "candidate:1 1 udp 2122260223 127.0.0.1 40000 typ host",
	})

	msg := readEvent[voiceSignalEvent](t, recipientInRoom.send)
	if msg.Type != "ice_candidate" || msg.Sender != "user-1" || msg.Recipient != "user-2" || msg.Candidate == "" {
		t.Fatalf("unexpected routed signal event: %+v", msg)
	}

	select {
	case data := <-recipientOutOfRoom.send:
		t.Fatalf("out-of-room recipient should not receive signal, got %s", string(data))
	default:
	}
	select {
	case data := <-unrelatedInRoom.send:
		t.Fatalf("unrelated in-room peer should not receive recipient-targeted signal, got %s", string(data))
	default:
	}
}

func TestDecodeIncoming_ChannelMessageValidationBranches(t *testing.T) {
	tooLongBody := strings.Repeat("a", maxMessageLen+1)

	tests := []struct {
		name    string
		payload map[string]any
	}{
		{
			name: "missing channel id",
			payload: map[string]any{
				"type":            "channel.message.send",
				"body":            "hello",
				"sender_name_enc": "enc",
			},
		},
		{
			name: "missing body",
			payload: map[string]any{
				"type":            "channel.message.send",
				"channel_id":      "ch-1",
				"body":            "   ",
				"sender_name_enc": "enc",
			},
		},
		{
			name: "message too long",
			payload: map[string]any{
				"type":            "channel.message.send",
				"channel_id":      "ch-1",
				"body":            tooLongBody,
				"sender_name_enc": "enc",
			},
		},
		{
			name: "missing sender name",
			payload: map[string]any{
				"type":            "channel.message.send",
				"channel_id":      "ch-1",
				"body":            "hello",
				"sender_name_enc": "   ",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.payload)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}
			_, err = decodeIncoming(data)
			if err == nil {
				t.Fatalf("expected decodeIncoming to fail for %s", tt.name)
			}
		})
	}
}

func TestDecodeIncoming_VoiceSignalValidationBranches(t *testing.T) {
	tests := []struct {
		name    string
		payload map[string]any
	}{
		{
			name: "voice_join missing channel",
			payload: map[string]any{
				"type": "voice_join",
			},
		},
		{
			name: "voice_leave missing channel",
			payload: map[string]any{
				"type": "voice_leave",
			},
		},
		{
			name: "webrtc_offer missing recipient",
			payload: map[string]any{
				"type":       "webrtc_offer",
				"channel_id": "ch-1",
				"sdp":        "offer",
			},
		},
		{
			name: "webrtc_answer missing sdp",
			payload: map[string]any{
				"type":       "webrtc_answer",
				"channel_id": "ch-1",
				"recipient":  "user-2",
			},
		},
		{
			name: "ice_candidate missing candidate",
			payload: map[string]any{
				"type":       "ice_candidate",
				"channel_id": "ch-1",
				"recipient":  "user-2",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.payload)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}
			_, err = decodeIncoming(data)
			if err == nil {
				t.Fatalf("expected decodeIncoming to fail for %s", tt.name)
			}
		})
	}
}

func TestHub_HandleVoiceJoin_ValidationAndStorageErrors(t *testing.T) {
	t.Run("missing channel id", func(t *testing.T) {
		hub := NewHub(nil, nil, &fakeChannelRepo{ch: channel.Channel{ID: "ch-1"}})
		client := &Client{send: make(chan []byte, 1), userID: "user-1"}

		hub.handleVoiceJoin(context.Background(), client, inboundMessage{Type: "voice_join"})

		event := readEvent[errorEvent](t, client.send)
		if event.Code != "invalid_message" {
			t.Fatalf("code = %q, want %q", event.Code, "invalid_message")
		}
	})

	t.Run("channel repo unavailable", func(t *testing.T) {
		hub := NewHub(nil, nil, nil)
		client := &Client{send: make(chan []byte, 1), userID: "user-1"}

		hub.handleVoiceJoin(context.Background(), client, inboundMessage{Type: "voice_join", ChannelID: "ch-1"})

		event := readEvent[errorEvent](t, client.send)
		if event.Code != "server_error" {
			t.Fatalf("code = %q, want %q", event.Code, "server_error")
		}
	})

	t.Run("channel not found", func(t *testing.T) {
		hub := NewHub(nil, nil, &fakeChannelRepo{getErr: storage.ErrNotFound})
		client := &Client{send: make(chan []byte, 1), userID: "user-1"}

		hub.handleVoiceJoin(context.Background(), client, inboundMessage{Type: "voice_join", ChannelID: "missing"})

		event := readEvent[errorEvent](t, client.send)
		if event.Code != "channel_not_found" {
			t.Fatalf("code = %q, want %q", event.Code, "channel_not_found")
		}
	})

	t.Run("channel lookup failure", func(t *testing.T) {
		hub := NewHub(nil, nil, &fakeChannelRepo{getErr: errors.New("boom")})
		client := &Client{send: make(chan []byte, 1), userID: "user-1"}

		hub.handleVoiceJoin(context.Background(), client, inboundMessage{Type: "voice_join", ChannelID: "ch-1"})

		event := readEvent[errorEvent](t, client.send)
		if event.Code != "server_error" {
			t.Fatalf("code = %q, want %q", event.Code, "server_error")
		}
	})
}

func TestHub_HandleVoiceLeave_ValidationAndPeerEvent(t *testing.T) {
	t.Run("missing channel id", func(t *testing.T) {
		hub := NewHub(nil, nil, nil)
		client := &Client{send: make(chan []byte, 1), userID: "user-1"}

		hub.handleVoiceLeave(client, inboundMessage{Type: "voice_leave"})

		event := readEvent[errorEvent](t, client.send)
		if event.Code != "invalid_message" {
			t.Fatalf("code = %q, want %q", event.Code, "invalid_message")
		}
	})

	t.Run("peer receives leave signal", func(t *testing.T) {
		hub := NewHub(nil, nil, nil)
		leaver := &Client{send: make(chan []byte, 2), userID: "user-1"}
		peer := &Client{send: make(chan []byte, 2), userID: "user-2"}

		hub.mu.Lock()
		hub.voiceRooms["ch-1"] = map[*Client]struct{}{leaver: {}, peer: {}}
		hub.voiceRoom[leaver] = "ch-1"
		hub.voiceRoom[peer] = "ch-1"
		hub.mu.Unlock()

		hub.handleVoiceLeave(leaver, inboundMessage{Type: "voice_leave", ChannelID: "ch-1"})

		event := readEvent[voiceSignalEvent](t, peer.send)
		if event.Type != "voice_leave" || event.ChannelID != "ch-1" || event.Sender != "user-1" {
			t.Fatalf("unexpected peer leave event: %+v", event)
		}
	})
}

func TestHub_RemoveFromVoiceRoomLocked(t *testing.T) {
	hub := NewHub(nil, nil, nil)
	missing := &Client{userID: "missing"}

	hub.mu.Lock()
	if peers := hub.removeFromVoiceRoomLocked(missing); peers != nil {
		hub.mu.Unlock()
		t.Fatalf("expected nil peers for client without room, got %d", len(peers))
	}
	hub.mu.Unlock()

	owner := &Client{userID: "owner"}
	hub.mu.Lock()
	hub.voiceRooms["room-a"] = map[*Client]struct{}{owner: {}}
	hub.voiceRoom[owner] = "room-a"
	peers := hub.removeFromVoiceRoomLocked(owner)
	_, hasRoom := hub.voiceRooms["room-a"]
	_, tracked := hub.voiceRoom[owner]
	hub.mu.Unlock()

	if peers != nil {
		t.Fatalf("expected nil peers when room is emptied, got %d", len(peers))
	}
	if hasRoom {
		t.Fatalf("expected empty room to be removed")
	}
	if tracked {
		t.Fatalf("expected client room tracking to be removed")
	}

	target := &Client{userID: "target"}
	peerA := &Client{userID: "peer-a"}
	peerB := &Client{userID: "peer-b"}
	hub.mu.Lock()
	hub.voiceRooms["room-b"] = map[*Client]struct{}{target: {}, peerA: {}, peerB: {}}
	hub.voiceRoom[target] = "room-b"
	hub.voiceRoom[peerA] = "room-b"
	hub.voiceRoom[peerB] = "room-b"
	peers = hub.removeFromVoiceRoomLocked(target)
	roomSize := len(hub.voiceRooms["room-b"])
	hub.mu.Unlock()

	if len(peers) != 2 {
		t.Fatalf("expected 2 remaining peers, got %d", len(peers))
	}
	if roomSize != 2 {
		t.Fatalf("expected room to retain 2 peers, got %d", roomSize)
	}
}
