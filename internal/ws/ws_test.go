package ws

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Avicted/dialtone/internal/auth"
	"github.com/Avicted/dialtone/internal/user"
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
	hub := NewHub(nil, nil, nil, nil)
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
	hub := NewHub(nil, nil, nil, nil)
	hub.sendHistory(context.TODO(), nil)
}

func TestHub_HandleIncoming_UnknownType(t *testing.T) {
	hub := NewHub(nil, nil, nil, nil)
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
