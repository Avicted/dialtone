package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/Avicted/dialtone/internal/crypto"
)

func TestRootModelAuthSuccess(t *testing.T) {
	setTestConfigDir(t)
	api := &APIClient{serverURL: "http://server", httpClient: http.DefaultClient}
	m := newRootModel(api, "")
	m.login.serverInput.SetValue("http://server")
	m.login.passphraseInp.SetValue("passphrase123")
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	updated, _ := m.Update(authSuccessMsg{auth: &AuthResponse{Username: "alice", UserID: "user"}, kp: kp})
	root := updated.(rootModel)
	if root.state != stateChat {
		t.Fatalf("expected chat state")
	}
	if root.chat.auth == nil || root.chat.auth.Username != "alice" {
		t.Fatalf("missing chat auth")
	}
}

func TestRootModelDoAuthLogin(t *testing.T) {
	setTestConfigDir(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/login" {
			t.Errorf("expected /auth/login, got %s", r.URL.Path)
			return
		}
		_ = json.NewEncoder(w).Encode(AuthResponse{Token: "token", UserID: "user", DeviceID: "dev"})
	}))
	defer server.Close()

	api := &APIClient{serverURL: server.URL, httpClient: server.Client()}
	m := newRootModel(api, "")
	cmd := m.doAuth(false, "alice", "password", "", "passphrase123")
	msg := cmd()
	if _, ok := msg.(authSuccessMsg); !ok {
		t.Fatalf("expected authSuccessMsg, got %T", msg)
	}
}

func TestRootModelDoAuthError(t *testing.T) {
	setTestConfigDir(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(apiError{Error: "bad"})
	}))
	defer server.Close()

	api := &APIClient{serverURL: server.URL, httpClient: server.Client()}
	m := newRootModel(api, "")
	cmd := m.doAuth(false, "alice", "password", "", "passphrase123")
	msg := cmd()
	if _, ok := msg.(authErrorMsg); !ok {
		t.Fatalf("expected authErrorMsg, got %T", msg)
	}
}

func TestRootModelUpdateCtrlQ(t *testing.T) {
	api := &APIClient{serverURL: "http://server", httpClient: http.DefaultClient}
	m := newRootModel(api, "")
	m.state = stateChat
	m.chat.ws = &WSClient{closed: true}
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlQ})
	if cmd == nil {
		t.Fatalf("expected quit command")
	}
}

func TestRootModelUpdateLoginSubmit(t *testing.T) {
	setTestConfigDir(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(AuthResponse{Token: "token", UserID: "user", DeviceID: "dev"})
	}))
	defer server.Close()

	api := &APIClient{serverURL: server.URL, httpClient: server.Client()}
	m := newRootModel(api, "")
	m.login.serverInput.SetValue(server.URL)
	m.login.usernameInput.SetValue("alice")
	m.login.passwordInput.SetValue("password")
	m.login.passphraseInp.SetValue("passphrase123")

	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	root := updated.(rootModel)
	if !root.login.submitting && cmd == nil {
		t.Fatalf("expected auth command")
	}
}

func TestRootModelUpdateWindowSize(t *testing.T) {
	api := &APIClient{serverURL: "http://server", httpClient: http.DefaultClient}
	m := newRootModel(api, "")
	updated, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	root := updated.(rootModel)
	if root.width != 80 || root.height != 24 {
		t.Fatalf("unexpected size")
	}
}

func TestRootModelView(t *testing.T) {
	api := &APIClient{serverURL: "http://server", httpClient: http.DefaultClient}
	m := newRootModel(api, "")
	if view := m.View(); view == "" {
		t.Fatalf("expected view")
	}
}

func TestRootModelDoAuthRegister(t *testing.T) {
	setTestConfigDir(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/register" {
			t.Errorf("expected /auth/register, got %s", r.URL.Path)
			return
		}
		_ = json.NewEncoder(w).Encode(AuthResponse{Token: "token", UserID: "user", DeviceID: "dev"})
	}))
	defer server.Close()

	api := &APIClient{serverURL: server.URL, httpClient: server.Client()}
	m := newRootModel(api, "")
	cmd := m.doAuth(true, "alice", "password", "invite", "passphrase123")
	msg := cmd()
	if _, ok := msg.(authSuccessMsg); !ok {
		t.Fatalf("expected authSuccessMsg, got %T", msg)
	}
}

func TestRootModelUpdateAuthErrorMsg(t *testing.T) {
	api := &APIClient{serverURL: "http://server", httpClient: http.DefaultClient}
	m := newRootModel(api, "")
	updated, _ := m.Update(authErrorMsg{err: context.Canceled})
	root := updated.(rootModel)
	if root.login.errMsg == "" {
		t.Fatalf("expected error message")
	}
}

func TestRootModelInit(t *testing.T) {
	api := &APIClient{serverURL: "http://server", httpClient: http.DefaultClient}
	m := newRootModel(api, "")
	if cmd := m.Init(); cmd == nil {
		t.Fatalf("expected init command")
	}
}

func TestRootModelViewChat(t *testing.T) {
	api := &APIClient{serverURL: "http://server", httpClient: http.DefaultClient}
	m := newRootModel(api, "")
	m.state = stateChat
	m.chat = newChatForTest(t, api)
	if view := m.View(); view == "" {
		t.Fatalf("expected chat view")
	}
}

func TestRootModelAuthSuccessSavesServerHistory(t *testing.T) {
	setTestConfigDir(t)
	api := &APIClient{serverURL: "http://server", httpClient: http.DefaultClient}
	m := newRootModel(api, "")
	m.login.serverInput.SetValue("http://server")
	_, _ = m.Update(authSuccessMsg{auth: &AuthResponse{Username: "alice", UserID: "user"}, kp: newTestKeyPair(t)})
	if history := loadServerHistory(); len(history) == 0 {
		t.Fatalf("expected server history")
	}
}
