package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"nhooyr.io/websocket"
)

type fakeProgram struct {
	ran bool
}

func (f *fakeProgram) Run() (tea.Model, error) {
	f.ran = true
	return nil, nil
}

func TestRunUsesServerFlag(t *testing.T) {
	var gotURL string
	factory := func(m tea.Model, _ ...tea.ProgramOption) programRunner {
		root := m.(rootModel)
		gotURL = root.api.serverURL
		return &fakeProgram{}
	}

	err := run([]string{"-server", "http://example"}, strings.NewReader(""), io.Discard, io.Discard, factory)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if gotURL != "http://example" {
		t.Fatalf("unexpected server url: %s", gotURL)
	}
}

func TestRunDefaultsToEmptyServer(t *testing.T) {
	var gotURL string
	factory := func(m tea.Model, _ ...tea.ProgramOption) programRunner {
		root := m.(rootModel)
		gotURL = root.api.serverURL
		return &fakeProgram{}
	}

	err := run([]string{}, strings.NewReader(""), io.Discard, io.Discard, factory)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if gotURL != "" {
		t.Fatalf("expected empty server url, got %s", gotURL)
	}
}

func TestChatInitConnectsWebsocket(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ws" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close(websocket.StatusNormalClosure, "done")
	}))
	defer server.Close()

	auth := newTestAuth()
	auth.IsTrusted = false
	api := &APIClient{serverURL: server.URL, httpClient: server.Client()}
	m := newChatModel(api, auth, newTestKeyPair(t), "passphrase123", 80, 24, "")
	cmd := m.Init()
	msg := cmd()

	found := false
	switch typed := msg.(type) {
	case tea.BatchMsg:
		for _, item := range typed {
			itemMsg := item()
			if connected, ok := itemMsg.(wsConnectedMsg); ok {
				found = true
				connected.ws.Close()
				break
			}
		}
	case wsConnectedMsg:
		found = true
		typed.ws.Close()
	}
	if !found {
		t.Fatalf("expected wsConnectedMsg")
	}
}
