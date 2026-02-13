package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
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

func TestRunVoiceFlagsApplied(t *testing.T) {
	var captured rootModel
	factory := func(m tea.Model, _ ...tea.ProgramOption) programRunner {
		captured = m.(rootModel)
		return &fakeProgram{}
	}

	err := run([]string{
		"-server", "http://example",
		"-voice-auto=false",
		"-voice-ipc", "/tmp/dialtone.sock",
		"-voiced", "/tmp/dialtone-voiced",
		"-voice-debug",
		"-voice-log", "/tmp/voice.log",
		"-voice-ptt", "F24",
		"-voice-ptt-backend", "PORTAL",
		"-voice-vad", "18",
		"-voice-meter",
		"-voice-stun", "stun:a,stun:b",
		"-voice-turn", "turn:a",
		"-voice-turn-user", "alice",
		"-voice-turn-pass", "secret",
	}, strings.NewReader(""), io.Discard, io.Discard, factory)
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	if captured.api.serverURL != "http://example" {
		t.Fatalf("unexpected server url: %q", captured.api.serverURL)
	}
	if captured.voiceAutoStart {
		t.Fatalf("expected voice auto-start disabled")
	}
	if captured.voice != "/tmp/dialtone.sock" {
		t.Fatalf("unexpected voice ipc: %q", captured.voice)
	}
	if captured.voicedPath != "/tmp/dialtone-voiced" {
		t.Fatalf("unexpected voiced path: %q", captured.voicedPath)
	}
	if !captured.voiceDebug {
		t.Fatalf("expected voiceDebug=true")
	}
	if captured.voiceLogPath != "/tmp/voice.log" {
		t.Fatalf("unexpected voice log path: %q", captured.voiceLogPath)
	}

	wantArgs := []string{
		"-ptt", "F24",
		"-ptt-backend", "portal",
		"-vad-threshold", "18",
		"-meter",
		"-stun", "stun:a,stun:b",
		"-turn", "turn:a",
		"-turn-user", "alice",
		"-turn-pass", "secret",
	}
	if !reflect.DeepEqual(captured.voiceArgs, wantArgs) {
		t.Fatalf("unexpected voice args: %#v", captured.voiceArgs)
	}
}

func TestRunVoiceFlagValidation(t *testing.T) {
	err := run([]string{"-voice-vad", "0"}, strings.NewReader(""), io.Discard, io.Discard, nil)
	if err == nil || !strings.Contains(err.Error(), "voice-vad must be > 0") {
		t.Fatalf("expected voice-vad validation error, got %v", err)
	}

	err = run([]string{"-voice-ptt-backend", "invalid"}, strings.NewReader(""), io.Discard, io.Discard, nil)
	if err == nil || !strings.Contains(err.Error(), "voice-ptt-backend must be one of") {
		t.Fatalf("expected voice-ptt-backend validation error, got %v", err)
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
