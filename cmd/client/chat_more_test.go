package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/Avicted/dialtone/internal/crypto"
)

func TestChatModelResolveChannelSelection(t *testing.T) {
	key := bytes.Repeat([]byte{1}, crypto.KeySize)
	nameEnc, err := encryptChannelField(key, "general")
	if err != nil {
		t.Fatalf("encryptChannelField: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/channels" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(ListChannelsResponse{Channels: []ChannelResponse{{ID: "ch-1", NameEnc: nameEnc}, {ID: "ch-2", NameEnc: nameEnc}}})
	}))
	defer server.Close()

	api := &APIClient{serverURL: server.URL, httpClient: server.Client()}
	m := newChatForTest(t, api)
	m.channelKeys["ch-1"] = key
	m.channelKeys["ch-2"] = key
	_, _, ok := m.resolveChannel("general", true)
	if ok {
		t.Fatalf("expected selection flow")
	}
	if !m.selectActive || len(m.selectOptions) != 2 {
		t.Fatalf("expected channel selection")
	}
}

func TestChatModelHandleChannelSelectKey(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	m.selectActive = true
	m.selectOptions = []channelInfo{{ID: "ch-1", Name: "general"}}
	m.channelHistoryLoaded["ch-1"] = true
	m.handleChannelSelectKey(tea.KeyMsg{Type: tea.KeyEnter})
	if m.selectActive || m.activeChannel != "ch-1" {
		t.Fatalf("expected channel selection applied")
	}

	m.selectActive = true
	m.selectOptions = []channelInfo{{ID: "ch-2", Name: "random"}}
	m.handleChannelSelectKey(tea.KeyMsg{Type: tea.KeyEsc})
	if m.selectActive {
		t.Fatalf("expected selection closed")
	}
	if lastSystemMessage(m) != "channel selection canceled" {
		t.Fatalf("unexpected message: %s", lastSystemMessage(m))
	}
}

func TestChatModelSendCurrentMessageNoChannel(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	m.ws = &WSClient{}
	m.input.SetValue("hello")
	m.sendCurrentMessage()
	if !strings.Contains(lastSystemMessage(m), "no global chat") {
		t.Fatalf("expected no channel message")
	}
}

func TestChatModelRenderMessagesEmptyStates(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	if out := m.renderMessages(); !strings.Contains(out, "No channel selected") {
		t.Fatalf("unexpected render output")
	}
	m.activeChannel = "ch-1"
	if out := m.renderMessages(); !strings.Contains(out, "No messages yet") {
		t.Fatalf("unexpected render output")
	}
}

func TestChatModelRefreshPresenceTrusted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/presence" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(PresenceResponse{Statuses: map[string]bool{"u1": true}, Admins: map[string]bool{"u1": true}})
	}))
	defer server.Close()

	api := &APIClient{serverURL: server.URL, httpClient: server.Client()}
	m := newChatForTest(t, api)
	m.userNames["u1"] = "alice"
	m.refreshPresence()
	if !m.userPresence["u1"] || !m.userAdmins["u1"] {
		t.Fatalf("expected presence/admin updated")
	}
}

func TestChatModelEnsureDirectoryKeyFromEnvelope(t *testing.T) {
	setTestConfigDir(t)
	senderKP := newTestKeyPair(t)
	recipientKP := newTestKeyPair(t)
	key := bytes.Repeat([]byte{9}, crypto.KeySize)
	ct, err := crypto.EncryptForPeer(senderKP.Private, recipientKP.Public, key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/directory/keys" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(DirectoryKeyEnvelope{SenderPublicKey: crypto.PublicKeyToBase64(senderKP.Public), Envelope: ct})
	}))
	defer server.Close()

	api := &APIClient{serverURL: server.URL, httpClient: server.Client()}
	m := newChatModel(api, newTestAuth(), recipientKP, "passphrase123", 80, 24)
	got, err := m.ensureDirectoryKey()
	if err != nil {
		t.Fatalf("ensureDirectoryKey: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Fatalf("unexpected key")
	}
}

func TestChatModelEnsureDirectoryKeyInvalidSenderKey(t *testing.T) {
	setTestConfigDir(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(DirectoryKeyEnvelope{SenderPublicKey: "not-base64", Envelope: "ct"})
	}))
	defer server.Close()

	api := &APIClient{serverURL: server.URL, httpClient: server.Client()}
	m := newChatModel(api, newTestAuth(), newTestKeyPair(t), "passphrase123", 80, 24)
	if _, err := m.ensureDirectoryKey(); err == nil {
		t.Fatalf("expected error")
	}
}

func TestChatModelShareKeyErrors(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	if err := m.shareChannelKey(""); err == nil {
		t.Fatalf("expected missing channel id error")
	}
	if err := m.shareChannelKey("ch-1"); err == nil {
		t.Fatalf("expected missing channel key error")
	}
	if err := m.shareDirectoryKey(); err == nil {
		t.Fatalf("expected missing directory key error")
	}
}

func TestChatModelShareChannelKeyNoDevices(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/devices/keys" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(DeviceKeysResponse{Keys: nil})
	}))
	defer server.Close()

	api := &APIClient{serverURL: server.URL, httpClient: server.Client()}
	m := newChatForTest(t, api)
	m.channelKeys["ch-1"] = bytes.Repeat([]byte{2}, crypto.KeySize)
	if err := m.shareChannelKey("ch-1"); err == nil || !strings.Contains(err.Error(), "no devices") {
		t.Fatalf("expected no devices error, got %v", err)
	}
}

func TestChatModelSyncDirectoryPushProfile(t *testing.T) {
	key := bytes.Repeat([]byte{3}, crypto.KeySize)
	nameEnc, err := encryptChannelField(key, "alice")
	if err != nil {
		t.Fatalf("encryptChannelField: %v", err)
	}
	var pushed bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/users/profiles":
			if r.Method == http.MethodPost {
				pushed = true
				w.WriteHeader(http.StatusOK)
				return
			}
			_ = json.NewEncoder(w).Encode(ListUserProfilesResponse{Profiles: []UserProfile{{UserID: "u1", NameEnc: nameEnc}}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	api := &APIClient{serverURL: server.URL, httpClient: server.Client()}
	m := newChatForTest(t, api)
	m.directoryKey = key
	profiles, didPush, err := m.syncDirectory(true)
	if err != nil {
		t.Fatalf("syncDirectory: %v", err)
	}
	if !didPush || !pushed || len(profiles) != 1 {
		t.Fatalf("unexpected sync results")
	}
}

func TestChatModelUpdateSidebarToggle(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	m.sidebarVisible = true
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyCtrlH})
	if updated.sidebarVisible {
		t.Fatalf("expected sidebar hidden")
	}
}

func TestChatModelRefreshChannelsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(apiError{Error: "boom"})
	}))
	defer server.Close()

	api := &APIClient{serverURL: server.URL, httpClient: server.Client()}
	m := newChatForTest(t, api)
	m.refreshChannels(false)
	if m.errMsg == "" || m.channelRefreshNeeded {
		t.Fatalf("expected refresh error state")
	}
}

func TestChatModelDecryptChannelFieldMissingKey(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	if got := m.decryptChannelField("ch-1", "not-encoded"); got != "<encrypted>" {
		t.Fatalf("unexpected decrypt result: %s", got)
	}
}

func TestBuildChannelKeyEnvelopesErrors(t *testing.T) {
	key := bytes.Repeat([]byte{1}, crypto.KeySize)
	if _, err := buildChannelKeyEnvelopes(nil, "dev", key, nil); err == nil {
		t.Fatalf("expected missing device key error")
	}
	if _, err := buildChannelKeyEnvelopes(newTestKeyPair(t), "", key, nil); err == nil {
		t.Fatalf("expected missing sender device id error")
	}
	if _, err := buildChannelKeyEnvelopes(newTestKeyPair(t), "dev", key, []DeviceKey{{DeviceID: "d1", PublicKey: "invalid"}}); err == nil {
		t.Fatalf("expected invalid public key error")
	}
}

func TestBuildDirectoryKeyEnvelopesErrors(t *testing.T) {
	key := bytes.Repeat([]byte{1}, crypto.KeySize)
	if _, err := buildDirectoryKeyEnvelopes(nil, "dev", key, nil); err == nil {
		t.Fatalf("expected missing device key error")
	}
	if _, err := buildDirectoryKeyEnvelopes(newTestKeyPair(t), "", key, nil); err == nil {
		t.Fatalf("expected missing sender device id error")
	}
}

func TestChatModelSelectSidebarChannel(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	m.channels["a"] = channelInfo{ID: "a", Name: "alpha"}
	m.channels["b"] = channelInfo{ID: "b", Name: "beta"}
	m.channelHistoryLoaded["a"] = true
	m.sidebarIndex = 0
	if !m.selectSidebarChannel() || m.activeChannel != "a" {
		t.Fatalf("expected sidebar selection")
	}
	m.sidebarIndex = 0
	if !m.selectSidebarChannel() {
		t.Fatalf("expected selection true")
	}
	if lastSystemMessage(m) != "already viewing that channel" {
		t.Fatalf("unexpected message: %s", lastSystemMessage(m))
	}
}

func TestChatModelActiveChannelLabel(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	if m.activeChannelLabel() != "no channel" {
		t.Fatalf("unexpected label")
	}
	m.activeChannel = "ch-1"
	m.channels["ch-1"] = channelInfo{ID: "ch-1", Name: "general"}
	if m.activeChannelLabel() != "channel: general" {
		t.Fatalf("unexpected label")
	}
}

func TestChatModelRenderMessagesStyled(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	msg := chatMessage{sender: "u1", senderName: "bob", body: "hello", sentAt: time.Now().UTC().Format(time.RFC3339Nano)}
	m.messages = append(m.messages, msg)
	if out := m.renderMessages(); out == "" {
		t.Fatalf("expected rendered output")
	}
}

func TestChatModelWaitForWSMsg(t *testing.T) {
	ch := make(chan ServerMessage, 1)
	ch <- ServerMessage{Type: "ping"}
	cmd := waitForWSMsg(ch)
	msg := cmd()
	if _, ok := msg.(wsMessageMsg); !ok {
		t.Fatalf("expected wsMessageMsg, got %T", msg)
	}

	closed := make(chan ServerMessage)
	close(closed)
	cmd = waitForWSMsg(closed)
	msg = cmd()
	if _, ok := msg.(wsErrorMsg); !ok {
		t.Fatalf("expected wsErrorMsg, got %T", msg)
	}
}

func TestChatModelUpdateWSStates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/channels" {
			_ = json.NewEncoder(w).Encode(ListChannelsResponse{Channels: nil})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	api := &APIClient{serverURL: server.URL, httpClient: server.Client()}
	m := newChatForTest(t, api)
	updated, _ := m.Update(wsConnectedMsg{ws: &WSClient{}, ch: make(chan ServerMessage)})
	if !updated.connected {
		t.Fatalf("expected connected state")
	}
	if lastSystemMessage(updated) == "" {
		t.Fatalf("expected system message")
	}

	updated, _ = updated.Update(wsErrorMsg{err: context.Canceled})
	if updated.connected || updated.errMsg == "" {
		t.Fatalf("expected error state")
	}
}

func TestChatModelUpdateDirectoryAndShareMsgs(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	profiles := []UserProfile{{UserID: "u1", NameEnc: ""}}
	updated, _ := m.Update(directorySyncMsg{profiles: profiles, pushed: true, err: nil})
	if updated.pendingProfilePush {
		t.Fatalf("expected pendingProfilePush cleared")
	}

	updated, _ = updated.Update(shareKeysMsg{err: context.Canceled})
	if updated.errMsg == "" {
		t.Fatalf("expected share keys error")
	}
	updated, _ = updated.Update(shareDirectoryMsg{err: context.Canceled})
	if updated.errMsg == "" {
		t.Fatalf("expected share directory error")
	}
}

func TestChatModelPresenceTickTrusted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/presence" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(PresenceResponse{Statuses: map[string]bool{"u1": true}, Admins: map[string]bool{}})
	}))
	defer server.Close()

	api := &APIClient{serverURL: server.URL, httpClient: server.Client()}
	m := newChatForTest(t, api)
	m.userNames["u1"] = "alice"
	m.sidebarMode = sidebarUsers
	m.sidebarVisible = true
	updated, cmd := m.Update(presenceTick{})
	if cmd == nil {
		t.Fatalf("expected presence tick cmd")
	}
	if !updated.userPresence["u1"] {
		t.Fatalf("expected presence set")
	}
}

func TestChatModelRenderSidebarUsersNotTrusted(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	m.auth.IsTrusted = false
	m.sidebarMode = sidebarUsers
	if out := m.renderSidebar(); !strings.Contains(out, "(no channel)") {
		t.Fatalf("unexpected sidebar output")
	}
}

func TestChatModelEnsureChannelKeyFromEnvelope(t *testing.T) {
	setTestConfigDir(t)
	senderKP := newTestKeyPair(t)
	recipientKP := newTestKeyPair(t)
	key := bytes.Repeat([]byte{7}, crypto.KeySize)
	ct, err := crypto.EncryptForPeer(senderKP.Private, recipientKP.Public, key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(ChannelKeyEnvelope{ChannelID: "ch-1", SenderPublicKey: crypto.PublicKeyToBase64(senderKP.Public), Envelope: ct})
	}))
	defer server.Close()

	api := &APIClient{serverURL: server.URL, httpClient: server.Client()}
	m := newChatModel(api, newTestAuth(), recipientKP, "passphrase123", 80, 24)
	if _, err := m.ensureChannelKey("ch-1"); err != nil {
		t.Fatalf("ensureChannelKey: %v", err)
	}
}

func TestChatModelFormatHelpers(t *testing.T) {
	if formatTime("invalid") != "invalid" {
		t.Fatalf("expected passthrough")
	}
	if shortID("123456789") != "12345678" {
		t.Fatalf("unexpected shortID")
	}
	if clampMin(1, 3) != 3 {
		t.Fatalf("unexpected clampMin")
	}
	if trimLine("hello", 4) != "h..." {
		t.Fatalf("unexpected trimLine")
	}
}
