package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/Avicted/dialtone/internal/crypto"
)

func newChatForTest(t *testing.T, api *APIClient) chatModel {
	t.Helper()
	setTestConfigDir(t)
	auth := newTestAuth()
	kp := newTestKeyPair(t)
	return newChatModel(api, auth, kp, "passphrase123", 80, 24)
}

func TestChatModelHandleCommandNonAdmin(t *testing.T) {
	api := &APIClient{serverURL: "http://server", httpClient: http.DefaultClient}
	m := newChatForTest(t, api)
	m.auth.IsAdmin = false
	m.handleCommand("/help")
	if !strings.Contains(lastSystemMessage(m), "commands") {
		t.Fatalf("expected help message")
	}
	m.handleCommand("/server invite")
	if lastSystemMessage(m) != "admin only: server invites" {
		t.Fatalf("unexpected message: %s", lastSystemMessage(m))
	}
}

func TestChatModelCreateServerInvite(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/server/invites" {
			t.Errorf("expected /server/invites, got %s", r.URL.Path)
			return
		}
		_ = json.NewEncoder(w).Encode(CreateServerInviteResponse{Token: "invite", ExpiresAt: time.Now().UTC().Format(time.RFC3339Nano)})
	}))
	defer server.Close()

	api := &APIClient{serverURL: server.URL, httpClient: server.Client()}
	m := newChatForTest(t, api)
	m.createServerInvite()
	found := false
	for _, msg := range m.messages {
		if strings.Contains(msg.body, "server invite") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected invite message")
	}
}

func TestChatModelRefreshChannelsAndUseChannel(t *testing.T) {
	key := bytes.Repeat([]byte{1}, crypto.KeySize)
	nameEnc, err := encryptChannelField(key, "general")
	if err != nil {
		t.Fatalf("encryptChannelField: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/channels" {
			t.Errorf("expected /channels, got %s", r.URL.Path)
			return
		}
		_ = json.NewEncoder(w).Encode(ListChannelsResponse{Channels: []ChannelResponse{{ID: "ch-1", NameEnc: nameEnc}}})
	}))
	defer server.Close()

	api := &APIClient{serverURL: server.URL, httpClient: server.Client()}
	m := newChatForTest(t, api)
	m.channelKeys["ch-1"] = key
	m.refreshChannels(true)
	if m.channels["ch-1"].Name != "general" {
		t.Fatalf("expected channel name")
	}
	m.channelHistoryLoaded["ch-1"] = true
	m.useChannel("ch-1")
	if m.activeChannel != "ch-1" {
		t.Fatalf("expected active channel")
	}
}

func TestChatModelCreateDeleteRenameChannel(t *testing.T) {
	deviceKP := newTestKeyPair(t)
	var createPayload map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/channels":
			_ = json.NewDecoder(r.Body).Decode(&createPayload)
			_ = json.NewEncoder(w).Encode(CreateChannelResponse{Channel: ChannelResponse{ID: "ch-1", NameEnc: createPayload["name_enc"]}})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/devices/keys"):
			_ = json.NewEncoder(w).Encode(DeviceKeysResponse{Keys: []DeviceKey{{DeviceID: "dev-2", PublicKey: crypto.PublicKeyToBase64(deviceKP.Public)}}})
		case r.Method == http.MethodPost && r.URL.Path == "/channels/keys":
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodDelete && r.URL.Path == "/channels":
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPatch && r.URL.Path == "/channels":
			var payload map[string]string
			_ = json.NewDecoder(r.Body).Decode(&payload)
			_ = json.NewEncoder(w).Encode(CreateChannelResponse{Channel: ChannelResponse{ID: payload["channel_id"], NameEnc: payload["name_enc"]}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	api := &APIClient{serverURL: server.URL, httpClient: server.Client()}
	m := newChatForTest(t, api)
	m.createChannel("general")
	if m.activeChannel != "ch-1" {
		t.Fatalf("expected active channel")
	}
	if m.channels["ch-1"].Name != "general" {
		t.Fatalf("expected channel name")
	}
	m.channelHistoryLoaded["ch-1"] = true
	m.deleteChannel("ch-1")
	if _, ok := m.channels["ch-1"]; ok {
		t.Fatalf("expected channel deleted")
	}
	key := bytes.Repeat([]byte{2}, crypto.KeySize)
	m.setChannelKey("ch-2", key)
	m.channels["ch-2"] = channelInfo{ID: "ch-2", Name: "old"}
	m.renameChannel("ch-2", "new")
	if m.channels["ch-2"].Name != "new" {
		t.Fatalf("expected renamed channel")
	}
}

func TestChatModelShareKnownChannelKeys(t *testing.T) {
	deviceKP := newTestKeyPair(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/channels":
			_ = json.NewEncoder(w).Encode(ListChannelsResponse{Channels: []ChannelResponse{{ID: "ch-1"}}})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/devices/keys"):
			_ = json.NewEncoder(w).Encode(DeviceKeysResponse{Keys: []DeviceKey{{DeviceID: "dev-2", PublicKey: crypto.PublicKeyToBase64(deviceKP.Public)}}})
		case r.Method == http.MethodPost && r.URL.Path == "/channels/keys":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	api := &APIClient{serverURL: server.URL, httpClient: server.Client()}
	m := newChatForTest(t, api)
	m.channelKeys["ch-1"] = bytes.Repeat([]byte{1}, crypto.KeySize)
	m.channelKeys["stale"] = bytes.Repeat([]byte{2}, crypto.KeySize)
	if err := m.shareKnownChannelKeys(); err != nil {
		t.Fatalf("shareKnownChannelKeys: %v", err)
	}
	if _, ok := m.channelKeys["stale"]; ok {
		t.Fatalf("expected stale key removal")
	}
}

func TestChatModelEnsureDirectoryKeyPending(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/directory/keys":
			w.WriteHeader(http.StatusNoContent)
		case "/users/profiles":
			_ = json.NewEncoder(w).Encode(ListUserProfilesResponse{Profiles: []UserProfile{{UserID: "user"}}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	api := &APIClient{serverURL: server.URL, httpClient: server.Client()}
	m := newChatForTest(t, api)
	_, err := m.ensureDirectoryKey()
	if err == nil || err != errDirectoryKeyPending {
		t.Fatalf("expected pending error, got %v", err)
	}
}

func TestChatModelEnsureDirectoryKeyGenerate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/directory/keys":
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/users/profiles":
			_ = json.NewEncoder(w).Encode(ListUserProfilesResponse{Profiles: nil})
		case strings.HasPrefix(r.URL.Path, "/devices/keys"):
			_ = json.NewEncoder(w).Encode(DeviceKeysResponse{Keys: nil})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	api := &APIClient{serverURL: server.URL, httpClient: server.Client()}
	m := newChatForTest(t, api)
	key, err := m.ensureDirectoryKey()
	if err != nil {
		t.Fatalf("ensureDirectoryKey: %v", err)
	}
	if len(key) != crypto.KeySize {
		t.Fatalf("unexpected key size")
	}
}

func TestChatModelEnsureChannelKey(t *testing.T) {
	recipientKP := newTestKeyPair(t)
	senderKP := newTestKeyPair(t)
	key := bytes.Repeat([]byte{3}, crypto.KeySize)
	ct, err := crypto.EncryptForPeer(senderKP.Private, recipientKP.Public, key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/channels/keys" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(ChannelKeyEnvelope{ChannelID: "ch-1", SenderDeviceID: "dev", SenderPublicKey: crypto.PublicKeyToBase64(senderKP.Public), Envelope: ct})
	}))
	defer server.Close()

	api := &APIClient{serverURL: server.URL, httpClient: server.Client()}
	setTestConfigDir(t)
	m := newChatModel(api, newTestAuth(), recipientKP, "passphrase123", 80, 24)
	got, err := m.ensureChannelKey("ch-1")
	if err != nil {
		t.Fatalf("ensureChannelKey: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Fatalf("unexpected key")
	}
}

func TestChatModelLoadChannelHistory(t *testing.T) {
	key := bytes.Repeat([]byte{4}, crypto.KeySize)
	nameEnc, err := encryptChannelField(key, "bob")
	if err != nil {
		t.Fatalf("encryptChannelField: %v", err)
	}
	bodyEnc, err := encryptChannelField(key, "hello")
	if err != nil {
		t.Fatalf("encryptChannelField: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/channels/messages") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(ChannelMessagesResponse{ChannelID: "ch-1", Messages: []ChannelMessageResponse{{ChannelID: "ch-1", SenderID: "user-2", SenderNameEnc: nameEnc, Body: bodyEnc, SentAt: time.Now().UTC().Format(time.RFC3339Nano)}}})
	}))
	defer server.Close()

	api := &APIClient{serverURL: server.URL, httpClient: server.Client()}
	m := newChatForTest(t, api)
	m.setChannelKey("ch-1", key)
	m.loadChannelHistory("ch-1")
	if len(m.channelMsgs["ch-1"]) != 1 {
		t.Fatalf("expected message loaded")
	}
}

func TestChatModelHandleServerMessage(t *testing.T) {
	key := bytes.Repeat([]byte{5}, crypto.KeySize)
	nameEnc, err := encryptChannelField(key, "bob")
	if err != nil {
		t.Fatalf("encryptChannelField: %v", err)
	}
	bodyEnc, err := encryptChannelField(key, "hello")
	if err != nil {
		t.Fatalf("encryptChannelField: %v", err)
	}
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	m.setChannelKey("ch-1", key)
	m.handleServerMessage(ServerMessage{Type: "channel.message.new", ChannelID: "ch-1", Sender: "user-2", SenderNameEnc: nameEnc, Body: bodyEnc, SentAt: time.Now().UTC().Format(time.RFC3339Nano)})
	if len(m.channelMsgs["ch-1"]) != 1 {
		t.Fatalf("expected message appended")
	}
	newNameEnc, _ := encryptChannelField(key, "new")
	m.activeChannel = "ch-1"
	m.channels["ch-1"] = channelInfo{ID: "ch-1", Name: "old"}
	m.handleServerMessage(ServerMessage{Type: "channel.updated", ChannelID: "ch-1", ChannelNameEnc: newNameEnc})
	if m.channels["ch-1"].Name != "new" {
		t.Fatalf("expected channel rename")
	}
	m.handleServerMessage(ServerMessage{Type: "channel.deleted", ChannelID: "ch-1"})
	if m.activeChannel != "" {
		t.Fatalf("expected active channel cleared")
	}
	m.handleServerMessage(ServerMessage{Type: "error", Code: "400", Message: "bad"})
	if m.errMsg == "" {
		t.Fatalf("expected error message")
	}
}

func TestChatModelRenderSidebarAndSelection(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	m.channels["a"] = channelInfo{ID: "a", Name: "alpha"}
	m.channels["b"] = channelInfo{ID: "b", Name: "beta"}
	m.activeChannel = "a"
	m.channelUnread["b"] = 2
	out := m.renderSidebar()
	if !strings.Contains(out, "alpha") || !strings.Contains(out, "(2)") {
		t.Fatalf("unexpected sidebar output")
	}

	m.sidebarMode = sidebarUsers
	m.userNames["user-1"] = "alice"
	m.userAdmins["user-1"] = true
	m.userPresence["user-1"] = true
	m.channelMsgs["a"] = []chatMessage{{sender: "user-1", senderName: "alice"}}
	out = m.renderSidebar()
	if !strings.Contains(out, "admin") {
		t.Fatalf("expected admin label")
	}
}

func TestChatModelChannelLists(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	m.channels["b"] = channelInfo{ID: "b", Name: "beta"}
	m.channels["a"] = channelInfo{ID: "a", Name: "alpha"}
	list := m.channelList()
	if list[0].ID != "a" {
		t.Fatalf("unexpected channel sort")
	}

	m.channelMsgs["a"] = []chatMessage{{sender: "user-2", senderName: "bob"}}
	entries := m.channelUserEntries("a")
	if len(entries) != 1 || entries[0].ID != "user-2" {
		t.Fatalf("unexpected user entries")
	}
	ids := m.channelUserIDs("a")
	if len(ids) != 1 || ids[0] != "user-2" {
		t.Fatalf("unexpected user ids")
	}

	all := m.allUserEntries()
	if len(all) == 0 {
		t.Fatalf("expected user entries")
	}
	allIDs := m.allUserIDs()
	if len(allIDs) == 0 {
		t.Fatalf("expected user ids")
	}
}

func TestChatModelRenderChannelSelectionModal(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	m.selectOptions = []channelInfo{{ID: "a", Name: "alpha"}, {ID: "b", Name: "beta"}}
	m.selectIndex = 1
	m.width = 60
	out := m.renderChannelSelectionModal()
	if !strings.Contains(out, "Select a channel") {
		t.Fatalf("unexpected modal output")
	}
}

func TestChatModelHelpers(t *testing.T) {
	if formatTime("invalid") != "invalid" {
		t.Fatalf("expected passthrough time")
	}
	if shortID("123456789") != "12345678" {
		t.Fatalf("unexpected shortID")
	}
	if clampMin(2, 3) != 3 {
		t.Fatalf("unexpected clampMin")
	}
	if trimLine("hello", 3) != "hel" {
		t.Fatalf("unexpected trimLine")
	}
	lines := formatMessageLines("12:00", "bob", "hello world", 20, false)
	if len(lines) == 0 {
		t.Fatalf("expected formatted lines")
	}
	wrapped := wrapText("a b c", 1)
	if len(wrapped) == 0 {
		t.Fatalf("expected wrapped text")
	}
	chunks := chunkText("abcdef", 2)
	if len(chunks) != 3 {
		t.Fatalf("unexpected chunks")
	}
	if isNotFoundErr(context.Canceled) {
		t.Fatalf("expected not found false")
	}
	if !isNotFoundErr(errors.New("not found")) {
		t.Fatalf("expected not found true")
	}
}

func TestChatModelEncryptDecryptFields(t *testing.T) {
	key := bytes.Repeat([]byte{9}, crypto.KeySize)
	encoded, err := encryptChannelField(key, "hello")
	if err != nil {
		t.Fatalf("encryptChannelField: %v", err)
	}
	value, err := decryptFieldWithKey(key, encoded)
	if err != nil {
		t.Fatalf("decryptFieldWithKey: %v", err)
	}
	if value != "hello" {
		t.Fatalf("unexpected value")
	}

	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	m.setChannelKey("ch", key)
	if m.decryptChannelField("ch", encoded) != "hello" {
		t.Fatalf("unexpected channel decrypt")
	}
	if m.decryptChannelField("missing", encoded) != "<encrypted>" {
		t.Fatalf("expected encrypted placeholder")
	}
	m.directoryKey = key
	if m.decryptDirectoryName(encoded) != "hello" {
		t.Fatalf("unexpected directory decrypt")
	}
	if m.decryptChannelName("missing", "") != "<encrypted>" {
		t.Fatalf("expected encrypted channel name")
	}
}

func TestChatModelSelectionAndSidebarMovement(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	m.channels["a"] = channelInfo{ID: "a", Name: "alpha"}
	m.channels["b"] = channelInfo{ID: "b", Name: "beta"}
	m.moveSidebarSelection(1)
	if m.sidebarIndex != 1 {
		t.Fatalf("expected sidebar index 1")
	}
	m.channelHistoryLoaded["b"] = true
	if !m.selectSidebarChannel() {
		t.Fatalf("expected selection")
	}
	if m.activeChannel != "b" {
		t.Fatalf("expected active channel")
	}
}

func TestChatModelChannelSelectionKeyHandling(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	m.selectOptions = []channelInfo{{ID: "a", Name: "alpha"}, {ID: "b", Name: "beta"}}
	m.selectActive = true
	m.handleChannelSelectKey(tea.KeyMsg{Type: tea.KeyDown})
	if m.selectIndex != 1 {
		t.Fatalf("expected select index 1")
	}
	m.channelHistoryLoaded["b"] = true
	m.handleChannelSelectKey(tea.KeyMsg{Type: tea.KeyEnter})
	if m.selectActive {
		t.Fatalf("expected selection done")
	}
}
