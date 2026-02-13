package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"nhooyr.io/websocket"

	"github.com/Avicted/dialtone/internal/crypto"
	"github.com/Avicted/dialtone/internal/ipc"
)

func newChatForTest(t *testing.T, api *APIClient) chatModel {
	t.Helper()
	setTestConfigDir(t)
	auth := newTestAuth()
	kp := newTestKeyPair(t)
	return newChatModel(api, auth, kp, "passphrase123", 80, 24, "")
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
	m := newChatModel(api, newTestAuth(), recipientKP, "passphrase123", 80, 24, "")
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
	m.voiceRoom = "b"
	m.resetVoiceMembersForRoom("b")
	m.voiceSpeaking[m.auth.UserID] = true
	m.channelUnread["b"] = 2
	out := m.renderSidebar()
	if !strings.Contains(out, "Channels") || !strings.Contains(out, "Users") {
		t.Fatalf("expected channels and users sections")
	}
	if !strings.Contains(out, "In Voice") {
		t.Fatalf("expected in-voice section")
	}
	if strings.Index(out, "Channels") > strings.Index(out, "Users") {
		t.Fatalf("expected channels above users")
	}
	if !strings.Contains(out, "alpha") || !strings.Contains(out, "(2)") {
		t.Fatalf("unexpected sidebar output")
	}
	if strings.Contains(out, "♪ beta") {
		t.Fatalf("did not expect voice marker on joined channel")
	}
	if !strings.Contains(out, "+ <"+m.auth.Username+">") {
		t.Fatalf("expected speaking marker in in-voice section")
	}

	m.userNames["user-1"] = "alice"
	m.userAdmins["user-1"] = true
	m.userPresence["user-1"] = true
	m.voiceSpeaking["user-1"] = true
	m.channelMsgs["a"] = []chatMessage{{sender: "user-1", senderName: "alice"}}
	out = m.renderSidebar()
	if !strings.Contains(out, "admin") || !strings.Contains(out, "alpha") {
		t.Fatalf("expected admin label")
	}
	usersIdx := strings.Index(out, "Users")
	if usersIdx == -1 {
		t.Fatalf("expected users section")
	}
	if strings.Contains(out[usersIdx:], "+ <alice>") {
		t.Fatalf("did not expect speaking marker in users section")
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
	m := newChatModel(api, newTestAuth(), recipientKP, "passphrase123", 80, 24, "")
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
	m := newChatModel(api, newTestAuth(), newTestKeyPair(t), "passphrase123", 80, 24, "")
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

func TestChatModelUpdateCtrlLTogglesSidebar(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	m.sidebarVisible = true
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyCtrlL})
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

func TestBuildDirectoryKeyEnvelopesSuccessAndValidation(t *testing.T) {
	sender := newTestKeyPair(t)
	recipient := newTestKeyPair(t)
	key := bytes.Repeat([]byte{9}, crypto.KeySize)

	envelopes, err := buildDirectoryKeyEnvelopes(sender, "dev-1", key, []DeviceKey{
		{},
		{DeviceID: "dev-2", PublicKey: crypto.PublicKeyToBase64(recipient.Public)},
	})
	if err != nil {
		t.Fatalf("buildDirectoryKeyEnvelopes: %v", err)
	}
	if len(envelopes) != 1 {
		t.Fatalf("expected exactly one envelope, got %d", len(envelopes))
	}
	if envelopes[0].DeviceID != "dev-2" || envelopes[0].SenderDeviceID != "dev-1" {
		t.Fatalf("unexpected envelope metadata: %+v", envelopes[0])
	}

	decrypted, err := crypto.DecryptFromPeer(recipient.Private, sender.Public, envelopes[0].Envelope)
	if err != nil {
		t.Fatalf("decrypt envelope: %v", err)
	}
	if !bytes.Equal(decrypted, key) {
		t.Fatalf("unexpected decrypted key")
	}

	if _, err := buildDirectoryKeyEnvelopes(sender, "dev-1", key, []DeviceKey{{DeviceID: "dev-x", PublicKey: "invalid"}}); err == nil {
		t.Fatalf("expected invalid device public key error")
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

func TestChatModelVoiceStatusLabel(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	if got := m.voiceStatusLabel(); got != "voice: off" {
		t.Fatalf("unexpected status: %s", got)
	}

	m.channels["ch-1"] = channelInfo{ID: "ch-1", Name: "general"}
	m.voiceRoom = "ch-1"
	if got := m.voiceStatusLabel(); got != "voice: general" {
		t.Fatalf("unexpected connected status: %s", got)
	}

	joinCmd := ipc.Message{Cmd: ipc.CommandVoiceJoin, Room: "ch-2"}
	m.channels["ch-2"] = channelInfo{ID: "ch-2", Name: "voice-lobby"}
	m.voicePendingCmd = &joinCmd
	m.voicePendingRoom = "ch-2"
	m.voiceRoom = ""
	if got := m.voiceStatusLabel(); got != "voice: connecting voice-lobby" {
		t.Fatalf("unexpected connecting status: %s", got)
	}

	m.voicePendingCmd = nil
	m.voicePendingRoom = ""
	m.voiceReconnectAttempt = 1
	m.voiceCh = nil
	if got := m.voiceStatusLabel(); got != "voice: reconnecting" {
		t.Fatalf("unexpected reconnect status: %s", got)
	}

	m.voiceReconnectAttempt = 0
	m.voiceRoom = "ch-1"
	leaveCmd := ipc.Message{Cmd: ipc.CommandVoiceLeave}
	m.voicePendingCmd = &leaveCmd
	if got := m.voiceStatusLabel(); got != "voice: leaving general" {
		t.Fatalf("unexpected leaving status: %s", got)
	}

	m.voicePendingCmd = &ipc.Message{Cmd: ipc.CommandMute}
	if got := m.voiceStatusLabel(); got != "voice: general" {
		t.Fatalf("unexpected updating status with active room: %s", got)
	}

	m.voicePendingCmd = nil
	m.voiceRoom = ""
	m.voiceAutoStarting = true
	m.voicePendingRoom = "ch-2"
	if got := m.voiceStatusLabel(); got != "voice: starting" {
		t.Fatalf("unexpected starting status: %s", got)
	}
}

func TestChatModelViewIncludesVoiceStatus(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	if out := m.View(); !strings.Contains(out, "voice: off") {
		t.Fatalf("expected default voice status in header")
	}

	m.channels["ch-1"] = channelInfo{ID: "ch-1", Name: "general"}
	m.voiceRoom = "ch-1"
	if out := m.View(); !strings.Contains(out, "voice: general") {
		t.Fatalf("expected connected voice status in header")
	}
}

func TestChatModelViewUsesSingleInputPrompt(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	out := m.View()
	if strings.Contains(out, "  > >") {
		t.Fatalf("expected single input prompt")
	}
}

func TestChatModelHandleVoiceMembersEvent(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	m.channels["ch-1"] = channelInfo{ID: "ch-1", Name: "general"}
	m.voiceRoom = "ch-1"
	m.handleVoiceEvent(ipc.Message{Event: ipc.EventVoiceMembers, Room: "ch-1", Users: []string{"user-2"}})

	if !m.voiceMembers["user-2"] {
		t.Fatalf("expected remote voice member")
	}
	if !m.voiceMembers[m.auth.UserID] {
		t.Fatalf("expected local user included in voice members")
	}

	m.handleVoiceEvent(ipc.Message{Event: ipc.EventVoiceMembers, Room: "other-room", Users: []string{"user-3"}})
	if m.voiceMembers["user-3"] {
		t.Fatalf("expected stale room roster ignored")
	}

	out := m.renderSidebar()
	if !strings.Contains(out, "In Voice") || strings.Contains(out, "(you)") {
		t.Fatalf("expected in-voice roster rendering without self label")
	}
}

func TestChatModelRenderSidebarServerVoicePresence(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	m.channels["ch-1"] = channelInfo{ID: "ch-1", Name: "general"}
	m.userNames["user-2"] = "bobross"
	m.userPresence["user-2"] = true
	inVoiceSection := func(sidebar string) string {
		start := strings.Index(sidebar, "In Voice")
		if start == -1 {
			return ""
		}
		section := sidebar[start:]
		if end := strings.Index(section, "Users"); end != -1 {
			section = section[:end]
		}
		return section
	}

	m.handleServerMessage(ServerMessage{
		Type:       "voice.presence.snapshot",
		VoiceRooms: map[string][]string{"ch-1": {"user-2"}},
	})
	out := m.renderSidebar()
	inVoice := inVoiceSection(out)
	if !strings.Contains(inVoice, "In Voice") || !strings.Contains(inVoice, "general") || !strings.Contains(inVoice, "<bobross>") {
		t.Fatalf("expected server voice presence in sidebar")
	}
	if strings.Contains(inVoice, "(not connected)") {
		t.Fatalf("unexpected disconnected placeholder when server presence exists")
	}

	m.handleServerMessage(ServerMessage{Type: "voice.presence", ChannelID: "ch-1", Sender: "user-2", Active: false})
	out = m.renderSidebar()
	inVoice = inVoiceSection(out)
	if strings.Contains(inVoice, "<bobross>") {
		t.Fatalf("expected member removed after inactive update")
	}
	if !strings.Contains(inVoice, "(not connected)") {
		t.Fatalf("expected disconnected placeholder when no server presence remains")
	}
}

func TestChatModelRenderSidebarShowsAllVoiceRoomsWhileJoined(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	m.channels["ch-1"] = channelInfo{ID: "ch-1", Name: "general"}
	m.channels["ch-2"] = channelInfo{ID: "ch-2", Name: "support"}
	m.userNames["user-2"] = "bobross"
	m.userNames["user-3"] = "alice"
	m.userPresence["user-2"] = true
	m.userPresence["user-3"] = true

	m.voiceRoom = "ch-1"
	m.resetVoiceMembersForRoom("ch-1")
	m.voiceMembers["user-2"] = true
	m.voiceSpeaking["user-2"] = true

	m.handleServerMessage(ServerMessage{
		Type: "voice.presence.snapshot",
		VoiceRooms: map[string][]string{
			"ch-1": {"user-2"},
			"ch-2": {"user-3"},
		},
	})

	out := m.renderSidebar()
	if !strings.Contains(out, "general") || !strings.Contains(out, "support") {
		t.Fatalf("expected all voice rooms rendered while joined")
	}
	if !strings.Contains(out, "+ <bobross>") {
		t.Fatalf("expected speaking marker in joined room")
	}
	if strings.Contains(out, "+ <alice>") {
		t.Fatalf("expected no speaking marker in non-joined room")
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

func TestChatModelHandleVoiceInfoEvent(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	m.handleVoiceEvent(ipc.Message{Event: ipc.EventInfo, Error: "ptt startup mode=auto wayland=true portal=available selected=portal"})
	if !strings.Contains(lastSystemMessage(m), "voice info: ptt startup mode=auto") {
		t.Fatalf("expected voice info message shown to user")
	}
}

func TestChatModelHandleVoiceEventAdditionalPaths(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	m.channels["ch-1"] = channelInfo{ID: "ch-1", Name: "general"}
	m.voiceRoom = "ch-1"
	m.voiceMembers["u2"] = true

	m.handleVoiceEvent(ipc.Message{Event: ipc.EventVoiceReady, Room: "ch-1"})
	if m.voiceRoom != "" {
		t.Fatalf("expected voice room cleared on ready event for same room")
	}
	if len(m.voiceMembers) != 0 {
		t.Fatalf("expected voice members cleared on ready event")
	}

	m.handleVoiceEvent(ipc.Message{Event: ipc.EventVoiceConnected, Room: "ch-1"})
	if m.voiceRoom != "ch-1" {
		t.Fatalf("expected connected room to be set")
	}
	if !m.voiceMembers[m.auth.UserID] {
		t.Fatalf("expected local user added to voice members on connect")
	}

	m.voiceSpeaking = nil
	m.handleVoiceEvent(ipc.Message{Event: ipc.EventUserSpeaking, User: "", Active: true})
	if m.voiceSpeaking != nil {
		t.Fatalf("expected empty user speaking event to be ignored")
	}
	m.handleVoiceEvent(ipc.Message{Event: ipc.EventUserSpeaking, User: "u2", Active: true})
	if m.voiceSpeaking == nil || !m.voiceSpeaking["u2"] {
		t.Fatalf("expected speaking map initialized and updated")
	}

	before := len(m.messages)
	m.voiceAutoStarting = true
	m.handleVoiceEvent(ipc.Message{Event: ipc.EventError, Error: "dial unix /tmp/dialtone-voice.sock: connect: no such file or directory"})
	if len(m.messages) != before {
		t.Fatalf("expected IPC-not-running error to be suppressed while auto-starting")
	}

	m.voiceAutoStarting = false
	m.handleVoiceEvent(ipc.Message{Event: ipc.EventError, Error: "boom"})
	if !strings.Contains(lastSystemMessage(m), "voice error: boom") {
		t.Fatalf("expected voice error message")
	}

	before = len(m.messages)
	m.handleVoiceEvent(ipc.Message{Event: ipc.EventPong})
	if len(m.messages) != before {
		t.Fatalf("expected pong event to be ignored")
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
	m.sidebarVisible = true
	updated, cmd := m.Update(presenceTick{})
	if cmd == nil {
		t.Fatalf("expected presence tick cmd")
	}
	if !updated.userPresence["u1"] {
		t.Fatalf("expected presence set")
	}
}

func TestChatModelRenderSidebarNotTrustedNoChannel(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	m.auth.IsTrusted = false
	if out := m.renderSidebar(); !strings.Contains(out, "(no channel)") || !strings.Contains(out, "Channels") {
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
	m := newChatModel(api, newTestAuth(), recipientKP, "passphrase123", 80, 24, "")
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

func TestChatModelConnectWS(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ws" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") != "Bearer token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close(websocket.StatusNormalClosure, "done")
	}))
	defer server.Close()

	api := &APIClient{serverURL: server.URL, httpClient: server.Client()}
	m := newChatModel(api, newTestAuth(), newTestKeyPair(t), "passphrase123", 80, 24, "")
	cmd := m.connectWS()
	msg := cmd()
	connected, ok := msg.(wsConnectedMsg)
	if !ok || connected.ws == nil {
		t.Fatalf("expected wsConnectedMsg")
	}
	connected.ws.Close()
}

func TestChatModelUpdateWindowAndPaging(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	updated, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 40})
	if updated.width != 100 || updated.height != 40 {
		t.Fatalf("unexpected size")
	}
	_, _ = updated.Update(tea.KeyMsg{Type: tea.KeyPgUp})
}

func TestChatModelUpdateCtrlUDoesNotToggleSidebar(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	m.sidebarVisible = true
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyCtrlU})
	if !updated.sidebarVisible {
		t.Fatalf("expected sidebar to remain visible")
	}
}

func TestChatModelUpdateShareAndRefreshTicks(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/channels":
			_ = json.NewEncoder(w).Encode(ListChannelsResponse{Channels: []ChannelResponse{{ID: "ch-1", NameEnc: ""}}})
		case "/channels/keys":
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(apiError{Error: "missing"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	api := &APIClient{serverURL: server.URL, httpClient: server.Client()}
	m := newChatForTest(t, api)
	m.connected = true
	_, cmd := m.Update(shareTick{})
	if cmd == nil {
		t.Fatalf("expected share tick cmd")
	}

	m.channelRefreshNeeded = true
	m.channelRefreshRetries = 0
	updated, cmd := m.Update(channelRefreshTick{})
	if cmd == nil || updated.channelRefreshRetries != 1 {
		t.Fatalf("expected refresh retry")
	}

	resetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/channels" {
			_ = json.NewEncoder(w).Encode(ListChannelsResponse{Channels: nil})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer resetServer.Close()

	updated.api = &APIClient{serverURL: resetServer.URL, httpClient: resetServer.Client()}
	updated.channelRefreshNeeded = false
	updated, _ = updated.Update(channelRefreshTick{})
	if updated.channelRefreshRetries != 0 {
		t.Fatalf("expected retries reset")
	}
}

func TestChatModelUpdateUserProfileUpdated(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	updated, cmd := m.Update(wsMessageMsg(ServerMessage{Type: "user.profile.updated"}))
	if cmd == nil {
		t.Fatalf("expected sync command")
	}
	if updated.errMsg != "" {
		t.Fatalf("unexpected error")
	}
}

func TestChatModelUpdateDirectoryTickUntrusted(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	m.auth.IsTrusted = false
	_, cmd := m.Update(directoryTick{})
	if cmd != nil {
		t.Fatalf("expected no command")
	}
}

func TestChatModelAppendHighlightedMessage(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	m.appendHighlightedMessage("token")
	if len(m.messages) != 1 || !m.messages[0].highlight {
		t.Fatalf("expected highlighted message")
	}
}

func TestChatModelHandleCommandAdminErrors(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	m.auth.IsAdmin = true
	m.handleCommand("/server")
	if !strings.Contains(lastSystemMessage(m), "server commands") {
		t.Fatalf("expected server help")
	}
	m.handleCommand("/server unknown")
	if lastSystemMessage(m) != "unknown server command" {
		t.Fatalf("unexpected message: %s", lastSystemMessage(m))
	}
	m.handleCommand("/channel")
	if !strings.Contains(lastSystemMessage(m), "channel commands") {
		t.Fatalf("expected channel help")
	}
	m.handleCommand("/channel rename")
	if !strings.Contains(lastSystemMessage(m), "usage: /channel rename") {
		t.Fatalf("expected rename usage")
	}
	m.handleCommand("/channel delete")
	if !strings.Contains(lastSystemMessage(m), "usage: /channel delete") {
		t.Fatalf("expected delete usage")
	}
	m.handleCommand("/channel create")
	if !strings.Contains(lastSystemMessage(m), "usage: /channel create") {
		t.Fatalf("expected create usage")
	}
	m.handleCommand("/unknown")
	if lastSystemMessage(m) != "unknown command" {
		t.Fatalf("unexpected message: %s", lastSystemMessage(m))
	}
}

func TestChatModelSendCurrentMessageCommand(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	m.connected = true
	m.ws = &WSClient{closed: true}
	m.input.SetValue("/help")
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if !strings.Contains(lastSystemMessage(updated), "commands") {
		t.Fatalf("expected help message")
	}
	if updated.input.Value() != "" {
		t.Fatalf("expected input reset")
	}
}

func TestChatModelSendCurrentMessageChannel(t *testing.T) {
	key := bytes.Repeat([]byte{4}, crypto.KeySize)
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	m.connected = true
	m.ws = &WSClient{closed: true}
	m.activeChannel = "ch-1"
	m.setChannelKey("ch-1", key)
	m.input.SetValue("hello")
	m.sendCurrentMessage()
	if m.input.Value() != "" {
		t.Fatalf("expected input reset")
	}
}

func TestChatModelScheduleTicks(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	originalTeaTick := teaTick
	durations := make([]time.Duration, 0, 5)
	teaTick = func(delay time.Duration, callback func(time.Time) tea.Msg) tea.Cmd {
		durations = append(durations, delay)
		return func() tea.Msg {
			return callback(time.Now())
		}
	}
	t.Cleanup(func() {
		teaTick = originalTeaTick
	})

	if cmd := m.scheduleDirectoryTick(); cmd == nil {
		t.Fatalf("expected directory tick cmd")
	} else if _, ok := cmd().(directoryTick); !ok {
		t.Fatalf("expected directoryTick message")
	}
	if cmd := m.schedulePresenceTick(); cmd == nil {
		t.Fatalf("expected presence tick cmd")
	} else if _, ok := cmd().(presenceTick); !ok {
		t.Fatalf("expected presenceTick message")
	}
	if cmd := m.scheduleVoicePing(); cmd == nil {
		t.Fatalf("expected voice ping cmd")
	} else if _, ok := cmd().(voicePingTick); !ok {
		t.Fatalf("expected voicePingTick message")
	}
	if cmd := m.scheduleShareTick(); cmd == nil {
		t.Fatalf("expected share tick cmd")
	} else if _, ok := cmd().(shareTick); !ok {
		t.Fatalf("expected shareTick message")
	}
	if cmd := m.scheduleChannelRefresh(); cmd == nil {
		t.Fatalf("expected channel refresh cmd")
	} else if _, ok := cmd().(channelRefreshTick); !ok {
		t.Fatalf("expected channelRefreshTick message")
	}

	expectedDurations := []time.Duration{10 * time.Second, 5 * time.Second, 15 * time.Second, shareKeysInterval, channelRefreshDelay}
	if len(durations) != len(expectedDurations) {
		t.Fatalf("captured durations length=%d want=%d", len(durations), len(expectedDurations))
	}
	for index := range expectedDurations {
		if durations[index] != expectedDurations[index] {
			t.Fatalf("duration[%d]=%s want=%s", index, durations[index], expectedDurations[index])
		}
	}
}

func TestChatModelDirectoryKeyHelpers(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	m.setDirectoryKey([]byte{1, 2, 3})
	if len(m.directoryKey) != 0 {
		t.Fatalf("expected directory key unchanged")
	}
	if got := m.decryptDirectoryName("abc"); got != "" {
		t.Fatalf("expected empty directory name")
	}
}

func TestChatModelVoicePendingCommandRetainedOnSendFailure(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	m.voiceIPC = &voiceIPC{addr: ""}
	m.voiceRoom = "room-1"
	leaveCmd := ipc.Message{Cmd: ipc.CommandVoiceLeave, Room: "room-1"}
	m.queueVoiceCommand(leaveCmd, "", "voice leave requested")

	updated, cmd := m.Update(voiceIPCConnectedMsg{ch: make(chan ipc.Message, 1)})
	if cmd == nil {
		t.Fatalf("expected reconnect command")
	}
	if updated.voicePendingCmd == nil {
		t.Fatalf("expected pending voice command to remain queued")
	}
	if updated.voicePendingCmd.Cmd != ipc.CommandVoiceLeave {
		t.Fatalf("expected leave command to remain queued")
	}
	if updated.voiceReconnectAttempt != 1 {
		t.Fatalf("expected reconnect attempt incremented, got %d", updated.voiceReconnectAttempt)
	}
	if updated.voiceRoom != "room-1" {
		t.Fatalf("expected voice room unchanged before leave ack")
	}
	if !strings.Contains(lastSystemMessage(updated), "voice command pending (retrying)") {
		t.Fatalf("expected retry notice message")
	}
}

func TestChatModelDispatchVoiceLeaveDoesNotClearRoomBeforeAck(t *testing.T) {
	addr := filepath.Join(t.TempDir(), "voice.sock")
	listener, err := ipc.Listen(addr)
	if err != nil {
		t.Fatalf("listen voice ipc: %v", err)
	}
	defer listener.Close()

	recv := make(chan ipc.Message, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		dec := ipc.NewDecoder(conn)
		var msg ipc.Message
		if err := dec.Decode(&msg); err == nil {
			recv <- msg
		}
	}()

	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	m.voiceIPC = newVoiceIPC(addr)
	m.voiceCh = make(chan ipc.Message, 1)
	m.voiceRoom = "room-1"

	cmd := m.dispatchVoiceCommand(
		ipc.Message{Cmd: ipc.CommandVoiceLeave, Room: m.voiceRoom},
		"",
		"voice leave requested",
		"voice leave",
	)
	if cmd != nil {
		t.Fatalf("expected no reconnect command on successful send")
	}
	if m.voiceRoom != "room-1" {
		t.Fatalf("expected voice room unchanged until daemon ready event")
	}

	select {
	case msg := <-recv:
		if msg.Cmd != ipc.CommandVoiceLeave || msg.Room != "room-1" {
			t.Fatalf("unexpected ipc message: %+v", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for leave command on ipc")
	}
}

func TestWaitForVoiceMsg(t *testing.T) {
	ch := make(chan ipc.Message, 1)
	ch <- ipc.Message{Event: ipc.EventPong}

	msg := waitForVoiceMsg(ch)()
	voiceMsg, ok := msg.(voiceIPCMsg)
	if !ok {
		t.Fatalf("expected voiceIPCMsg, got %T", msg)
	}
	if ipc.Message(voiceMsg).Event != ipc.EventPong {
		t.Fatalf("expected pong event, got %#v", ipc.Message(voiceMsg))
	}

	closed := make(chan ipc.Message)
	close(closed)
	msg = waitForVoiceMsg(closed)()
	errMsg, ok := msg.(voiceIPCErrorMsg)
	if !ok {
		t.Fatalf("expected voiceIPCErrorMsg, got %T", msg)
	}
	if !strings.Contains(errMsg.err.Error(), "voice daemon disconnected") {
		t.Fatalf("unexpected disconnect error: %v", errMsg.err)
	}
}

func TestChatModelConnectVoiceIPC(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	m.voiceIPC = nil
	if cmd := m.connectVoiceIPC(); cmd != nil {
		t.Fatalf("expected nil connect command when voice IPC is not configured")
	}

	m.voiceIPC = newVoiceIPC("")
	cmd := m.connectVoiceIPC()
	if cmd == nil {
		t.Fatalf("expected connect command")
	}
	msg := cmd()
	errMsg, ok := msg.(voiceIPCErrorMsg)
	if !ok {
		t.Fatalf("expected voiceIPCErrorMsg for invalid address, got %T", msg)
	}
	if !strings.Contains(errMsg.err.Error(), "voice ipc address is empty") {
		t.Fatalf("unexpected connect error: %v", errMsg.err)
	}

	addr := filepath.Join(t.TempDir(), "voice.sock")
	listener, err := ipc.Listen(addr)
	if err != nil {
		t.Fatalf("listen voice ipc: %v", err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		_ = conn.Close()
	}()

	m.voiceIPC = newVoiceIPC(addr)
	cmd = m.connectVoiceIPC()
	msg = cmd()
	connected, ok := msg.(voiceIPCConnectedMsg)
	if !ok {
		t.Fatalf("expected voiceIPCConnectedMsg, got %T", msg)
	}
	if connected.ch == nil {
		t.Fatalf("expected non-nil voice IPC channel")
	}
}

func TestChatModelHandleVoiceCommandPaths(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	if cmd := m.handleVoiceCommand("/voice", []string{"/voice"}); cmd != nil {
		t.Fatalf("expected no command for usage help")
	}
	if !strings.Contains(lastSystemMessage(m), "voice commands") {
		t.Fatalf("expected voice help message")
	}

	m.voiceIPC = nil
	if cmd := m.handleVoiceCommand("/voice mute", []string{"/voice", "mute"}); cmd != nil {
		t.Fatalf("expected no command when voice IPC is nil")
	}
	if !strings.Contains(lastSystemMessage(m), "voice daemon not configured") {
		t.Fatalf("expected missing daemon message")
	}

	m.voiceIPC = &voiceIPC{addr: ""}
	m.voiceRoom = "room-1"
	_ = m.handleVoiceCommand("/voice leave", []string{"/voice", "leave"})
	if !strings.Contains(lastSystemMessage(m), "voice leave failed") {
		t.Fatalf("expected leave failure message")
	}
	_ = m.handleVoiceCommand("/voice mute", []string{"/voice", "mute"})
	if !strings.Contains(lastSystemMessage(m), "voice mute failed") {
		t.Fatalf("expected mute failure message")
	}
	_ = m.handleVoiceCommand("/voice unmute", []string{"/voice", "unmute"})
	if !strings.Contains(lastSystemMessage(m), "voice unmute failed") {
		t.Fatalf("expected unmute failure message")
	}

	addr := filepath.Join(t.TempDir(), "voice.sock")
	listener, err := ipc.Listen(addr)
	if err != nil {
		t.Fatalf("listen voice ipc: %v", err)
	}
	defer listener.Close()

	recv := make(chan ipc.Message, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var msg ipc.Message
		if err := ipc.NewDecoder(conn).Decode(&msg); err == nil {
			recv <- msg
		}
	}()

	m.voiceIPC = newVoiceIPC(addr)
	m.voiceCh = make(chan ipc.Message, 1)
	m.channels["ch-1"] = channelInfo{ID: "ch-1", Name: "general"}
	m.activeChannel = "ch-1"

	if cmd := m.handleVoiceCommand("/voice join", []string{"/voice", "join"}); cmd != nil {
		t.Fatalf("expected no reconnect cmd when voice channel already connected")
	}
	if m.voiceRoom != "ch-1" {
		t.Fatalf("expected voice room set to joined channel, got %q", m.voiceRoom)
	}
	if !strings.Contains(lastSystemMessage(m), "voice join requested") {
		t.Fatalf("expected join notice")
	}

	select {
	case sent := <-recv:
		if sent.Cmd != ipc.CommandVoiceJoin || sent.Room != "ch-1" {
			t.Fatalf("unexpected join IPC message: %#v", sent)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for join message")
	}
}

func TestChatModelVoiceHelperMethods(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})

	pending := ipc.Message{Cmd: ipc.CommandVoiceJoin, Room: "room-1"}
	m.queueVoiceCommand(pending, "room-1", "queued")
	m.clearPendingVoiceCommand()
	if m.voicePendingCmd != nil || m.voicePendingRoom != "" || m.voicePendingNotice != "" {
		t.Fatalf("expected pending voice command state to be cleared")
	}

	if cmd := m.scheduleVoicePing(); cmd == nil {
		t.Fatalf("expected non-nil voice ping schedule command")
	}

	m.voiceMembers = nil
	m.clearVoiceMembers()
	if m.voiceMembers == nil {
		t.Fatalf("expected voiceMembers map initialized")
	}
	m.voiceMembers["user-1"] = true
	m.clearVoiceMembers()
	if len(m.voiceMembers) != 0 {
		t.Fatalf("expected voiceMembers map cleared")
	}
}

func TestChatModelDispatchVoiceCommandAutoStartPaths(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	m.voiceAutoStart = true
	m.voiceIPCAddr = filepath.Join(t.TempDir(), "missing.sock")
	m.voiceIPC = newVoiceIPC(m.voiceIPCAddr)
	m.voicedPath = "/bin/true"
	m.channels["ch-1"] = channelInfo{ID: "ch-1", Name: "general"}

	cmd := m.dispatchVoiceCommand(
		ipc.Message{Cmd: ipc.CommandVoiceJoin, Room: "ch-1"},
		"ch-1",
		"voice join requested",
		"voice join",
	)
	if cmd == nil {
		t.Fatalf("expected reconnect command when auto-start queues voice command")
	}
	if m.voicePendingCmd == nil || m.voicePendingCmd.Cmd != ipc.CommandVoiceJoin {
		t.Fatalf("expected pending join command to be queued")
	}
	if m.voicePendingRoom != "ch-1" {
		t.Fatalf("expected pending room ch-1, got %q", m.voicePendingRoom)
	}
	if !strings.Contains(lastSystemMessage(m), "starting voice daemon") {
		t.Fatalf("expected auto-start notice")
	}

	m.stopVoiceDaemon()

	m2 := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	m2.voiceAutoStart = true
	m2.voiceIPCAddr = filepath.Join(t.TempDir(), "missing.sock")
	m2.voiceIPC = newVoiceIPC(m2.voiceIPCAddr)
	m2.voicedPath = filepath.Join(t.TempDir(), "does-not-exist")

	cmd = m2.dispatchVoiceCommand(
		ipc.Message{Cmd: ipc.CommandMute},
		"",
		"voice mute requested",
		"voice mute",
	)
	if cmd != nil {
		t.Fatalf("expected no command when auto-start fails")
	}
	if !strings.Contains(lastSystemMessage(m2), "voice auto-start failed") {
		t.Fatalf("expected auto-start failure message")
	}
}

func TestChatModelCommandClosures(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	m.auth.IsTrusted = true
	m.api = nil

	cmd := m.syncDirectoryCmd(true)
	if cmd == nil {
		t.Fatalf("expected syncDirectoryCmd when trusted")
	}
	if _, ok := cmd().(directorySyncMsg); !ok {
		t.Fatalf("expected directorySyncMsg from syncDirectoryCmd")
	}

	m.channelKeys["ch-1"] = bytes.Repeat([]byte{1}, crypto.KeySize)
	m.auth = nil
	m.kp = nil
	cmd = m.shareKnownChannelKeysCmd()
	if cmd == nil {
		t.Fatalf("expected shareKnownChannelKeysCmd when channel keys are present")
	}
	if _, ok := cmd().(shareKeysMsg); !ok {
		t.Fatalf("expected shareKeysMsg from shareKnownChannelKeysCmd")
	}
}

func TestChatModelShareDirectoryKeyCmdGuards(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	m.auth.IsTrusted = false
	if cmd := m.shareDirectoryKeyCmd(); cmd != nil {
		t.Fatalf("expected nil cmd when user is not trusted")
	}

	m.auth.IsTrusted = true
	m.directoryKey = nil
	if cmd := m.shareDirectoryKeyCmd(); cmd != nil {
		t.Fatalf("expected nil cmd without directory key")
	}

	m.directoryKey = bytes.Repeat([]byte{7}, crypto.KeySize)
	m.api = nil
	m.kp = nil
	cmd := m.shareDirectoryKeyCmd()
	if cmd == nil {
		t.Fatalf("expected cmd when trusted and directory key exists")
	}
	msg := cmd()
	result, ok := msg.(shareDirectoryMsg)
	if !ok {
		t.Fatalf("expected shareDirectoryMsg, got %T", msg)
	}
	if result.err != nil {
		t.Fatalf("expected nil error when shareDirectoryKey short-circuits missing deps, got %v", result.err)
	}
}

func TestChatModelResolveChannelAdditionalPaths(t *testing.T) {
	key := bytes.Repeat([]byte{6}, crypto.KeySize)
	nameEnc, err := encryptChannelField(key, "general")
	if err != nil {
		t.Fatalf("encryptChannelField: %v", err)
	}

	t.Run("direct-map-hit", func(t *testing.T) {
		m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
		m.channels["ch-1"] = channelInfo{ID: "ch-1", Name: "general"}
		id, info, ok := m.resolveChannel("ch-1", false)
		if !ok || id != "ch-1" || info.Name != "general" {
			t.Fatalf("unexpected resolve result: id=%q info=%+v ok=%v", id, info, ok)
		}
	})

	t.Run("empty-name", func(t *testing.T) {
		m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
		_, _, ok := m.resolveChannel("", false)
		if ok {
			t.Fatalf("expected empty name to fail")
		}
		if !strings.Contains(lastSystemMessage(m), "required") {
			t.Fatalf("expected required message")
		}
	})

	t.Run("list-error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(apiError{Error: "boom"})
		}))
		defer server.Close()

		m := newChatForTest(t, &APIClient{serverURL: server.URL, httpClient: server.Client()})
		_, _, ok := m.resolveChannel("general", false)
		if ok {
			t.Fatalf("expected resolve failure")
		}
		if !strings.Contains(m.errMsg, "list channels") {
			t.Fatalf("expected list channels error, got %q", m.errMsg)
		}
	})

	t.Run("no-channels", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/channels" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(ListChannelsResponse{Channels: nil})
		}))
		defer server.Close()

		m := newChatForTest(t, &APIClient{serverURL: server.URL, httpClient: server.Client()})
		_, _, ok := m.resolveChannel("general", false)
		if ok {
			t.Fatalf("expected resolve failure")
		}
		if lastSystemMessage(m) != "no channels available" {
			t.Fatalf("unexpected message: %q", lastSystemMessage(m))
		}
	})

	t.Run("unknown-channel-name", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/channels" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(ListChannelsResponse{Channels: []ChannelResponse{{ID: "ch-1", NameEnc: nameEnc}}})
		}))
		defer server.Close()

		m := newChatForTest(t, &APIClient{serverURL: server.URL, httpClient: server.Client()})
		m.channelKeys["ch-1"] = key
		_, _, ok := m.resolveChannel("random", false)
		if ok {
			t.Fatalf("expected unknown channel")
		}
		if lastSystemMessage(m) != "unknown channel name" {
			t.Fatalf("unexpected message: %q", lastSystemMessage(m))
		}
	})

	t.Run("multiple-matches-without-selector", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/channels" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(ListChannelsResponse{Channels: []ChannelResponse{{ID: "ch-1", NameEnc: nameEnc}, {ID: "ch-2", NameEnc: nameEnc}}})
		}))
		defer server.Close()

		m := newChatForTest(t, &APIClient{serverURL: server.URL, httpClient: server.Client()})
		m.channelKeys["ch-1"] = key
		m.channelKeys["ch-2"] = key
		_, _, ok := m.resolveChannel("general", false)
		if ok {
			t.Fatalf("expected ambiguous match")
		}
		if !strings.Contains(lastSystemMessage(m), "multiple channels match") {
			t.Fatalf("unexpected message: %q", lastSystemMessage(m))
		}
	})

	t.Run("prefix-id-match", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/channels" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(ListChannelsResponse{Channels: []ChannelResponse{{ID: "abcdef12", NameEnc: ""}}})
		}))
		defer server.Close()

		m := newChatForTest(t, &APIClient{serverURL: server.URL, httpClient: server.Client()})
		id, _, ok := m.resolveChannel("abc", false)
		if !ok || id != "abcdef12" {
			t.Fatalf("expected prefix match, got id=%q ok=%v", id, ok)
		}
	})
}

func TestChatModelHandleCommandAdditionalBranches(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/channels" {
			_ = json.NewEncoder(w).Encode(ListChannelsResponse{Channels: nil})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	m := newChatForTest(t, &APIClient{serverURL: server.URL, httpClient: server.Client()})
	m.auth.IsAdmin = true
	m.channels["general"] = channelInfo{ID: "general", Name: "general"}
	m.channelHistoryLoaded["general"] = true

	m.handleCommand("/channel help")
	if !strings.Contains(lastSystemMessage(m), "channel commands") {
		t.Fatalf("expected channel help")
	}

	m.handleCommand("/list")
	if lastSystemMessage(m) != "no channels yet" {
		t.Fatalf("unexpected /list message: %q", lastSystemMessage(m))
	}

	m.handleCommand("/ls")
	if lastSystemMessage(m) != "no channels yet" {
		t.Fatalf("unexpected /ls message: %q", lastSystemMessage(m))
	}

	m.handleCommand("/channel list")
	if lastSystemMessage(m) != "no channels yet" {
		t.Fatalf("unexpected list message: %q", lastSystemMessage(m))
	}

	m.handleCommand("/join #general")
	if m.activeChannel != "general" {
		t.Fatalf("expected /join to switch to channel")
	}

	m.activeChannel = ""
	m.handleCommand("/j #general")
	if m.activeChannel != "general" {
		t.Fatalf("expected /j to switch to channel")
	}

	m.handleCommand("/join")
	if lastSystemMessage(m) != "usage: /join <channel>" {
		t.Fatalf("unexpected /join usage message: %q", lastSystemMessage(m))
	}

	m.handleCommand("/channel unknown")
	if lastSystemMessage(m) != "unknown channel command" {
		t.Fatalf("unexpected message: %q", lastSystemMessage(m))
	}
}

func TestChatModelUpdateSupplementalBranches(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/channels" {
			_ = json.NewEncoder(w).Encode(ListChannelsResponse{Channels: nil})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	m := newChatForTest(t, &APIClient{serverURL: server.URL, httpClient: server.Client()})
	m.wsCh = make(chan ServerMessage)

	updated, cmd := m.Update(shareTick{})
	if cmd != nil {
		t.Fatalf("expected no share tick cmd while disconnected")
	}

	updated.sidebarVisible = false
	updated, cmd = updated.Update(presenceTick{})
	if cmd != nil {
		t.Fatalf("expected no presence tick cmd while sidebar hidden")
	}

	updated.voiceIPC = nil
	updated.voiceReconnectAttempt = 0
	updated, cmd = updated.Update(voicePingTick{})
	if cmd == nil || updated.voiceReconnectAttempt != 1 {
		t.Fatalf("expected reconnect schedule when voice IPC missing")
	}

	updated.voiceIPC = newVoiceIPC("")
	updated.voiceReconnectAttempt = 0
	updated, cmd = updated.Update(voicePingTick{})
	if cmd == nil || updated.voiceReconnectAttempt != 1 {
		t.Fatalf("expected reconnect schedule when ping send fails")
	}
	if !strings.Contains(updated.errMsg, "voice ping failed") {
		t.Fatalf("expected ping failure error, got %q", updated.errMsg)
	}

	updated.errMsg = ""
	updated, _ = updated.Update(directorySyncMsg{err: errDirectoryKeyPending})
	if updated.errMsg != "" {
		t.Fatalf("expected pending directory key to suppress error, got %q", updated.errMsg)
	}

	before := len(updated.messages)
	updated.voiceAutoStarting = true
	updated.voiceIPC = nil
	updated, cmd = updated.Update(voiceIPCErrorMsg{err: errors.New("boom")})
	if cmd != nil {
		t.Fatalf("expected nil cmd without configured voice IPC")
	}
	if len(updated.messages) != before {
		t.Fatalf("expected no disconnect message while auto-starting")
	}

	updated.voiceIPC = newVoiceIPC("")
	_, cmd = updated.Update(voiceReconnectTick{})
	if cmd == nil {
		t.Fatalf("expected reconnect command")
	}
	if _, ok := cmd().(voiceIPCErrorMsg); !ok {
		t.Fatalf("expected reconnect command to produce voiceIPCErrorMsg")
	}

	updated.channelRefreshNeeded = true
	updated.channelRefreshRetries = 2
	updated, cmd = updated.Update(wsMessageMsg(ServerMessage{Type: "device.joined", DeviceID: updated.auth.DeviceID}))
	if cmd == nil {
		t.Fatalf("expected device joined follow-up commands")
	}
	if updated.channelRefreshRetries != 0 {
		t.Fatalf("expected channel refresh retries reset on own device join")
	}
}

func TestChatModelApplyServerVoicePresenceBranches(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})

	m.applyServerVoicePresence("", "u1", true)
	m.applyServerVoicePresence("ch-1", "", true)
	if len(m.serverVoiceRooms) != 0 {
		t.Fatalf("expected empty updates to be ignored")
	}

	m.applyServerVoicePresence("ch-1", "u1", true)
	if m.serverVoiceRooms["ch-1"] == nil || !m.serverVoiceRooms["ch-1"]["u1"] {
		t.Fatalf("expected active user added to room")
	}

	m.applyServerVoicePresence("ch-1", "u1", false)
	if _, ok := m.serverVoiceRooms["ch-1"]; ok {
		t.Fatalf("expected empty room removed after user leaves")
	}
}

func TestChatModelTextAndHighlightHelpersAdditionalPaths(t *testing.T) {
	if got := wrapText("hello", 0); len(got) != 1 || got[0] != "hello" {
		t.Fatalf("expected width<=0 passthrough, got %#v", got)
	}
	if got := wrapText("", 10); len(got) != 1 || got[0] != "" {
		t.Fatalf("expected empty string wrap result, got %#v", got)
	}
	if got := wrapText("   ", 10); len(got) != 1 || got[0] != "" {
		t.Fatalf("expected whitespace-only wrap result, got %#v", got)
	}
	if got := wrapText("abcdefgh ij", 3); len(got) < 3 {
		t.Fatalf("expected chunked wrap result, got %#v", got)
	}
	if got := formatUsername("<alice>"); got != "<alice>" {
		t.Fatalf("expected angle-bracket name passthrough, got %q", got)
	}

	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	m.activeChannel = "ch-1"
	m.appendHighlightedMessage("token")
	msgs := m.channelMsgs["ch-1"]
	if len(msgs) != 1 || !msgs[0].highlight {
		t.Fatalf("expected highlighted channel message")
	}

	if cmd := m.scheduleVoiceReconnect(0); cmd == nil {
		t.Fatalf("expected reconnect command for low attempt")
	}
	if cmd := m.scheduleVoiceReconnect(999); cmd == nil {
		t.Fatalf("expected reconnect command for capped attempt")
	}
}

func TestChatModelShareDirectoryKeyAdditionalPaths(t *testing.T) {
	key := bytes.Repeat([]byte{8}, crypto.KeySize)

	t.Run("no-devices", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/devices/keys" {
				_ = json.NewEncoder(w).Encode(DeviceKeysResponse{Keys: nil})
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		m := newChatForTest(t, &APIClient{serverURL: server.URL, httpClient: server.Client()})
		m.directoryKey = key
		if err := m.shareDirectoryKey(); err != nil {
			t.Fatalf("shareDirectoryKey: %v", err)
		}
	})

	t.Run("self-only-devices-yield-empty-envelopes", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/devices/keys" {
				_ = json.NewEncoder(w).Encode(DeviceKeysResponse{Keys: []DeviceKey{{}}})
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		m := newChatForTest(t, &APIClient{serverURL: server.URL, httpClient: server.Client()})
		m.directoryKey = key
		if err := m.shareDirectoryKey(); err != nil {
			t.Fatalf("shareDirectoryKey: %v", err)
		}
	})

	t.Run("put-failure", func(t *testing.T) {
		recipient := newTestKeyPair(t)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/devices/keys":
				_ = json.NewEncoder(w).Encode(DeviceKeysResponse{Keys: []DeviceKey{{
					DeviceID:  "device-2",
					PublicKey: crypto.PublicKeyToBase64(recipient.Public),
				}}})
			case "/directory/keys":
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(apiError{Error: "boom"})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		m := newChatForTest(t, &APIClient{serverURL: server.URL, httpClient: server.Client()})
		m.directoryKey = key
		if err := m.shareDirectoryKey(); err == nil {
			t.Fatalf("expected put directory key error")
		}
	})

	t.Run("success", func(t *testing.T) {
		recipient := newTestKeyPair(t)
		var posted bool
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/devices/keys":
				_ = json.NewEncoder(w).Encode(DeviceKeysResponse{Keys: []DeviceKey{{
					DeviceID:  "device-2",
					PublicKey: crypto.PublicKeyToBase64(recipient.Public),
				}}})
			case "/directory/keys":
				posted = true
				w.WriteHeader(http.StatusOK)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		m := newChatForTest(t, &APIClient{serverURL: server.URL, httpClient: server.Client()})
		m.directoryKey = key
		if err := m.shareDirectoryKey(); err != nil {
			t.Fatalf("shareDirectoryKey: %v", err)
		}
		if !posted {
			t.Fatalf("expected directory key envelopes to be posted")
		}
	})
}

func TestChatModelEnsureChannelKeyAndHistoryErrorPaths(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	if _, err := m.ensureChannelKey(""); err == nil {
		t.Fatalf("expected missing channel id error")
	}

	sender := newTestKeyPair(t)

	t.Run("invalid-sender-public-key", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(ChannelKeyEnvelope{SenderPublicKey: "invalid", Envelope: "ct"})
		}))
		defer server.Close()

		local := newChatForTest(t, &APIClient{serverURL: server.URL, httpClient: server.Client()})
		if _, err := local.ensureChannelKey("ch-1"); err == nil {
			t.Fatalf("expected invalid sender key error")
		}
	})

	t.Run("invalid-ciphertext", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(ChannelKeyEnvelope{SenderPublicKey: crypto.PublicKeyToBase64(sender.Public), Envelope: "bad"})
		}))
		defer server.Close()

		local := newChatForTest(t, &APIClient{serverURL: server.URL, httpClient: server.Client()})
		if _, err := local.ensureChannelKey("ch-1"); err == nil {
			t.Fatalf("expected decrypt key envelope error")
		}
	})

	t.Run("invalid-key-size", func(t *testing.T) {
		local := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
		badSizeCipher, err := crypto.EncryptForPeer(sender.Private, local.kp.Public, []byte{1, 2, 3})
		if err != nil {
			t.Fatalf("encrypt small payload: %v", err)
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(ChannelKeyEnvelope{SenderPublicKey: crypto.PublicKeyToBase64(sender.Public), Envelope: badSizeCipher})
		}))
		defer server.Close()

		local.api = &APIClient{serverURL: server.URL, httpClient: server.Client()}
		if _, err := local.ensureChannelKey("ch-1"); err == nil || !strings.Contains(err.Error(), "invalid channel key size") {
			t.Fatalf("expected invalid channel key size error, got %v", err)
		}
	})

	t.Run("load-history-paths", func(t *testing.T) {
		key := bytes.Repeat([]byte{9}, crypto.KeySize)
		bodyEnc, err := encryptChannelField(key, "hello")
		if err != nil {
			t.Fatalf("encrypt body: %v", err)
		}
		senderEnc, err := encryptChannelField(key, "alice")
		if err != nil {
			t.Fatalf("encrypt sender: %v", err)
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/channels/messages":
				if r.URL.Query().Get("channel_id") == "empty" {
					_ = json.NewEncoder(w).Encode(ChannelMessagesResponse{Messages: nil})
					return
				}
				if r.URL.Query().Get("channel_id") == "boom" {
					w.WriteHeader(http.StatusInternalServerError)
					_ = json.NewEncoder(w).Encode(apiError{Error: "boom"})
					return
				}
				_ = json.NewEncoder(w).Encode(ChannelMessagesResponse{Messages: []ChannelMessageResponse{{
					SenderID:      "u1",
					SenderNameEnc: senderEnc,
					Body:          bodyEnc,
					SentAt:        time.Now().UTC().Format(time.RFC3339Nano),
				}}})
			case "/channels/keys":
				w.WriteHeader(http.StatusNotFound)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		local := newChatForTest(t, &APIClient{serverURL: server.URL, httpClient: server.Client()})
		local.setChannelKey("ok", key)
		local.loadChannelHistory("ok")
		if len(local.channelMsgs["ok"]) == 0 || !local.channelHistoryLoaded["ok"] {
			t.Fatalf("expected channel history loaded")
		}

		local.loadChannelHistory("boom")
		if !strings.Contains(local.errMsg, "channel key") {
			t.Fatalf("expected channel key error before history request, got %q", local.errMsg)
		}

		local.errMsg = ""
		local.setChannelKey("empty", key)
		local.loadChannelHistory("empty")
		if !local.channelHistoryLoaded["empty"] {
			t.Fatalf("expected empty history to mark as loaded")
		}
	})
}

func TestChatModelSelectionAndUserEntryEdges(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	m.channels["ch-1"] = channelInfo{ID: "ch-1", Name: "general"}
	m.channelHistoryLoaded["ch-1"] = true
	m.activeChannel = "ch-1"

	m.useChannel("ch-1")
	if lastSystemMessage(m) != "already viewing that channel" {
		t.Fatalf("unexpected message: %q", lastSystemMessage(m))
	}

	m.selectActive = true
	m.selectOptions = nil
	m.handleChannelSelectKey(tea.KeyMsg{Type: tea.KeyEnter})
	if m.selectActive {
		t.Fatalf("expected empty select options to close selection")
	}

	m.channelMsgs["ch-1"] = []chatMessage{
		{isSystem: true, body: "system"},
		{sender: "u2", senderName: "bob", body: "hello"},
		{sender: "u3", body: "hi"},
	}
	m.userNames["u3"] = "carol"
	m.userPresence["u2"] = true
	m.userAdmins["u2"] = true
	m.voiceSpeaking["u2"] = true

	entries := m.channelUserEntries("ch-1")
	if len(entries) != 2 {
		t.Fatalf("expected 2 channel user entries, got %d", len(entries))
	}

	m.serverVoiceRooms = map[string]map[string]bool{
		"ch-1": {"u2": true, m.auth.UserID: true},
		"ch-2": {},
	}
	m.channels["ch-2"] = channelInfo{ID: "ch-2", Name: "support"}
	rooms := m.serverVoiceRoomEntries()
	if len(rooms) != 1 || rooms[0].ChannelID != "ch-1" {
		t.Fatalf("unexpected voice room entries: %+v", rooms)
	}
}

func TestChatModelUpdateAdditionalMessageBranches(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	m.channels["ch-1"] = channelInfo{ID: "ch-1", Name: "general"}
	m.channels["ch-2"] = channelInfo{ID: "ch-2", Name: "random"}
	m.channelHistoryLoaded["ch-1"] = true
	m.sidebarVisible = true
	m.input.SetValue("")

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
	if updated.sidebarIndex != 0 {
		t.Fatalf("expected plain down arrow to not move sidebar selection")
	}

	updated, _ = updated.Update(tea.KeyMsg{Type: tea.KeyCtrlDown})
	if updated.sidebarIndex != 1 {
		t.Fatalf("expected ctrl+down to move sidebar selection")
	}

	updated.connected = false
	_, cmd := updated.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd != nil {
		t.Fatalf("expected enter while disconnected to return nil cmd")
	}

	updated.wsCh = make(chan ServerMessage)
	updated, cmd = updated.Update(wsMessageMsg(ServerMessage{Type: "error", Code: "bad", Message: "oops"}))
	if cmd == nil {
		t.Fatalf("expected follow-up ws wait command")
	}
	if !strings.Contains(updated.errMsg, "[bad] oops") {
		t.Fatalf("expected ws error message, got %q", updated.errMsg)
	}

	updated.errMsg = ""
	updated, _ = updated.Update(directorySyncMsg{err: context.Canceled})
	if updated.errMsg == "" {
		t.Fatalf("expected directory sync error")
	}

	updated.errMsg = ""
	updated, _ = updated.Update(shareKeysMsg{err: nil})
	if updated.errMsg != "" {
		t.Fatalf("expected nil share keys error to keep errMsg empty")
	}
	updated, _ = updated.Update(shareDirectoryMsg{err: nil})
	if updated.errMsg != "" {
		t.Fatalf("expected nil share directory error to keep errMsg empty")
	}

	updated.auth.IsTrusted = true
	updated.pendingProfilePush = true
	updated, cmd = updated.Update(directoryTick{})
	if cmd == nil {
		t.Fatalf("expected trusted directory tick to schedule work")
	}

	updated.channelRefreshNeeded = true
	updated.channelRefreshRetries = channelRefreshMaxRetries
	updated, cmd = updated.Update(channelRefreshTick{})
	if cmd != nil {
		t.Fatalf("expected no refresh schedule when retries are exhausted")
	}
}

func TestChatModelUpdateEnterSendsDraftInsteadOfSwitching(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	m.channels["ch-1"] = channelInfo{ID: "ch-1", Name: "general"}
	m.channels["ch-2"] = channelInfo{ID: "ch-2", Name: "random"}
	m.channelHistoryLoaded["ch-1"] = true
	m.channelHistoryLoaded["ch-2"] = true
	m.sidebarVisible = true
	m.activeChannel = "ch-1"
	m.sidebarIndex = 1
	m.connected = true
	m.ws = &WSClient{closed: true}
	m.input.SetValue("hello")

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if updated.activeChannel != "ch-1" {
		t.Fatalf("expected enter with draft to stay on current channel")
	}
	if updated.input.Value() != "hello" {
		t.Fatalf("expected input to remain unchanged after failed send")
	}
}

func TestChatModelUpdateEnterSwitchesWhenDraftEmpty(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	m.channels["ch-1"] = channelInfo{ID: "ch-1", Name: "general"}
	m.channels["ch-2"] = channelInfo{ID: "ch-2", Name: "random"}
	m.channelHistoryLoaded["ch-1"] = true
	m.channelHistoryLoaded["ch-2"] = true
	m.sidebarVisible = true
	m.activeChannel = "ch-1"
	m.sidebarIndex = 1
	m.connected = true
	m.ws = &WSClient{closed: true}
	m.input.SetValue("")

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if updated.activeChannel != "ch-2" {
		t.Fatalf("expected enter to switch selected sidebar channel when draft is empty")
	}
}

func TestChatModelUpdateCtrlArrowIgnoredWhileDrafting(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	m.channels["ch-1"] = channelInfo{ID: "ch-1", Name: "general"}
	m.channels["ch-2"] = channelInfo{ID: "ch-2", Name: "random"}
	m.sidebarVisible = true
	m.sidebarIndex = 0
	m.input.SetValue("hello")

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyCtrlDown})
	if updated.sidebarIndex != 0 {
		t.Fatalf("expected ctrl+down to be ignored while drafting")
	}
}

func TestChatModelUpdateF1TogglesHelp(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	m.helpVisible = true

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyF1})
	if updated.helpVisible {
		t.Fatalf("expected f1 to hide help")
	}
}

func TestChatModelUpdateVoiceIPCPaths(t *testing.T) {
	addr := filepath.Join(t.TempDir(), "voice-update.sock")
	listener, err := ipc.Listen(addr)
	if err != nil {
		t.Fatalf("listen voice ipc: %v", err)
	}
	defer listener.Close()

	recv := make(chan ipc.Message, 2)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		dec := ipc.NewDecoder(conn)
		for i := 0; i < 2; i++ {
			var msg ipc.Message
			if err := dec.Decode(&msg); err != nil {
				return
			}
			recv <- msg
		}
	}()

	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	m.voiceIPC = newVoiceIPC(addr)
	join := ipc.Message{Cmd: ipc.CommandVoiceJoin, Room: "ch-1"}
	m.queueVoiceCommand(join, "ch-1", "voice join requested")

	updated, cmd := m.Update(voiceIPCConnectedMsg{ch: make(chan ipc.Message, 1)})
	if cmd == nil {
		t.Fatalf("expected voice wait/ping batch command")
	}
	if updated.voicePendingCmd != nil || updated.voicePendingRoom != "" {
		t.Fatalf("expected pending voice command to clear after successful resend")
	}
	if updated.voiceRoom != "ch-1" {
		t.Fatalf("expected pending room to become active room")
	}
	if !strings.Contains(lastSystemMessage(updated), "voice join requested") {
		t.Fatalf("expected pending notice message")
	}

	select {
	case first := <-recv:
		if first.Cmd != ipc.CommandIdentify {
			t.Fatalf("expected identify first, got %#v", first)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for identify command")
	}
	select {
	case second := <-recv:
		if second.Cmd != ipc.CommandVoiceJoin || second.Room != "ch-1" {
			t.Fatalf("unexpected pending resend message: %#v", second)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for pending voice command")
	}

	updated.voiceCh = make(chan ipc.Message, 1)
	updated, cmd = updated.Update(voiceIPCMsg(ipc.Message{Event: ipc.EventInfo, Error: "hello"}))
	if cmd == nil {
		t.Fatalf("expected follow-up voice wait cmd")
	}
	if !strings.Contains(lastSystemMessage(updated), "voice info: hello") {
		t.Fatalf("expected voice info message")
	}

	updated.voiceAutoStarting = false
	updated.voiceIPC = newVoiceIPC("")
	before := len(updated.messages)
	updated, cmd = updated.Update(voiceIPCErrorMsg{err: errors.New("disconnect")})
	if cmd == nil || updated.voiceReconnectAttempt == 0 {
		t.Fatalf("expected reconnect schedule after voice IPC error")
	}
	if len(updated.messages) != before+1 || lastSystemMessage(updated) != "voice daemon disconnected" {
		t.Fatalf("expected disconnect system message")
	}
}

func TestChatModelSendCurrentMessageAndHelpersEdgeCases(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	m.input.SetValue("   ")
	if cmd := m.sendCurrentMessage(); cmd != nil {
		t.Fatalf("expected nil cmd for empty message")
	}

	m.input.SetValue("hello")
	m.ws = nil
	if cmd := m.sendCurrentMessage(); cmd != nil {
		t.Fatalf("expected nil cmd when websocket is nil")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/channels/keys" {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(apiError{Error: "missing"})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	m = newChatForTest(t, &APIClient{serverURL: server.URL, httpClient: server.Client()})
	m.activeChannel = "ch-1"
	m.ws = &WSClient{closed: true}
	m.input.SetValue("hello")
	_ = m.sendCurrentMessage()
	if !strings.Contains(m.errMsg, "channel key") {
		t.Fatalf("expected channel key error, got %q", m.errMsg)
	}

	if got := m.channelHelpText(); !strings.Contains(got, "create") {
		t.Fatalf("expected admin channel help text")
	}
	m.auth.IsAdmin = false
	if got := m.channelHelpText(); !strings.Contains(got, "/join <channel>") || !strings.Contains(got, "/channel list") {
		t.Fatalf("unexpected non-admin channel help text: %q", got)
	}
	if got := m.serverHelpText(); got != "admin only: server invites" {
		t.Fatalf("unexpected non-admin server help text: %q", got)
	}

	if m.getChannelKey("") != nil {
		t.Fatalf("expected empty channel id to return nil key")
	}

	if _, err := decryptFieldWithKey(bytes.Repeat([]byte{1}, crypto.KeySize), "not-base64"); err == nil {
		t.Fatalf("expected decryptFieldWithKey decode error")
	}
	if _, err := encryptChannelField([]byte{1, 2}, "hello"); err == nil {
		t.Fatalf("expected encryptChannelField key size error")
	}
	if !isNotFoundErr(errors.New("Not Found")) || isNotFoundErr(nil) {
		t.Fatalf("unexpected isNotFoundErr behavior")
	}
}

func TestChatModelShareKnownChannelKeysAdditionalPaths(t *testing.T) {
	t.Run("list-channels-error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/channels" {
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(apiError{Error: "boom"})
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		m := newChatForTest(t, &APIClient{serverURL: server.URL, httpClient: server.Client()})
		m.channelKeys["ch-1"] = bytes.Repeat([]byte{1}, crypto.KeySize)
		if err := m.shareKnownChannelKeys(); err == nil {
			t.Fatalf("expected list channels error")
		}
	})

	t.Run("list-devices-error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/channels":
				_ = json.NewEncoder(w).Encode(ListChannelsResponse{Channels: []ChannelResponse{{ID: "ch-1"}}})
			case "/devices/keys":
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(apiError{Error: "boom"})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		m := newChatForTest(t, &APIClient{serverURL: server.URL, httpClient: server.Client()})
		m.channelKeys["ch-1"] = bytes.Repeat([]byte{1}, crypto.KeySize)
		if err := m.shareKnownChannelKeys(); err == nil {
			t.Fatalf("expected list devices error")
		}
	})

	t.Run("no-devices-short-circuit", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/channels":
				_ = json.NewEncoder(w).Encode(ListChannelsResponse{Channels: []ChannelResponse{{ID: "ch-1"}}})
			case "/devices/keys":
				_ = json.NewEncoder(w).Encode(DeviceKeysResponse{Keys: nil})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		m := newChatForTest(t, &APIClient{serverURL: server.URL, httpClient: server.Client()})
		m.channelKeys["ch-1"] = bytes.Repeat([]byte{1}, crypto.KeySize)
		if err := m.shareKnownChannelKeys(); err != nil {
			t.Fatalf("shareKnownChannelKeys: %v", err)
		}
	})
}

func TestChatModelSyncDirectoryAndChannelMutationEdges(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	m.directoryKey = bytes.Repeat([]byte{1}, crypto.KeySize)
	m.auth = nil
	if _, _, err := m.syncDirectory(false); err == nil || !strings.Contains(err.Error(), "missing auth") {
		t.Fatalf("expected missing auth error, got %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/directory/keys":
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(apiError{Error: "boom"})
		case "/channels":
			if r.Method == http.MethodPost {
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(apiError{Error: "create failed"})
				return
			}
			if r.Method == http.MethodDelete {
				w.WriteHeader(http.StatusOK)
				return
			}
			if r.Method == http.MethodPatch {
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(apiError{Error: "rename failed"})
				return
			}
			_ = json.NewEncoder(w).Encode(ListChannelsResponse{Channels: nil})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	m = newChatForTest(t, &APIClient{serverURL: server.URL, httpClient: server.Client()})
	if _, err := m.ensureDirectoryKey(); err == nil {
		t.Fatalf("expected ensureDirectoryKey error")
	}

	m.createChannel("general")
	if !strings.Contains(m.errMsg, "create channel") {
		t.Fatalf("expected create channel error, got %q", m.errMsg)
	}

	m.errMsg = ""
	m.channels["abcdefghijk"] = channelInfo{ID: "abcdefghijk", Name: ""}
	m.deleteChannel("abcdefghijk")
	if !strings.Contains(lastSystemMessage(m), "deleted channel") {
		t.Fatalf("expected deleted channel message")
	}

	m.errMsg = ""
	m.channels["ch-2"] = channelInfo{ID: "ch-2", Name: "old"}
	m.channelKeys["ch-2"] = bytes.Repeat([]byte{2}, crypto.KeySize)
	m.renameChannel("ch-2", "new")
	if !strings.Contains(m.errMsg, "rename channel") {
		t.Fatalf("expected rename channel error, got %q", m.errMsg)
	}

	m.voicePendingCmd = &ipc.Message{Cmd: ipc.CommandVoiceJoin, Room: "ch-voice"}
	m.voicePendingRoom = ""
	if id := m.voiceChannelIndicatorID(); id != "ch-voice" {
		t.Fatalf("expected pending command room fallback, got %q", id)
	}
	if name := m.channelDisplayName("unknown-channel-id"); name != "unknown-" {
		t.Fatalf("expected shortID fallback, got %q", name)
	}
	m.resetVoiceMembersForRoom("")
	if len(m.voiceMembers) != 0 {
		t.Fatalf("expected resetVoiceMembersForRoom empty to clear members")
	}
}

func TestChatModelVoiceAndInviteGuardBranches(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	m.voiceIPC = newVoiceIPC("")
	m.activeChannel = ""

	_ = m.handleVoiceCommand("/voice join", []string{"/voice", "join"})
	if !strings.Contains(lastSystemMessage(m), "usage: /voice join") {
		t.Fatalf("expected voice join usage message")
	}

	m.voiceIPC = nil
	cmd := m.dispatchVoiceCommand(ipc.Message{Cmd: ipc.CommandMute}, "", "", "voice mute")
	if cmd != nil {
		t.Fatalf("expected nil command when voice IPC is missing")
	}
	if lastSystemMessage(m) != "voice daemon not configured" {
		t.Fatalf("unexpected dispatch guard message: %q", lastSystemMessage(m))
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(apiError{Error: "boom"})
	}))
	defer server.Close()

	m = newChatForTest(t, &APIClient{serverURL: server.URL, httpClient: server.Client()})
	m.createServerInvite()
	if !strings.Contains(m.errMsg, "server invite") {
		t.Fatalf("expected invite error, got %q", m.errMsg)
	}

	m.startChannelSelection(nil)
	if m.selectActive {
		t.Fatalf("expected empty selection options to keep modal inactive")
	}
}
