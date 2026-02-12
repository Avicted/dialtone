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
	if !strings.Contains(out, "♪ beta") {
		t.Fatalf("expected voice marker on joined channel")
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

func TestChatModelUpdateCtrlHTogglesSidebar(t *testing.T) {
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
	if !strings.Contains(out, "In Voice") || !strings.Contains(out, "(you)") {
		t.Fatalf("expected in-voice roster rendering")
	}
}

func TestChatModelRenderSidebarServerVoicePresence(t *testing.T) {
	m := newChatForTest(t, &APIClient{serverURL: "http://server", httpClient: http.DefaultClient})
	m.channels["ch-1"] = channelInfo{ID: "ch-1", Name: "general"}
	m.userNames["user-2"] = "bobross"
	m.userPresence["user-2"] = true

	m.handleServerMessage(ServerMessage{
		Type:       "voice.presence.snapshot",
		VoiceRooms: map[string][]string{"ch-1": {"user-2"}},
	})
	out := m.renderSidebar()
	if !strings.Contains(out, "In Voice") || !strings.Contains(out, "general") || !strings.Contains(out, "<bobross>") {
		t.Fatalf("expected server voice presence in sidebar")
	}
	if strings.Contains(out, "(not connected)") {
		t.Fatalf("unexpected disconnected placeholder when server presence exists")
	}

	m.handleServerMessage(ServerMessage{Type: "voice.presence", ChannelID: "ch-1", Sender: "user-2", Active: false})
	out = m.renderSidebar()
	if strings.Contains(out, "<bobross>") {
		t.Fatalf("expected bobross removed after inactive update")
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

func TestChatModelUpdateCtrlUTogglesSidebar(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/presence" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(PresenceResponse{Statuses: map[string]bool{"u1": true}})
	}))
	defer server.Close()

	api := &APIClient{serverURL: server.URL, httpClient: server.Client()}
	m := newChatForTest(t, api)
	m.userNames["u1"] = "alice"
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlU})
	if updated.sidebarVisible {
		t.Fatalf("expected sidebar hidden")
	}
	if cmd != nil {
		t.Fatalf("expected no command when hiding sidebar")
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
	if cmd := m.scheduleDirectoryTick(); cmd == nil {
		t.Fatalf("expected directory tick cmd")
	}
	if cmd := m.schedulePresenceTick(); cmd == nil {
		t.Fatalf("expected presence tick cmd")
	}
	if cmd := m.scheduleShareTick(); cmd == nil {
		t.Fatalf("expected share tick cmd")
	}
	if cmd := m.scheduleChannelRefresh(); cmd == nil {
		t.Fatalf("expected channel refresh cmd")
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
