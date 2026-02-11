package e2e

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"nhooyr.io/websocket"

	"github.com/Avicted/dialtone/internal/auth"
	"github.com/Avicted/dialtone/internal/channel"
	"github.com/Avicted/dialtone/internal/crypto"
	"github.com/Avicted/dialtone/internal/device"
	"github.com/Avicted/dialtone/internal/httpapi"
	"github.com/Avicted/dialtone/internal/serverinvite"
	"github.com/Avicted/dialtone/internal/storage"
	"github.com/Avicted/dialtone/internal/user"
	"github.com/Avicted/dialtone/internal/ws"
)

type inviteResponse struct {
	Token string `json:"token"`
}

type authResponse struct {
	Token    string `json:"token"`
	UserID   string `json:"user_id"`
	DeviceID string `json:"device_id"`
}

type profileListResponse struct {
	Profiles []struct {
		UserID  string `json:"user_id"`
		NameEnc string `json:"name_enc"`
	} `json:"profiles"`
}

type channelResponse struct {
	Channel struct {
		ID      string `json:"id"`
		NameEnc string `json:"name_enc"`
	} `json:"channel"`
}

type channelListResponse struct {
	Channels []struct {
		ID      string `json:"id"`
		NameEnc string `json:"name_enc"`
	} `json:"channels"`
}

type channelKeyEnvelopeResponse struct {
	ChannelID string `json:"channel_id"`
	DeviceID  string `json:"device_id"`
	Envelope  string `json:"envelope"`
}

type presenceResponse struct {
	Statuses map[string]bool `json:"statuses"`
}

type wsEvent struct {
	Type     string `json:"type"`
	Sender   string `json:"sender"`
	DeviceID string `json:"device_id"`
}

type wsPayload struct {
	Type           string `json:"type"`
	Sender         string `json:"sender"`
	SenderNameEnc  string `json:"sender_name_enc"`
	ChannelID      string `json:"channel_id"`
	ChannelNameEnc string `json:"channel_name_enc"`
	MessageID      string `json:"message_id"`
	Body           string `json:"body"`
}

func TestE2E_ProfileSync(t *testing.T) {
	ctx := context.Background()

	pgURL, cleanup := startPostgres(t, ctx)
	defer cleanup()

	serverURL, shutdown := startServer(t, ctx, pgURL)
	defer shutdown()

	adminToken := "test-admin-token"

	invite := createInvite(t, ctx, serverURL, adminToken)
	adminAuth := registerUser(t, ctx, serverURL, "admin", "password123", "pubkey-admin", invite)
	adminWS := connectWS(t, ctx, serverURL, adminAuth.Token)
	defer adminWS.Close(websocket.StatusNormalClosure, "bye")

	invite2 := createInvite(t, ctx, serverURL, adminToken)
	userAuth := registerUser(t, ctx, serverURL, "alice", "password123", "pubkey-alice", invite2)
	userWS := connectWS(t, ctx, serverURL, userAuth.Token)
	defer userWS.Close(websocket.StatusNormalClosure, "bye")

	waitForDeviceJoin(t, adminWS, userAuth.UserID)

	status := getDirectoryKeyStatus(t, ctx, serverURL, userAuth.Token)
	if status != http.StatusNoContent && status != http.StatusOK {
		t.Fatalf("directory key status = %d", status)
	}

	postUserProfile(t, ctx, serverURL, userAuth.Token, "enc-name-alice")
	waitForProfileUpdate(t, adminWS, userAuth.UserID)

	profiles := listProfiles(t, ctx, serverURL, adminAuth.Token)
	if !containsProfile(profiles, userAuth.UserID) {
		t.Fatalf("expected profile for user %s", userAuth.UserID)
	}
}

func TestE2E_ChannelLifecycleAndKeys(t *testing.T) {
	ctx := context.Background()

	pgURL, cleanup := startPostgres(t, ctx)
	defer cleanup()

	serverURL, shutdown := startServer(t, ctx, pgURL)
	defer shutdown()

	adminToken := "test-admin-token"
	invite := createInvite(t, ctx, serverURL, adminToken)
	adminAuth := registerUser(t, ctx, serverURL, "admin", "password123", "pubkey-admin", invite)
	adminWS := connectWS(t, ctx, serverURL, adminAuth.Token)
	defer adminWS.Close(websocket.StatusNormalClosure, "bye")

	channelID := createChannel(t, ctx, serverURL, adminAuth.Token, "enc-channel")
	waitForWSEvent(t, adminWS, func(evt wsPayload) bool {
		return evt.Type == "channel.updated" && evt.ChannelID == channelID
	})

	updateChannel(t, ctx, serverURL, adminAuth.Token, channelID, "enc-channel-renamed")
	waitForWSEvent(t, adminWS, func(evt wsPayload) bool {
		return evt.Type == "channel.updated" && evt.ChannelID == channelID
	})

	putChannelKeyEnvelope(t, ctx, serverURL, adminAuth.Token, channelID, adminAuth.DeviceID, "pubkey-admin", "env-admin")
	got := getChannelKeyEnvelope(t, ctx, serverURL, adminAuth.Token, channelID)
	if got.Envelope != "env-admin" {
		t.Fatalf("channel envelope = %q", got.Envelope)
	}

	deleteChannel(t, ctx, serverURL, adminAuth.Token, channelID)
	waitForWSEvent(t, adminWS, func(evt wsPayload) bool {
		return evt.Type == "channel.deleted" && evt.ChannelID == channelID
	})
}

func TestE2E_MessageSendReceivePresence(t *testing.T) {
	ctx := context.Background()

	pgURL, cleanup := startPostgres(t, ctx)
	defer cleanup()

	serverURL, shutdown := startServer(t, ctx, pgURL)
	defer shutdown()

	adminToken := "test-admin-token"
	invite := createInvite(t, ctx, serverURL, adminToken)
	adminAuth := registerUser(t, ctx, serverURL, "admin", "password123", "pubkey-admin", invite)
	adminWS := connectWS(t, ctx, serverURL, adminAuth.Token)
	defer adminWS.Close(websocket.StatusNormalClosure, "bye")

	invite2 := createInvite(t, ctx, serverURL, adminToken)
	userAuth := registerUser(t, ctx, serverURL, "alice", "password123", "pubkey-alice", invite2)
	userWS := connectWS(t, ctx, serverURL, userAuth.Token)
	defer userWS.Close(websocket.StatusNormalClosure, "bye")

	channelID := createChannel(t, ctx, serverURL, adminAuth.Token, "enc-chat")
	waitForWSEvent(t, adminWS, func(evt wsPayload) bool {
		return evt.Type == "channel.updated" && evt.ChannelID == channelID
	})

	sendChannelMessage(t, adminWS, channelID, "enc-admin", "hello")
	waitForWSEvent(t, userWS, func(evt wsPayload) bool {
		return evt.Type == "channel.message.new" && evt.ChannelID == channelID && evt.Sender == adminAuth.UserID
	})

	ids := []string{adminAuth.UserID, userAuth.UserID}
	waitForPresence(t, ctx, serverURL, adminAuth.Token, ids)
}

func TestE2E_NewUserSeesNewChannel(t *testing.T) {
	ctx := context.Background()

	pgURL, cleanup := startPostgres(t, ctx)
	defer cleanup()

	serverURL, shutdown := startServer(t, ctx, pgURL)
	defer shutdown()

	adminToken := "test-admin-token"
	invite := createInvite(t, ctx, serverURL, adminToken)
	adminAuth := registerUser(t, ctx, serverURL, "admin", "password123", "pubkey-admin", invite)
	adminWS := connectWS(t, ctx, serverURL, adminAuth.Token)
	defer adminWS.Close(websocket.StatusNormalClosure, "bye")

	invite2 := createInvite(t, ctx, serverURL, adminToken)
	userAuth := registerUser(t, ctx, serverURL, "alice", "password123", "pubkey-alice", invite2)
	userWS := connectWS(t, ctx, serverURL, userAuth.Token)
	defer userWS.Close(websocket.StatusNormalClosure, "bye")

	channelID := createChannel(t, ctx, serverURL, adminAuth.Token, "enc-new-channel")
	waitForWSEvent(t, userWS, func(evt wsPayload) bool {
		return evt.Type == "channel.updated" && evt.ChannelID == channelID
	})

	channels := listChannels(t, ctx, serverURL, userAuth.Token)
	if !containsChannel(channels, channelID) {
		t.Fatalf("expected channel %s in list", channelID)
	}
}

func TestE2E_EncryptedMessageRoundTrip(t *testing.T) {
	ctx := context.Background()

	pgURL, cleanup := startPostgres(t, ctx)
	defer cleanup()

	serverURL, shutdown := startServer(t, ctx, pgURL)
	defer shutdown()

	adminToken := "test-admin-token"
	invite := createInvite(t, ctx, serverURL, adminToken)
	adminAuth := registerUser(t, ctx, serverURL, "admin", "password123", "pubkey-admin", invite)
	adminWS := connectWS(t, ctx, serverURL, adminAuth.Token)
	defer adminWS.Close(websocket.StatusNormalClosure, "bye")

	invite2 := createInvite(t, ctx, serverURL, adminToken)
	userAuth := registerUser(t, ctx, serverURL, "alice", "password123", "pubkey-alice", invite2)
	userWS := connectWS(t, ctx, serverURL, userAuth.Token)
	defer userWS.Close(websocket.StatusNormalClosure, "bye")

	channelID := createChannel(t, ctx, serverURL, adminAuth.Token, "enc-secure")
	waitForWSEvent(t, adminWS, func(evt wsPayload) bool {
		return evt.Type == "channel.updated" && evt.ChannelID == channelID
	})

	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	senderEnc := encryptField(t, key, "admin")
	bodyEnc := encryptField(t, key, "secret message")
	sendChannelMessage(t, adminWS, channelID, senderEnc, bodyEnc)

	msg := waitForWSEvent(t, userWS, func(evt wsPayload) bool {
		return evt.Type == "channel.message.new" && evt.ChannelID == channelID
	})

	gotSender := decryptField(t, key, msg.SenderNameEnc)
	gotBody := decryptField(t, key, msg.Body)
	if gotSender != "admin" {
		t.Fatalf("sender name = %q, want %q", gotSender, "admin")
	}
	if gotBody != "secret message" {
		t.Fatalf("body = %q, want %q", gotBody, "secret message")
	}
}

func startPostgres(t *testing.T, ctx context.Context) (string, func()) {
	t.Helper()
	if err := testcontainers.SkipIfDockerNotAvailable(); err != nil {
		t.Skip("docker not available for testcontainers")
	}

	req := testcontainers.ContainerRequest{
		Image:        "postgres:15-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "dialtone",
			"POSTGRES_PASSWORD": "dialtone",
			"POSTGRES_DB":       "dialtone",
		},
		WaitingFor: wait.ForLog("database system is ready to accept connections").WithStartupTimeout(60 * time.Second),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("start postgres: %v", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		_ = container.Terminate(ctx)
		t.Fatalf("postgres host: %v", err)
	}
	port, err := container.MappedPort(ctx, "5432/tcp")
	if err != nil {
		_ = container.Terminate(ctx)
		t.Fatalf("postgres port: %v", err)
	}
	conn := fmt.Sprintf("postgres://dialtone:dialtone@%s:%s/dialtone?sslmode=disable", host, port.Port())

	return conn, func() {
		_ = container.Terminate(context.Background())
	}
}

func startServer(t *testing.T, ctx context.Context, dbURL string) (string, func()) {
	t.Helper()

	store, err := storage.NewPostgresStore(ctx, dbURL)
	if err != nil {
		t.Fatalf("init store: %v", err)
	}
	if err := store.Migrate(ctx); err != nil {
		_ = store.Close(ctx)
		t.Fatalf("migrate: %v", err)
	}

	hub := ws.NewHub(store.Broadcasts(), store.Devices(), store.Channels())
	hubCtx, cancel := context.WithCancel(ctx)
	go hub.Run(hubCtx)

	userService := user.NewService(store.Users(), "test-pepper")
	deviceService := device.NewService(store.Devices())
	channelService := channel.NewService(store.Channels(), userService)
	inviteService := serverinvite.NewService(store.ServerInvites())
	authService := auth.NewService(userService, deviceService, inviteService)

	api := httpapi.NewHandler(userService, deviceService, channelService, authService, inviteService, hub, hub, hub, "test-admin-token")

	mux := http.NewServeMux()
	mux.Handle("/ws", ws.WithAuthValidator(http.HandlerFunc(hub.HandleWS), authService))
	api.Register(mux)

	srv := httptest.NewServer(mux)

	return srv.URL, func() {
		srv.Close()
		cancel()
		_ = store.Close(context.Background())
	}
}

func createInvite(t *testing.T, ctx context.Context, serverURL, adminToken string) string {
	t.Helper()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/server/invites", nil)
	if err != nil {
		t.Fatalf("invite request: %v", err)
	}
	req.Header.Set("X-Admin-Token", adminToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("invite call: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("invite status = %d", resp.StatusCode)
	}

	var payload inviteResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("invite decode: %v", err)
	}
	if strings.TrimSpace(payload.Token) == "" {
		t.Fatalf("invite token empty")
	}
	return payload.Token
}

func registerUser(t *testing.T, ctx context.Context, serverURL, username, password, publicKey, inviteToken string) authResponse {
	t.Helper()

	body := map[string]string{
		"username":     username,
		"password":     password,
		"public_key":   publicKey,
		"invite_token": inviteToken,
	}
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("register marshal: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/auth/register", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("register request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("register call: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register status = %d", resp.StatusCode)
	}

	var payload authResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("register decode: %v", err)
	}
	if payload.Token == "" || payload.UserID == "" || payload.DeviceID == "" {
		t.Fatalf("register missing fields")
	}
	return payload
}

func connectWS(t *testing.T, ctx context.Context, serverURL, token string) *websocket.Conn {
	t.Helper()

	wsURL := strings.Replace(serverURL, "https://", "wss://", 1)
	wsURL = strings.Replace(wsURL, "http://", "ws://", 1)
	wsURL = wsURL + "/ws"

	opts := &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": []string{"Bearer " + token}},
	}
	conn, _, err := websocket.Dial(ctx, wsURL, opts)
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	return conn
}

func waitForDeviceJoin(t *testing.T, conn *websocket.Conn, userID string) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		_, data, err := conn.Read(ctx)
		cancel()
		if err != nil {
			continue
		}
		var evt wsEvent
		if err := json.Unmarshal(data, &evt); err != nil {
			continue
		}
		if evt.Type == "device.joined" && evt.Sender == userID {
			return
		}
	}
	if userID == "" {
		t.Fatalf("expected device.joined")
	}
	t.Fatalf("expected device.joined for user %s", userID)
}

func waitForProfileUpdate(t *testing.T, conn *websocket.Conn, userID string) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		_, data, err := conn.Read(ctx)
		cancel()
		if err != nil {
			continue
		}
		var evt wsEvent
		if err := json.Unmarshal(data, &evt); err != nil {
			continue
		}
		if evt.Type == "user.profile.updated" && evt.Sender == userID {
			return
		}
	}
	if userID == "" {
		t.Fatalf("expected user.profile.updated")
	}
	t.Fatalf("expected user.profile.updated for user %s", userID)
}

func waitForWSEvent(t *testing.T, conn *websocket.Conn, predicate func(wsPayload) bool) wsPayload {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		_, data, err := conn.Read(ctx)
		cancel()
		if err != nil {
			continue
		}
		var evt wsPayload
		if err := json.Unmarshal(data, &evt); err != nil {
			continue
		}
		if predicate(evt) {
			return evt
		}
	}
	t.Fatalf("expected websocket event")
	return wsPayload{}
}

func getDirectoryKeyStatus(t *testing.T, ctx context.Context, serverURL, token string) int {
	t.Helper()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, serverURL+"/directory/keys", nil)
	if err != nil {
		t.Fatalf("directory keys request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("directory keys call: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func postUserProfile(t *testing.T, ctx context.Context, serverURL, token, nameEnc string) {
	t.Helper()

	body := map[string]string{"name_enc": nameEnc}
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("profile marshal: %v", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/users/profiles", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("profile request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("profile call: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("profile status = %d", resp.StatusCode)
	}
}

func listProfiles(t *testing.T, ctx context.Context, serverURL, token string) []string {
	t.Helper()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, serverURL+"/users/profiles", nil)
	if err != nil {
		t.Fatalf("list profiles request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("list profiles call: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list profiles status = %d", resp.StatusCode)
	}

	var payload profileListResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("list profiles decode: %v", err)
	}

	ids := make([]string, 0, len(payload.Profiles))
	for _, profile := range payload.Profiles {
		ids = append(ids, profile.UserID)
	}
	return ids
}

func listChannels(t *testing.T, ctx context.Context, serverURL, token string) []string {
	t.Helper()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, serverURL+"/channels", nil)
	if err != nil {
		t.Fatalf("list channels request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("list channels call: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list channels status = %d", resp.StatusCode)
	}

	var payload channelListResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("list channels decode: %v", err)
	}

	ids := make([]string, 0, len(payload.Channels))
	for _, ch := range payload.Channels {
		ids = append(ids, ch.ID)
	}
	return ids
}

func createChannel(t *testing.T, ctx context.Context, serverURL, token, nameEnc string) string {
	t.Helper()

	body := map[string]string{"name_enc": nameEnc}
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("create channel marshal: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/channels", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("create channel request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create channel call: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create channel status = %d", resp.StatusCode)
	}

	var payload channelResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("create channel decode: %v", err)
	}
	if payload.Channel.ID == "" {
		t.Fatalf("create channel missing id")
	}
	return payload.Channel.ID
}

func updateChannel(t *testing.T, ctx context.Context, serverURL, token, channelID, nameEnc string) {
	t.Helper()

	body := map[string]string{"channel_id": channelID, "name_enc": nameEnc}
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("update channel marshal: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, serverURL+"/channels", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("update channel request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("update channel call: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("update channel status = %d", resp.StatusCode)
	}
}

func deleteChannel(t *testing.T, ctx context.Context, serverURL, token, channelID string) {
	t.Helper()

	query := url.Values{}
	query.Set("channel_id", channelID)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, serverURL+"/channels?"+query.Encode(), nil)
	if err != nil {
		t.Fatalf("delete channel request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete channel call: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete channel status = %d", resp.StatusCode)
	}
}

func putChannelKeyEnvelope(t *testing.T, ctx context.Context, serverURL, token, channelID, deviceID, senderPublicKey, envelope string) {
	t.Helper()

	body := map[string]any{
		"channel_id": channelID,
		"envelopes": []map[string]string{{
			"device_id":         deviceID,
			"sender_device_id":  deviceID,
			"sender_public_key": senderPublicKey,
			"envelope":          envelope,
		}},
	}
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("put channel keys marshal: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/channels/keys", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("put channel keys request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("put channel keys call: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("put channel keys status = %d", resp.StatusCode)
	}
}

func getChannelKeyEnvelope(t *testing.T, ctx context.Context, serverURL, token, channelID string) channelKeyEnvelopeResponse {
	t.Helper()

	query := url.Values{}
	query.Set("channel_id", channelID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, serverURL+"/channels/keys?"+query.Encode(), nil)
	if err != nil {
		t.Fatalf("get channel keys request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get channel keys call: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get channel keys status = %d", resp.StatusCode)
	}

	var payload channelKeyEnvelopeResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("get channel keys decode: %v", err)
	}
	return payload
}

func sendChannelMessage(t *testing.T, conn *websocket.Conn, channelID, senderNameEnc, body string) {
	t.Helper()

	msg := map[string]string{
		"type":            "channel.message.send",
		"channel_id":      channelID,
		"body":            body,
		"sender_name_enc": senderNameEnc,
	}
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("send message marshal: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := conn.Write(ctx, websocket.MessageText, data); err != nil {
		t.Fatalf("send message write: %v", err)
	}
}

func waitForPresence(t *testing.T, ctx context.Context, serverURL, token string, ids []string) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		statuses := fetchPresence(t, ctx, serverURL, token, ids)
		ready := true
		for _, id := range ids {
			if !statuses[id] {
				ready = false
				break
			}
		}
		if ready {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("presence never became online for all users")
}

func fetchPresence(t *testing.T, ctx context.Context, serverURL, token string, ids []string) map[string]bool {
	t.Helper()

	body := map[string][]string{"user_ids": ids}
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("presence marshal: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/presence", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("presence request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("presence call: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("presence status = %d", resp.StatusCode)
	}

	var payload presenceResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("presence decode: %v", err)
	}
	if payload.Statuses == nil {
		return map[string]bool{}
	}
	return payload.Statuses
}

func containsProfile(ids []string, userID string) bool {
	for _, id := range ids {
		if id == userID {
			return true
		}
	}
	return false
}

func containsChannel(ids []string, channelID string) bool {
	for _, id := range ids {
		if id == channelID {
			return true
		}
	}
	return false
}

func encryptField(t *testing.T, key []byte, plaintext string) string {
	t.Helper()

	ct, err := crypto.Encrypt(key, []byte(plaintext))
	if err != nil {
		t.Fatalf("encrypt field: %v", err)
	}
	return base64.StdEncoding.EncodeToString(ct)
}

func decryptField(t *testing.T, key []byte, encoded string) string {
	t.Helper()

	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode field: %v", err)
	}
	pt, err := crypto.Decrypt(key, raw)
	if err != nil {
		t.Fatalf("decrypt field: %v", err)
	}
	return string(pt)
}
