package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Avicted/dialtone/internal/auth"
	"github.com/Avicted/dialtone/internal/channel"
	"github.com/Avicted/dialtone/internal/device"
	"github.com/Avicted/dialtone/internal/serverinvite"
	"github.com/Avicted/dialtone/internal/storage"
	"github.com/Avicted/dialtone/internal/user"
)

type memUserRepo struct {
	mu         sync.Mutex
	users      map[user.ID]user.User
	byHash     map[string]user.ID
	profiles   map[user.ID]user.Profile
	dirEnvelop map[string]user.DirectoryKeyEnvelope
}

func newMemUserRepo() *memUserRepo {
	return &memUserRepo{
		users:      make(map[user.ID]user.User),
		byHash:     make(map[string]user.ID),
		profiles:   make(map[user.ID]user.Profile),
		dirEnvelop: make(map[string]user.DirectoryKeyEnvelope),
	}
}

func (r *memUserRepo) Create(_ context.Context, u user.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if u.ID == "" || u.UsernameHash == "" {
		return errors.New("missing required fields")
	}
	if _, ok := r.byHash[u.UsernameHash]; ok {
		return errors.New("duplicate username")
	}
	r.users[u.ID] = u
	r.byHash[u.UsernameHash] = u.ID
	return nil
}

func (r *memUserRepo) GetByID(_ context.Context, id user.ID) (user.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[id]
	if !ok {
		return user.User{}, storage.ErrNotFound
	}
	return u, nil
}

func (r *memUserRepo) GetByUsernameHash(_ context.Context, usernameHash string) (user.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id, ok := r.byHash[usernameHash]
	if !ok {
		return user.User{}, storage.ErrNotFound
	}
	return r.users[id], nil
}

func (r *memUserRepo) Count(_ context.Context) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.users), nil
}

func (r *memUserRepo) UpsertProfile(_ context.Context, profile user.Profile) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.profiles[profile.UserID] = profile
	return nil
}

func (r *memUserRepo) ListProfiles(_ context.Context) ([]user.Profile, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]user.Profile, 0, len(r.profiles))
	for _, profile := range r.profiles {
		out = append(out, profile)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].UpdatedAt.After(out[j].UpdatedAt)
	})
	return out, nil
}

func (r *memUserRepo) UpsertDirectoryKeyEnvelope(_ context.Context, env user.DirectoryKeyEnvelope) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dirEnvelop[env.DeviceID] = env
	return nil
}

func (r *memUserRepo) GetDirectoryKeyEnvelope(_ context.Context, deviceID string) (user.DirectoryKeyEnvelope, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	env, ok := r.dirEnvelop[deviceID]
	if !ok {
		return user.DirectoryKeyEnvelope{}, storage.ErrNotFound
	}
	return env, nil
}

type memDeviceRepo struct {
	mu      sync.Mutex
	devices map[device.ID]device.Device
}

func newMemDeviceRepo() *memDeviceRepo {
	return &memDeviceRepo{devices: make(map[device.ID]device.Device)}
}

func (r *memDeviceRepo) Create(_ context.Context, d device.Device) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.devices[d.ID] = d
	return nil
}

func (r *memDeviceRepo) GetByID(_ context.Context, id device.ID) (device.Device, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.devices[id]
	if !ok {
		return device.Device{}, device.ErrNotFound
	}
	return d, nil
}

func (r *memDeviceRepo) GetByUserAndPublicKey(_ context.Context, userID user.ID, publicKey string) (device.Device, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, d := range r.devices {
		if d.UserID == userID && d.PublicKey == publicKey {
			return d, nil
		}
	}
	return device.Device{}, device.ErrNotFound
}

func (r *memDeviceRepo) ListByUser(_ context.Context, userID user.ID) ([]device.Device, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []device.Device
	for _, d := range r.devices {
		if d.UserID == userID {
			out = append(out, d)
		}
	}
	return out, nil
}

func (r *memDeviceRepo) ListAll(_ context.Context) ([]device.Device, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []device.Device
	for _, d := range r.devices {
		out = append(out, d)
	}
	return out, nil
}

func (r *memDeviceRepo) UpdateLastSeen(_ context.Context, id device.ID, lastSeenAt time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.devices[id]
	if !ok {
		return device.ErrNotFound
	}
	d.LastSeenAt = &lastSeenAt
	r.devices[id] = d
	return nil
}

type memChannelRepo struct {
	mu       sync.Mutex
	channels map[channel.ID]channel.Channel
	messages map[channel.ID][]channel.Message
	keyEnv   map[string]channel.KeyEnvelope
}

func newMemChannelRepo() *memChannelRepo {
	return &memChannelRepo{
		channels: make(map[channel.ID]channel.Channel),
		messages: make(map[channel.ID][]channel.Message),
		keyEnv:   make(map[string]channel.KeyEnvelope),
	}
}

func (r *memChannelRepo) CreateChannel(_ context.Context, ch channel.Channel) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.channels[ch.ID] = ch
	return nil
}

func (r *memChannelRepo) GetChannel(_ context.Context, id channel.ID) (channel.Channel, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ch, ok := r.channels[id]
	if !ok {
		return channel.Channel{}, storage.ErrNotFound
	}
	return ch, nil
}

func (r *memChannelRepo) ListChannels(_ context.Context) ([]channel.Channel, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]channel.Channel, 0, len(r.channels))
	for _, ch := range r.channels {
		out = append(out, ch)
	}
	return out, nil
}

func (r *memChannelRepo) UpdateChannelName(_ context.Context, id channel.ID, nameEnc string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	ch, ok := r.channels[id]
	if !ok {
		return storage.ErrNotFound
	}
	ch.NameEnc = nameEnc
	r.channels[id] = ch
	return nil
}

func (r *memChannelRepo) DeleteChannel(_ context.Context, id channel.ID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.channels[id]; !ok {
		return storage.ErrNotFound
	}
	delete(r.channels, id)
	return nil
}

func (r *memChannelRepo) SaveMessage(_ context.Context, msg channel.Message) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.messages[msg.ChannelID] = append(r.messages[msg.ChannelID], msg)
	return nil
}

func (r *memChannelRepo) ListRecentMessages(_ context.Context, channelID channel.ID, limit int) ([]channel.Message, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	msgs := r.messages[channelID]
	if limit <= 0 || len(msgs) == 0 {
		return nil, nil
	}
	if limit > len(msgs) {
		limit = len(msgs)
	}
	return append([]channel.Message(nil), msgs[len(msgs)-limit:]...), nil
}

func (r *memChannelRepo) UpsertKeyEnvelope(_ context.Context, env channel.KeyEnvelope) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := string(env.ChannelID) + ":" + string(env.DeviceID)
	r.keyEnv[key] = env
	return nil
}

func (r *memChannelRepo) GetKeyEnvelope(_ context.Context, channelID channel.ID, deviceID device.ID) (channel.KeyEnvelope, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := string(channelID) + ":" + string(deviceID)
	env, ok := r.keyEnv[key]
	if !ok {
		return channel.KeyEnvelope{}, storage.ErrNotFound
	}
	return env, nil
}

type memInviteRepo struct {
	mu      sync.Mutex
	invites map[string]serverinvite.Invite
}

func newMemInviteRepo() *memInviteRepo {
	return &memInviteRepo{invites: make(map[string]serverinvite.Invite)}
}

func (r *memInviteRepo) Create(_ context.Context, invite serverinvite.Invite) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.invites[invite.Token] = invite
	return nil
}

func (r *memInviteRepo) Consume(_ context.Context, token string, userID user.ID, now time.Time) (serverinvite.Invite, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	invite, ok := r.invites[token]
	if !ok {
		return serverinvite.Invite{}, serverinvite.ErrNotFound
	}
	if invite.ConsumedAt != nil {
		return serverinvite.Invite{}, serverinvite.ErrConsumed
	}
	if !invite.ExpiresAt.IsZero() && !invite.ExpiresAt.After(now) {
		return serverinvite.Invite{}, serverinvite.ErrExpired
	}
	invite.ConsumedAt = &now
	invite.ConsumedBy = &userID
	r.invites[token] = invite
	return invite, nil
}

type fakePresence struct {
	online map[user.ID]bool
}

func (p fakePresence) IsOnline(userID user.ID) bool {
	return p.online[userID]
}

type fakeNotifier struct {
	updated []channel.ID
	deleted []channel.ID
}

func (n *fakeNotifier) NotifyChannelUpdated(ch channel.Channel) {
	n.updated = append(n.updated, ch.ID)
}

func (n *fakeNotifier) NotifyChannelDeleted(id channel.ID) {
	n.deleted = append(n.deleted, id)
}

type fakeUserNotify struct {
	updated []user.ID
}

func (n *fakeUserNotify) NotifyUserProfileUpdated(id user.ID) {
	n.updated = append(n.updated, id)
}

type httpTestEnv struct {
	handler     *Handler
	mux         *http.ServeMux
	server      *httptest.Server
	userRepo    *memUserRepo
	deviceRepo  *memDeviceRepo
	channelRepo *memChannelRepo
	inviteRepo  *memInviteRepo
	adminToken  string
}

func newHTTPTestEnv(t *testing.T, presence PresenceProvider, notifier ChannelNotifier, userNotify UserNotifier) *httpTestEnv {
	t.Helper()

	userRepo := newMemUserRepo()
	deviceRepo := newMemDeviceRepo()
	channelRepo := newMemChannelRepo()
	inviteRepo := newMemInviteRepo()

	userSvc := user.NewService(userRepo, "test-pepper")
	deviceSvc := device.NewService(deviceRepo)
	channelSvc := channel.NewService(channelRepo, userSvc)
	inviteSvc := serverinvite.NewService(inviteRepo)
	authSvc := auth.NewService(userSvc, deviceSvc, inviteSvc)

	h := NewHandler(userSvc, deviceSvc, channelSvc, authSvc, inviteSvc, presence, notifier, userNotify, "admin-token")
	mux := http.NewServeMux()
	h.Register(mux)

	srv := httptest.NewServer(mux)
	return &httpTestEnv{
		handler:     h,
		mux:         mux,
		server:      srv,
		userRepo:    userRepo,
		deviceRepo:  deviceRepo,
		channelRepo: channelRepo,
		inviteRepo:  inviteRepo,
		adminToken:  "admin-token",
	}
}

func (e *httpTestEnv) close() {
	e.server.Close()
}

func createInviteHTTP(t *testing.T, baseURL, adminToken string) string {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, baseURL+"/server/invites", nil)
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
	var payload createServerInviteResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("invite decode: %v", err)
	}
	return payload.Token
}

func registerHTTP(t *testing.T, baseURL, username, inviteToken string) authResponse {
	t.Helper()

	body := map[string]string{
		"username":     username,
		"password":     "password123",
		"public_key":   "pubkey-" + username,
		"invite_token": inviteToken,
	}
	data, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, baseURL+"/auth/register", bytes.NewReader(data))
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
	return payload
}

func loginHTTP(t *testing.T, baseURL, username string) authResponse {
	t.Helper()

	body := map[string]string{
		"username":   username,
		"password":   "password123",
		"public_key": "pubkey-" + username,
	}
	data, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, baseURL+"/auth/login", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("login request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("login call: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d", resp.StatusCode)
	}
	var payload authResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("login decode: %v", err)
	}
	return payload
}

func TestHandlers_ServerInviteAndAuth(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	if strings.TrimSpace(invite) == "" {
		t.Fatal("invite token empty")
	}

	register := registerHTTP(t, env.server.URL, "admin", invite)
	if register.Token == "" || register.UserID == "" {
		t.Fatal("register missing fields")
	}

	login := loginHTTP(t, env.server.URL, "admin")
	if login.Token == "" || login.UserID == "" {
		t.Fatal("login missing fields")
	}
}

func TestHandlers_UsersAndProfiles(t *testing.T) {
	userNotify := &fakeUserNotify{}
	env := newHTTPTestEnv(t, nil, nil, userNotify)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	authResp := registerHTTP(t, env.server.URL, "alice", invite)

	userReq := map[string]string{"username": "bob"}
	userData, _ := json.Marshal(userReq)
	userReqHTTP, _ := http.NewRequest(http.MethodPost, env.server.URL+"/users", bytes.NewReader(userData))
	userReqHTTP.Header.Set("Content-Type", "application/json")
	userResp, err := http.DefaultClient.Do(userReqHTTP)
	if err != nil {
		t.Fatalf("users call: %v", err)
	}
	defer userResp.Body.Close()
	if userResp.StatusCode != http.StatusCreated {
		t.Fatalf("users status = %d", userResp.StatusCode)
	}

	profileReq := map[string]string{"name_enc": "enc-name"}
	profileData, _ := json.Marshal(profileReq)
	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/users/profiles", bytes.NewReader(profileData))
	req.Header.Set("Authorization", "Bearer "+authResp.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("profiles post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("profiles status = %d", resp.StatusCode)
	}
	if len(userNotify.updated) != 1 {
		t.Fatalf("expected profile notify, got %d", len(userNotify.updated))
	}

	getReq, _ := http.NewRequest(http.MethodGet, env.server.URL+"/users/profiles", nil)
	getReq.Header.Set("Authorization", "Bearer "+authResp.Token)
	getResp, err := http.DefaultClient.Do(getReq)
	if err != nil {
		t.Fatalf("profiles get: %v", err)
	}
	defer getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("profiles get status = %d", getResp.StatusCode)
	}
}

func TestHandlers_DevicesAndKeys(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	authResp := registerHTTP(t, env.server.URL, "alice", invite)

	deviceReq := map[string]string{
		"user_id":    string(authResp.UserID),
		"public_key": "pubkey-device",
	}
	payload, _ := json.Marshal(deviceReq)
	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/devices", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+authResp.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("devices call: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("devices status = %d", resp.StatusCode)
	}

	keysReq, _ := http.NewRequest(http.MethodGet, env.server.URL+"/devices/keys?user_id="+string(authResp.UserID), nil)
	keysReq.Header.Set("Authorization", "Bearer "+authResp.Token)
	keysResp, err := http.DefaultClient.Do(keysReq)
	if err != nil {
		t.Fatalf("devices keys: %v", err)
	}
	defer keysResp.Body.Close()
	if keysResp.StatusCode != http.StatusOK {
		t.Fatalf("device keys status = %d", keysResp.StatusCode)
	}
}

func TestHandlers_DirectoryKeys(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	authResp := registerHTTP(t, env.server.URL, "alice", invite)

	getReq, _ := http.NewRequest(http.MethodGet, env.server.URL+"/directory/keys", nil)
	getReq.Header.Set("Authorization", "Bearer "+authResp.Token)
	getResp, err := http.DefaultClient.Do(getReq)
	if err != nil {
		t.Fatalf("directory get: %v", err)
	}
	defer getResp.Body.Close()
	if getResp.StatusCode != http.StatusNoContent {
		t.Fatalf("directory get status = %d", getResp.StatusCode)
	}

	postReq := map[string]any{"envelopes": []map[string]string{{
		"device_id":         string(authResp.DeviceID),
		"sender_device_id":  string(authResp.DeviceID),
		"sender_public_key": "pubkey-alice",
		"envelope":          "env",
	}}}
	postData, _ := json.Marshal(postReq)
	post, _ := http.NewRequest(http.MethodPost, env.server.URL+"/directory/keys", bytes.NewReader(postData))
	post.Header.Set("Authorization", "Bearer "+authResp.Token)
	post.Header.Set("Content-Type", "application/json")
	postResp, err := http.DefaultClient.Do(post)
	if err != nil {
		t.Fatalf("directory post: %v", err)
	}
	defer postResp.Body.Close()
	if postResp.StatusCode != http.StatusCreated {
		t.Fatalf("directory post status = %d", postResp.StatusCode)
	}
}

func TestHandlers_ChannelsAndMessages(t *testing.T) {
	notifier := &fakeNotifier{}
	env := newHTTPTestEnv(t, nil, notifier, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	authResp := registerHTTP(t, env.server.URL, "admin", invite)

	channelReq := map[string]string{"name_enc": "enc-name"}
	channelData, _ := json.Marshal(channelReq)
	createReq, _ := http.NewRequest(http.MethodPost, env.server.URL+"/channels", bytes.NewReader(channelData))
	createReq.Header.Set("Authorization", "Bearer "+authResp.Token)
	createReq.Header.Set("Content-Type", "application/json")
	createResp, err := http.DefaultClient.Do(createReq)
	if err != nil {
		t.Fatalf("channels create: %v", err)
	}
	defer createResp.Body.Close()
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("channels create status = %d", createResp.StatusCode)
	}

	var createdResp createChannelResponse
	_ = json.NewDecoder(createResp.Body).Decode(&createdResp)
	channelID := createdResp.Channel.ID

	updateReq := map[string]string{"channel_id": string(channelID), "name_enc": "enc-name-2"}
	updateData, _ := json.Marshal(updateReq)
	patchReq, _ := http.NewRequest(http.MethodPatch, env.server.URL+"/channels", bytes.NewReader(updateData))
	patchReq.Header.Set("Authorization", "Bearer "+authResp.Token)
	patchReq.Header.Set("Content-Type", "application/json")
	patchResp, err := http.DefaultClient.Do(patchReq)
	if err != nil {
		t.Fatalf("channels patch: %v", err)
	}
	defer patchResp.Body.Close()
	if patchResp.StatusCode != http.StatusOK {
		t.Fatalf("channels patch status = %d", patchResp.StatusCode)
	}

	listReq, _ := http.NewRequest(http.MethodGet, env.server.URL+"/channels", nil)
	listReq.Header.Set("Authorization", "Bearer "+authResp.Token)
	listResp, err := http.DefaultClient.Do(listReq)
	if err != nil {
		t.Fatalf("channels list: %v", err)
	}
	defer listResp.Body.Close()
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("channels list status = %d", listResp.StatusCode)
	}

	_ = env.channelRepo.SaveMessage(context.Background(), channel.Message{
		ID:            "msg-1",
		ChannelID:     channelID,
		SenderID:      user.ID(authResp.UserID),
		SenderNameEnc: "enc-sender",
		Body:          "enc-body",
		SentAt:        time.Now().UTC(),
	})

	msgReq, _ := http.NewRequest(http.MethodGet, env.server.URL+"/channels/messages?channel_id="+string(channelID), nil)
	msgReq.Header.Set("Authorization", "Bearer "+authResp.Token)
	msgResp, err := http.DefaultClient.Do(msgReq)
	if err != nil {
		t.Fatalf("channels messages: %v", err)
	}
	defer msgResp.Body.Close()
	if msgResp.StatusCode != http.StatusOK {
		t.Fatalf("channels messages status = %d", msgResp.StatusCode)
	}

	deleteReq, _ := http.NewRequest(http.MethodDelete, env.server.URL+"/channels?channel_id="+string(channelID), nil)
	deleteReq.Header.Set("Authorization", "Bearer "+authResp.Token)
	deleteResp, err := http.DefaultClient.Do(deleteReq)
	if err != nil {
		t.Fatalf("channels delete: %v", err)
	}
	defer deleteResp.Body.Close()
	if deleteResp.StatusCode != http.StatusNoContent {
		t.Fatalf("channels delete status = %d", deleteResp.StatusCode)
	}
	if len(notifier.updated) == 0 || len(notifier.deleted) == 0 {
		t.Fatalf("expected notifier callbacks")
	}
}

func TestHandlers_ChannelKeys(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	authResp := registerHTTP(t, env.server.URL, "admin", invite)

	channelID := channel.ID("ch-1")
	_ = env.channelRepo.CreateChannel(context.Background(), channel.Channel{
		ID:        channelID,
		NameEnc:   "enc",
		CreatedBy: user.ID(authResp.UserID),
		CreatedAt: time.Now().UTC(),
	})

	postBody := map[string]any{
		"channel_id": channelID,
		"envelopes": []map[string]string{{
			"device_id":         string(authResp.DeviceID),
			"sender_device_id":  string(authResp.DeviceID),
			"sender_public_key": "pubkey-admin",
			"envelope":          "env",
		}},
	}
	postData, _ := json.Marshal(postBody)
	postReq, _ := http.NewRequest(http.MethodPost, env.server.URL+"/channels/keys", bytes.NewReader(postData))
	postReq.Header.Set("Authorization", "Bearer "+authResp.Token)
	postReq.Header.Set("Content-Type", "application/json")
	postResp, err := http.DefaultClient.Do(postReq)
	if err != nil {
		t.Fatalf("channel keys post: %v", err)
	}
	defer postResp.Body.Close()
	if postResp.StatusCode != http.StatusCreated {
		t.Fatalf("channel keys post status = %d", postResp.StatusCode)
	}

	getReq, _ := http.NewRequest(http.MethodGet, env.server.URL+"/channels/keys?channel_id="+string(channelID), nil)
	getReq.Header.Set("Authorization", "Bearer "+authResp.Token)
	getResp, err := http.DefaultClient.Do(getReq)
	if err != nil {
		t.Fatalf("channel keys get: %v", err)
	}
	defer getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("channel keys get status = %d", getResp.StatusCode)
	}
}

func TestHandlers_Presence(t *testing.T) {
	presence := fakePresence{online: map[user.ID]bool{"u1": true, "u2": false}}
	env := newHTTPTestEnv(t, presence, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	authResp := registerHTTP(t, env.server.URL, "admin", invite)

	body := map[string][]string{"user_ids": {"u1", "u2"}}
	data, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/presence", bytes.NewReader(data))
	req.Header.Set("Authorization", "Bearer "+authResp.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("presence call: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("presence status = %d", resp.StatusCode)
	}
}

func TestHandlers_DeviceKeys_AllAndErrors(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite1 := createInviteHTTP(t, env.server.URL, env.adminToken)
	authResp1 := registerHTTP(t, env.server.URL, "alice", invite1)

	invite2 := createInviteHTTP(t, env.server.URL, env.adminToken)
	authResp2 := registerHTTP(t, env.server.URL, "bob", invite2)

	allReq, _ := http.NewRequest(http.MethodGet, env.server.URL+"/devices/keys?all=1", nil)
	allReq.Header.Set("Authorization", "Bearer "+authResp1.Token)
	allResp, err := http.DefaultClient.Do(allReq)
	if err != nil {
		t.Fatalf("device keys all: %v", err)
	}
	defer allResp.Body.Close()
	if allResp.StatusCode != http.StatusOK {
		t.Fatalf("device keys all status = %d", allResp.StatusCode)
	}
	var allPayload deviceKeysResponse
	if err := json.NewDecoder(allResp.Body).Decode(&allPayload); err != nil {
		t.Fatalf("device keys all decode: %v", err)
	}
	if len(allPayload.Keys) < 2 {
		t.Fatalf("device keys all count = %d", len(allPayload.Keys))
	}
	seenUsers := map[user.ID]bool{}
	for _, key := range allPayload.Keys {
		seenUsers[key.UserID] = true
	}
	if !seenUsers[authResp1.UserID] || !seenUsers[authResp2.UserID] {
		t.Fatalf("device keys all missing users")
	}

	missingReq, _ := http.NewRequest(http.MethodGet, env.server.URL+"/devices/keys", nil)
	missingReq.Header.Set("Authorization", "Bearer "+authResp1.Token)
	missingResp, err := http.DefaultClient.Do(missingReq)
	if err != nil {
		t.Fatalf("device keys missing: %v", err)
	}
	defer missingResp.Body.Close()
	if missingResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("device keys missing status = %d", missingResp.StatusCode)
	}

	forbiddenReq, _ := http.NewRequest(http.MethodGet, env.server.URL+"/devices/keys?user_id="+string(authResp2.UserID), nil)
	forbiddenReq.Header.Set("Authorization", "Bearer "+authResp1.Token)
	forbiddenResp, err := http.DefaultClient.Do(forbiddenReq)
	if err != nil {
		t.Fatalf("device keys forbidden: %v", err)
	}
	defer forbiddenResp.Body.Close()
	if forbiddenResp.StatusCode != http.StatusForbidden {
		t.Fatalf("device keys forbidden status = %d", forbiddenResp.StatusCode)
	}
}

func TestHandlers_DirectoryKeys_SenderMismatch(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	authResp := registerHTTP(t, env.server.URL, "alice", invite)

	body := map[string]any{"envelopes": []map[string]string{{
		"device_id":         string(authResp.DeviceID),
		"sender_device_id":  "other-device",
		"sender_public_key": "pubkey-alice",
		"envelope":          "env",
	}}}
	data, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/directory/keys", bytes.NewReader(data))
	req.Header.Set("Authorization", "Bearer "+authResp.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("directory keys sender mismatch: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("directory keys sender mismatch status = %d", resp.StatusCode)
	}
}

func TestHandlers_ChannelKeys_Errors(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	authResp := registerHTTP(t, env.server.URL, "admin", invite)

	missingReq, _ := http.NewRequest(http.MethodGet, env.server.URL+"/channels/keys", nil)
	missingReq.Header.Set("Authorization", "Bearer "+authResp.Token)
	missingResp, err := http.DefaultClient.Do(missingReq)
	if err != nil {
		t.Fatalf("channel keys missing: %v", err)
	}
	defer missingResp.Body.Close()
	if missingResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("channel keys missing status = %d", missingResp.StatusCode)
	}

	noChannelBody := map[string]any{
		"channel_id": "missing",
		"envelopes": []map[string]string{{
			"device_id":         string(authResp.DeviceID),
			"sender_device_id":  string(authResp.DeviceID),
			"sender_public_key": "pubkey-admin",
			"envelope":          "env",
		}},
	}
	noChannelData, _ := json.Marshal(noChannelBody)
	noChannelReq, _ := http.NewRequest(http.MethodPost, env.server.URL+"/channels/keys", bytes.NewReader(noChannelData))
	noChannelReq.Header.Set("Authorization", "Bearer "+authResp.Token)
	noChannelReq.Header.Set("Content-Type", "application/json")
	noChannelResp, err := http.DefaultClient.Do(noChannelReq)
	if err != nil {
		t.Fatalf("channel keys not found: %v", err)
	}
	defer noChannelResp.Body.Close()
	if noChannelResp.StatusCode != http.StatusNotFound {
		t.Fatalf("channel keys not found status = %d", noChannelResp.StatusCode)
	}

	channelID := channel.ID("ch-1")
	_ = env.channelRepo.CreateChannel(context.Background(), channel.Channel{
		ID:        channelID,
		NameEnc:   "enc",
		CreatedBy: authResp.UserID,
		CreatedAt: time.Now().UTC(),
	})

	mismatchBody := map[string]any{
		"channel_id": channelID,
		"envelopes": []map[string]string{{
			"device_id":         string(authResp.DeviceID),
			"sender_device_id":  "other-device",
			"sender_public_key": "pubkey-admin",
			"envelope":          "env",
		}},
	}
	mismatchData, _ := json.Marshal(mismatchBody)
	mismatchReq, _ := http.NewRequest(http.MethodPost, env.server.URL+"/channels/keys", bytes.NewReader(mismatchData))
	mismatchReq.Header.Set("Authorization", "Bearer "+authResp.Token)
	mismatchReq.Header.Set("Content-Type", "application/json")
	mismatchResp, err := http.DefaultClient.Do(mismatchReq)
	if err != nil {
		t.Fatalf("channel keys mismatch: %v", err)
	}
	defer mismatchResp.Body.Close()
	if mismatchResp.StatusCode != http.StatusForbidden {
		t.Fatalf("channel keys mismatch status = %d", mismatchResp.StatusCode)
	}
}

func TestHandlers_ServerInvites_AdminAccessRequired(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/server/invites", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("server invite no auth: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("server invite no auth status = %d", resp.StatusCode)
	}

	adminInvite := createInviteHTTP(t, env.server.URL, env.adminToken)
	_ = registerHTTP(t, env.server.URL, "admin", adminInvite)

	bobInvite := createInviteHTTP(t, env.server.URL, env.adminToken)
	bobAuth := registerHTTP(t, env.server.URL, "bob", bobInvite)

	userReq, _ := http.NewRequest(http.MethodPost, env.server.URL+"/server/invites", nil)
	userReq.Header.Set("Authorization", "Bearer "+bobAuth.Token)
	userResp, err := http.DefaultClient.Do(userReq)
	if err != nil {
		t.Fatalf("server invite user: %v", err)
	}
	defer userResp.Body.Close()
	if userResp.StatusCode != http.StatusForbidden {
		t.Fatalf("server invite user status = %d", userResp.StatusCode)
	}
}

func TestDecodeJSONMultipleObjects(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"a":1}{"b":2}`))
	var dst map[string]int
	if err := decodeJSON(rec, req, &dst); err == nil {
		t.Fatal("expected error for multiple json objects")
	}
}

func TestWriteError(t *testing.T) {
	rec := httptest.NewRecorder()
	writeError(rec, http.StatusBadRequest, errors.New("bad request"))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}

	var payload map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if payload["error"] != "bad request" {
		t.Fatalf("error = %q, want %q", payload["error"], "bad request")
	}
}

func TestWriteError_ServerError(t *testing.T) {
	rec := httptest.NewRecorder()
	writeError(rec, http.StatusInternalServerError, errors.New("internal error"))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// --- Method Not Allowed tests ---

func TestHandlers_MethodNotAllowed(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	tests := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/auth/register"},
		{http.MethodPut, "/auth/register"},
		{http.MethodGet, "/auth/login"},
		{http.MethodPut, "/auth/login"},
		{http.MethodGet, "/users"},
		{http.MethodDelete, "/users"},
		{http.MethodDelete, "/users/profiles"},
		{http.MethodGet, "/devices"},
		{http.MethodDelete, "/devices"},
		{http.MethodPost, "/devices/keys"},
		{http.MethodDelete, "/devices/keys"},
		{http.MethodDelete, "/directory/keys"},
		{http.MethodDelete, "/channels/keys"},
		{http.MethodPost, "/channels/messages"},
		{http.MethodDelete, "/channels/messages"},
		{http.MethodGet, "/presence"},
		{http.MethodDelete, "/presence"},
		{http.MethodGet, "/server/invites"},
		{http.MethodDelete, "/server/invites"},
		{http.MethodPut, "/channels"},
	}
	for _, tc := range tests {
		req, _ := http.NewRequest(tc.method, env.server.URL+tc.path, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", tc.method, tc.path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: status = %d, want 405", tc.method, tc.path, resp.StatusCode)
		}
	}
}

// --- Nil service tests ---

func TestHandlers_Register_NilAuth(t *testing.T) {
	h := NewHandler(nil, nil, nil, nil, nil, nil, nil, nil, "")
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	body := `{"username":"alice","password":"pass123A","public_key":"pub","invite_token":"tok"}`
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/auth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("register nil auth: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
}

func TestHandlers_Login_NilAuth(t *testing.T) {
	h := NewHandler(nil, nil, nil, nil, nil, nil, nil, nil, "")
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	body := `{"username":"alice","password":"pass123A","public_key":"pub"}`
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("login nil auth: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
}

func TestHandlers_Register_InvalidJSON(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/auth/register", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("register invalid json: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandlers_Login_InvalidJSON(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/auth/login", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("login invalid json: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandlers_Register_BadInput(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	// Empty username
	body := `{"username":"","password":"pass123A","public_key":"pub","invite_token":"tok"}`
	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/auth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("register bad input: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandlers_Register_ExpiredInvite(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	// Create and expire an invite
	token := createInviteHTTP(t, env.server.URL, env.adminToken)
	env.inviteRepo.mu.Lock()
	inv := env.inviteRepo.invites[token]
	past := time.Now().Add(-time.Hour)
	inv.ExpiresAt = past
	env.inviteRepo.invites[token] = inv
	env.inviteRepo.mu.Unlock()

	body, _ := json.Marshal(map[string]string{
		"username": "alice", "password": "password123",
		"public_key": "pub", "invite_token": token,
	})
	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("register expired invite: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusGone {
		t.Fatalf("status = %d, want 410", resp.StatusCode)
	}
}

func TestHandlers_Register_NotFoundInvite(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	body, _ := json.Marshal(map[string]string{
		"username": "alice", "password": "password123",
		"public_key": "pub", "invite_token": "nonexistent-token",
	})
	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("register not found invite: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestHandlers_Register_ConsumedInvite(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	token := createInviteHTTP(t, env.server.URL, env.adminToken)
	_ = registerHTTP(t, env.server.URL, "alice", token)

	body, _ := json.Marshal(map[string]string{
		"username": "bob", "password": "password123",
		"public_key": "pub2", "invite_token": token,
	})
	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("register consumed invite: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusGone {
		t.Fatalf("status = %d, want 410", resp.StatusCode)
	}
}

func TestHandlers_Login_BadCredentials(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	_ = registerHTTP(t, env.server.URL, "alice", invite)

	body, _ := json.Marshal(map[string]string{
		"username": "alice", "password": "wrongpassword1",
		"public_key": "pub",
	})
	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("login bad creds: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestHandlers_Login_EmptyUsername(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	body := `{"username":"","password":"password123","public_key":"pub"}`
	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("login empty username: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

// --- authenticate and authenticateTrusted ---

func TestHandlers_UserProfiles_Untrusted(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	admin := registerHTTP(t, env.server.URL, "admin", invite)

	// Mark admin as NOT trusted
	env.userRepo.mu.Lock()
	u := env.userRepo.users[admin.UserID]
	u.IsTrusted = false
	env.userRepo.users[admin.UserID] = u
	env.userRepo.mu.Unlock()

	req, _ := http.NewRequest(http.MethodGet, env.server.URL+"/users/profiles", nil)
	req.Header.Set("Authorization", "Bearer "+admin.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("profiles untrusted: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestHandlers_UserProfiles_NilUsers(t *testing.T) {
	h := NewHandler(nil, nil, nil, nil, nil, nil, nil, nil, "")
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/users/profiles", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("profiles nil users: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
}

func TestHandlers_UserProfiles_InvalidJSON(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	auth := registerHTTP(t, env.server.URL, "alice", invite)

	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/users/profiles", strings.NewReader("not json"))
	req.Header.Set("Authorization", "Bearer "+auth.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("profiles invalid json: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandlers_UserProfiles_InvalidInput(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	auth := registerHTTP(t, env.server.URL, "alice", invite)

	// Empty name_enc
	body := `{"name_enc":"   "}`
	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/users/profiles", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+auth.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("profiles invalid input: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

// --- Devices ---

func TestHandlers_Devices_Forbidden(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite1 := createInviteHTTP(t, env.server.URL, env.adminToken)
	alice := registerHTTP(t, env.server.URL, "alice", invite1)

	invite2 := createInviteHTTP(t, env.server.URL, env.adminToken)
	bob := registerHTTP(t, env.server.URL, "bob", invite2)

	// alice tries to create device for bob
	body, _ := json.Marshal(map[string]string{
		"user_id": string(bob.UserID), "public_key": "pub",
	})
	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/devices", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+alice.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("devices forbidden: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestHandlers_Devices_UserNotFound(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	auth := registerHTTP(t, env.server.URL, "alice", invite)

	// Delete the user from repo so the GetByID fails
	env.userRepo.mu.Lock()
	delete(env.userRepo.users, auth.UserID)
	env.userRepo.mu.Unlock()

	body, _ := json.Marshal(map[string]string{
		"user_id": string(auth.UserID), "public_key": "new-pub",
	})
	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/devices", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+auth.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("devices user not found: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestHandlers_Devices_NoAuth(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	body := `{"user_id":"uid","public_key":"pub"}`
	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/devices", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("devices no auth: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestHandlers_Devices_InvalidJSON(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	auth := registerHTTP(t, env.server.URL, "alice", invite)

	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/devices", strings.NewReader("not json"))
	req.Header.Set("Authorization", "Bearer "+auth.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("devices invalid json: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

// --- Channel messages errors ---

func TestHandlers_ChannelMessages_NilChannels(t *testing.T) {
	h := NewHandler(nil, nil, nil, nil, nil, nil, nil, nil, "")
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/channels/messages?channel_id=ch-1", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("channel messages nil: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
}

func TestHandlers_ChannelMessages_NoAuth(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	req, _ := http.NewRequest(http.MethodGet, env.server.URL+"/channels/messages?channel_id=ch-1", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("channel messages no auth: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestHandlers_ChannelMessages_MissingChannelID(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	auth := registerHTTP(t, env.server.URL, "alice", invite)

	req, _ := http.NewRequest(http.MethodGet, env.server.URL+"/channels/messages", nil)
	req.Header.Set("Authorization", "Bearer "+auth.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("channel messages missing: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandlers_ChannelMessages_WithLimit(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	auth := registerHTTP(t, env.server.URL, "admin", invite)

	channelID := channel.ID("ch-1")
	_ = env.channelRepo.CreateChannel(context.Background(), channel.Channel{
		ID: channelID, NameEnc: "enc", CreatedBy: auth.UserID, CreatedAt: time.Now().UTC(),
	})
	for i := 0; i < 5; i++ {
		_ = env.channelRepo.SaveMessage(context.Background(), channel.Message{
			ID: "msg-" + strings.Repeat("x", i+1), ChannelID: channelID,
			SenderID: auth.UserID, Body: "body", SentAt: time.Now().UTC(),
		})
	}

	req, _ := http.NewRequest(http.MethodGet, env.server.URL+"/channels/messages?channel_id="+string(channelID)+"&limit=2", nil)
	req.Header.Set("Authorization", "Bearer "+auth.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("channel messages limit: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var payload channelMessagesResponse
	_ = json.NewDecoder(resp.Body).Decode(&payload)
	if len(payload.Messages) != 2 {
		t.Fatalf("messages = %d, want 2", len(payload.Messages))
	}
}

func TestHandlers_ChannelMessages_InvalidLimit(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	auth := registerHTTP(t, env.server.URL, "admin", invite)

	channelID := channel.ID("ch-1")
	_ = env.channelRepo.CreateChannel(context.Background(), channel.Channel{
		ID: channelID, NameEnc: "enc", CreatedBy: auth.UserID, CreatedAt: time.Now().UTC(),
	})

	// "abc" is not a valid int, should be ignored and default to 0
	req, _ := http.NewRequest(http.MethodGet, env.server.URL+"/channels/messages?channel_id="+string(channelID)+"&limit=abc", nil)
	req.Header.Set("Authorization", "Bearer "+auth.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("channel messages invalid limit: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

// --- Presence ---

func TestHandlers_Presence_NilProvider(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	auth := registerHTTP(t, env.server.URL, "alice", invite)

	body := `{"user_ids":["u1","u2"]}`
	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/presence", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+auth.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("presence nil: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestHandlers_Presence_EmptyUserIDs(t *testing.T) {
	presence := fakePresence{online: map[user.ID]bool{}}
	env := newHTTPTestEnv(t, presence, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	auth := registerHTTP(t, env.server.URL, "alice", invite)

	body := `{"user_ids":["","u1"]}`
	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/presence", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+auth.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("presence empty ids: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestHandlers_Presence_NoAuth(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	body := `{"user_ids":["u1"]}`
	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/presence", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("presence no auth: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

// --- Admin authentication ---

func TestAuthenticateAdmin_EmptyToken(t *testing.T) {
	h := &Handler{adminToken: ""}
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	if h.authenticateAdmin(req) {
		t.Fatal("expected false for empty admin token")
	}
}

func TestAuthenticateAdmin_ValidToken(t *testing.T) {
	h := &Handler{adminToken: "admin-secret"}
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("X-Admin-Token", "admin-secret")
	if !h.authenticateAdmin(req) {
		t.Fatal("expected true for valid admin token")
	}
}

func TestAuthenticateAdmin_InvalidToken(t *testing.T) {
	h := &Handler{adminToken: "admin-secret"}
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("X-Admin-Token", "wrong-token")
	if h.authenticateAdmin(req) {
		t.Fatal("expected false for invalid admin token")
	}
}

func TestAuthenticateAdmin_WhitespaceToken(t *testing.T) {
	h := &Handler{adminToken: "  "}
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	if h.authenticateAdmin(req) {
		t.Fatal("expected false for whitespace admin token")
	}
}

// --- Channel keys ---

func TestHandlers_ChannelKeys_NilChannels(t *testing.T) {
	h := NewHandler(nil, nil, nil, nil, nil, nil, nil, nil, "")
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/channels/keys?channel_id=ch-1", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("channel keys nil: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
}

func TestHandlers_ChannelKeys_PostEmptyEnvelopes(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	auth := registerHTTP(t, env.server.URL, "admin", invite)

	body := `{"channel_id":"ch-1","envelopes":[]}`
	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/channels/keys", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+auth.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("channel keys empty envelopes: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandlers_ChannelKeys_PostEmptyChannelID(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	auth := registerHTTP(t, env.server.URL, "admin", invite)

	body := `{"channel_id":"","envelopes":[{"device_id":"d","sender_device_id":"d","envelope":"e"}]}`
	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/channels/keys", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+auth.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("channel keys empty channel_id: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandlers_ChannelKeys_GetNotFound(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	auth := registerHTTP(t, env.server.URL, "admin", invite)

	_ = env.channelRepo.CreateChannel(context.Background(), channel.Channel{
		ID: "ch-1", NameEnc: "enc", CreatedBy: auth.UserID, CreatedAt: time.Now().UTC(),
	})

	req, _ := http.NewRequest(http.MethodGet, env.server.URL+"/channels/keys?channel_id=ch-1", nil)
	req.Header.Set("Authorization", "Bearer "+auth.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("channel keys get not found: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

// --- Directory keys ---

func TestHandlers_DirectoryKeys_NilUsers(t *testing.T) {
	h := NewHandler(nil, nil, nil, nil, nil, nil, nil, nil, "")
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/directory/keys", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("directory keys nil users: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
}

func TestHandlers_DirectoryKeys_PostEmptyEnvelopes(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	auth := registerHTTP(t, env.server.URL, "alice", invite)

	body := `{"envelopes":[]}`
	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/directory/keys", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+auth.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("directory keys empty envelopes: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandlers_DirectoryKeys_GetFound(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	auth := registerHTTP(t, env.server.URL, "alice", invite)

	// Set a directory key envelope so GET returns 200
	env.userRepo.mu.Lock()
	env.userRepo.dirEnvelop[string(auth.DeviceID)] = user.DirectoryKeyEnvelope{
		DeviceID:        string(auth.DeviceID),
		SenderDeviceID:  string(auth.DeviceID),
		SenderPublicKey: "pub",
		Envelope:        "env",
		CreatedAt:       time.Now().UTC(),
	}
	env.userRepo.mu.Unlock()

	getReq, _ := http.NewRequest(http.MethodGet, env.server.URL+"/directory/keys", nil)
	getReq.Header.Set("Authorization", "Bearer "+auth.Token)
	getResp, err := http.DefaultClient.Do(getReq)
	if err != nil {
		t.Fatalf("directory keys get: %v", err)
	}
	defer getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", getResp.StatusCode)
	}
}

// --- Channels errors ---

func TestHandlers_Channels_NilChannels(t *testing.T) {
	h := NewHandler(nil, nil, nil, nil, nil, nil, nil, nil, "")
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/channels", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("channels nil: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
}

func TestHandlers_Channels_NoAuth(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	req, _ := http.NewRequest(http.MethodGet, env.server.URL+"/channels", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("channels no auth: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestHandlers_Channels_NotAdmin(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite1 := createInviteHTTP(t, env.server.URL, env.adminToken)
	_ = registerHTTP(t, env.server.URL, "admin", invite1)

	invite2 := createInviteHTTP(t, env.server.URL, env.adminToken)
	bob := registerHTTP(t, env.server.URL, "bob", invite2)

	body := `{"name_enc":"enc"}`
	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/channels", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+bob.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("channels not admin: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestHandlers_Channels_DeleteMissingID(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	auth := registerHTTP(t, env.server.URL, "admin", invite)

	req, _ := http.NewRequest(http.MethodDelete, env.server.URL+"/channels", nil)
	req.Header.Set("Authorization", "Bearer "+auth.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("channels delete missing id: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandlers_Channels_DeleteNotFound(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	auth := registerHTTP(t, env.server.URL, "admin", invite)

	req, _ := http.NewRequest(http.MethodDelete, env.server.URL+"/channels?channel_id=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+auth.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("channels delete not found: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestHandlers_Channels_PatchInvalidJSON(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	auth := registerHTTP(t, env.server.URL, "admin", invite)

	req, _ := http.NewRequest(http.MethodPatch, env.server.URL+"/channels", strings.NewReader("not json"))
	req.Header.Set("Authorization", "Bearer "+auth.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("channels patch invalid: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandlers_Channels_PatchNotFound(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	auth := registerHTTP(t, env.server.URL, "admin", invite)

	body := `{"channel_id":"nonexistent","name_enc":"enc"}`
	req, _ := http.NewRequest(http.MethodPatch, env.server.URL+"/channels", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+auth.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("channels patch not found: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestHandlers_Channels_PostInvalidJSON(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	auth := registerHTTP(t, env.server.URL, "admin", invite)

	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/channels", strings.NewReader("not json"))
	req.Header.Set("Authorization", "Bearer "+auth.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("channels post invalid: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

// --- ServerInvites admin user ---

func TestHandlers_ServerInvites_AdminUser(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	admin := registerHTTP(t, env.server.URL, "admin", invite)

	// admin user (first user is admin) can create invites
	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/server/invites", nil)
	req.Header.Set("Authorization", "Bearer "+admin.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("invite admin user: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", resp.StatusCode)
	}
}

func TestHandlers_ServerInvites_NilInvites(t *testing.T) {
	h := NewHandler(nil, nil, nil, nil, nil, nil, nil, nil, "admin-token")
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/server/invites", nil)
	req.Header.Set("X-Admin-Token", "admin-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("invite nil invites: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
}

// --- Users ---

func TestHandlers_Users_InvalidJSON(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/users", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("users invalid json: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandlers_Users_EmptyUsername(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	body := `{"username":"   "}`
	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/users", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("users empty username: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

// --- NewHandler and Register ---

func TestNewHandler(t *testing.T) {
	h := NewHandler(nil, nil, nil, nil, nil, nil, nil, nil, "tok")
	if h == nil {
		t.Fatal("NewHandler returned nil")
	}
	if h.adminToken != "tok" {
		t.Fatalf("adminToken = %q, want %q", h.adminToken, "tok")
	}
}

func TestHandlers_DeviceKeys_NoAuth(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	req, _ := http.NewRequest(http.MethodGet, env.server.URL+"/devices/keys?user_id=u1", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("device keys no auth: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestHandlers_ChannelKeys_NoAuth(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	req, _ := http.NewRequest(http.MethodGet, env.server.URL+"/channels/keys?channel_id=ch-1", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("channel keys no auth: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestHandlers_DirectoryKeys_NoAuth(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	req, _ := http.NewRequest(http.MethodGet, env.server.URL+"/directory/keys", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("directory keys no auth: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestHandlers_Presence_InvalidJSON(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	auth := registerHTTP(t, env.server.URL, "alice", invite)

	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/presence", strings.NewReader("not json"))
	req.Header.Set("Authorization", "Bearer "+auth.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("presence invalid json: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandlers_ChannelMessages_NonexistentChannel(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	auth := registerHTTP(t, env.server.URL, "admin", invite)

	// ListMessages doesn't verify channel existence, returns empty list
	req, _ := http.NewRequest(http.MethodGet, env.server.URL+"/channels/messages?channel_id=nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+auth.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("channel messages nonexistent: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var payload channelMessagesResponse
	_ = json.NewDecoder(resp.Body).Decode(&payload)
	if len(payload.Messages) != 0 {
		t.Fatalf("messages = %d, want 0", len(payload.Messages))
	}
}

func TestHandlers_ChannelKeys_PostInvalidJSON(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	auth := registerHTTP(t, env.server.URL, "admin", invite)

	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/channels/keys", strings.NewReader("not json"))
	req.Header.Set("Authorization", "Bearer "+auth.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("channel keys invalid json: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandlers_DirectoryKeys_PostInvalidJSON(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	auth := registerHTTP(t, env.server.URL, "alice", invite)

	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/directory/keys", strings.NewReader("not json"))
	req.Header.Set("Authorization", "Bearer "+auth.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("directory keys invalid json: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandlers_Channels_CreateWithNotifier(t *testing.T) {
	notifier := &fakeNotifier{}
	env := newHTTPTestEnv(t, nil, notifier, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	auth := registerHTTP(t, env.server.URL, "admin", invite)

	body := `{"name_enc":"enc-name"}`
	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/channels", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+auth.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("channels create: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", resp.StatusCode)
	}
	if len(notifier.updated) != 1 {
		t.Fatalf("expected 1 notification, got %d", len(notifier.updated))
	}
}

func TestHandlers_Devices_EmptyPublicKey(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	auth := registerHTTP(t, env.server.URL, "alice", invite)

	body, _ := json.Marshal(map[string]string{
		"user_id": string(auth.UserID), "public_key": "   ",
	})
	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/devices", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+auth.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("devices empty pubkey: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandlers_Channels_CreateEmptyName(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	auth := registerHTTP(t, env.server.URL, "admin", invite)

	body := `{"name_enc":"   "}`
	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/channels", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+auth.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("channels create empty name: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandlers_Channels_PatchEmptyName(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	auth := registerHTTP(t, env.server.URL, "admin", invite)

	// Create a channel first
	channelID := channel.ID("ch-1")
	_ = env.channelRepo.CreateChannel(context.Background(), channel.Channel{
		ID: channelID, NameEnc: "enc", CreatedBy: auth.UserID, CreatedAt: time.Now().UTC(),
	})

	body := `{"channel_id":"ch-1","name_enc":"  "}`
	req, _ := http.NewRequest(http.MethodPatch, env.server.URL+"/channels", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+auth.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("channels patch empty name: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandlers_Channels_DeleteWithNotifier(t *testing.T) {
	notifier := &fakeNotifier{}
	env := newHTTPTestEnv(t, nil, notifier, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	auth := registerHTTP(t, env.server.URL, "admin", invite)

	channelID := channel.ID("ch-del")
	_ = env.channelRepo.CreateChannel(context.Background(), channel.Channel{
		ID: channelID, NameEnc: "enc", CreatedBy: auth.UserID, CreatedAt: time.Now().UTC(),
	})

	req, _ := http.NewRequest(http.MethodDelete, env.server.URL+"/channels?channel_id="+string(channelID), nil)
	req.Header.Set("Authorization", "Bearer "+auth.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("channels delete: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
	if len(notifier.deleted) != 1 || notifier.deleted[0] != channelID {
		t.Fatalf("expected delete notification for %s", channelID)
	}
}

func TestHandlers_Channels_PatchWithNotifier(t *testing.T) {
	notifier := &fakeNotifier{}
	env := newHTTPTestEnv(t, nil, notifier, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	auth := registerHTTP(t, env.server.URL, "admin", invite)

	channelID := channel.ID("ch-patch")
	_ = env.channelRepo.CreateChannel(context.Background(), channel.Channel{
		ID: channelID, NameEnc: "enc", CreatedBy: auth.UserID, CreatedAt: time.Now().UTC(),
	})

	body := `{"channel_id":"ch-patch","name_enc":"new-enc"}`
	req, _ := http.NewRequest(http.MethodPatch, env.server.URL+"/channels", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+auth.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("channels patch: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if len(notifier.updated) != 1 {
		t.Fatalf("expected 1 notification, got %d", len(notifier.updated))
	}
}

func TestHandlers_ChannelKeys_UpsertError(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	auth := registerHTTP(t, env.server.URL, "admin", invite)

	channelID := channel.ID("ch-keyerr")
	_ = env.channelRepo.CreateChannel(context.Background(), channel.Channel{
		ID: channelID, NameEnc: "enc", CreatedBy: auth.UserID, CreatedAt: time.Now().UTC(),
	})

	// Empty envelope field should trigger ErrInvalidInput
	body := map[string]any{
		"channel_id": string(channelID),
		"envelopes": []map[string]string{{
			"device_id":         string(auth.DeviceID),
			"sender_device_id":  string(auth.DeviceID),
			"sender_public_key": "  ",
			"envelope":          "env",
		}},
	}
	data, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/channels/keys", bytes.NewReader(data))
	req.Header.Set("Authorization", "Bearer "+auth.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("channel keys upsert error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandlers_DirectoryKeys_UpsertError(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	auth := registerHTTP(t, env.server.URL, "alice", invite)

	// Empty envelope field -> ErrInvalidInput from UpsertDirectoryKeyEnvelope
	body := map[string]any{"envelopes": []map[string]string{{
		"device_id":         "other-dev",
		"sender_device_id":  string(auth.DeviceID),
		"sender_public_key": "  ",
		"envelope":          "env",
	}}}
	data, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/directory/keys", bytes.NewReader(data))
	req.Header.Set("Authorization", "Bearer "+auth.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("directory keys upsert error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandlers_ChannelMessages_WithLimitAndMessages(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	auth := registerHTTP(t, env.server.URL, "admin", invite)

	channelID := channel.ID("ch-msgs")
	_ = env.channelRepo.CreateChannel(context.Background(), channel.Channel{
		ID: channelID, NameEnc: "enc", CreatedBy: auth.UserID, CreatedAt: time.Now().UTC(),
	})
	for i := 0; i < 3; i++ {
		_ = env.channelRepo.SaveMessage(context.Background(), channel.Message{
			ID: "msg-" + string(rune('a'+i)), ChannelID: channelID,
			SenderID: auth.UserID, SenderNameEnc: "enc", Body: "body", SentAt: time.Now().UTC(),
		})
	}

	// Test with limit=1
	req, _ := http.NewRequest(http.MethodGet, env.server.URL+"/channels/messages?channel_id="+string(channelID)+"&limit=1", nil)
	req.Header.Set("Authorization", "Bearer "+auth.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("channel messages limit: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var payload channelMessagesResponse
	_ = json.NewDecoder(resp.Body).Decode(&payload)
	if len(payload.Messages) != 1 {
		t.Fatalf("messages = %d, want 1", len(payload.Messages))
	}
}

func TestHandlers_ServerInvites_InvalidAdminToken(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/server/invites", nil)
	req.Header.Set("X-Admin-Token", "wrong-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("invite wrong token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestHandlers_Channels_GetByNonAdmin(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite1 := createInviteHTTP(t, env.server.URL, env.adminToken)
	_ = registerHTTP(t, env.server.URL, "admin", invite1)

	invite2 := createInviteHTTP(t, env.server.URL, env.adminToken)
	bob := registerHTTP(t, env.server.URL, "bob", invite2)

	// Non-admin can GET channels (list)
	req, _ := http.NewRequest(http.MethodGet, env.server.URL+"/channels", nil)
	req.Header.Set("Authorization", "Bearer "+bob.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("channels get non-admin: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestHandlers_Channels_DeleteNonAdmin(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite1 := createInviteHTTP(t, env.server.URL, env.adminToken)
	_ = registerHTTP(t, env.server.URL, "admin", invite1)

	invite2 := createInviteHTTP(t, env.server.URL, env.adminToken)
	bob := registerHTTP(t, env.server.URL, "bob", invite2)

	req, _ := http.NewRequest(http.MethodDelete, env.server.URL+"/channels?channel_id=ch-1", nil)
	req.Header.Set("Authorization", "Bearer "+bob.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("channels delete non-admin: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestHandlers_Channels_PatchNonAdmin(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite1 := createInviteHTTP(t, env.server.URL, env.adminToken)
	_ = registerHTTP(t, env.server.URL, "admin", invite1)

	invite2 := createInviteHTTP(t, env.server.URL, env.adminToken)
	bob := registerHTTP(t, env.server.URL, "bob", invite2)

	body := `{"channel_id":"ch-1","name_enc":"new"}`
	req, _ := http.NewRequest(http.MethodPatch, env.server.URL+"/channels", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+bob.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("channels patch non-admin: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestHandlers_Users_DuplicateUsername(t *testing.T) {
	env := newHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	body := `{"username":"duplicate"}`
	req1, _ := http.NewRequest(http.MethodPost, env.server.URL+"/users", strings.NewReader(body))
	req1.Header.Set("Content-Type", "application/json")
	resp1, _ := http.DefaultClient.Do(req1)
	resp1.Body.Close()

	req2, _ := http.NewRequest(http.MethodPost, env.server.URL+"/users", strings.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("users duplicate: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp2.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Error-injecting repository wrappers
// ---------------------------------------------------------------------------

type errUserRepo struct {
	*memUserRepo
	getByIDErr                    error
	countErr                      error
	getByUsernameHashErr          error
	upsertProfileErr              error
	listProfilesErr               error
	getDirectoryKeyEnvelopeErr    error
	upsertDirectoryKeyEnvelopeErr error
}

func (r *errUserRepo) GetByID(ctx context.Context, id user.ID) (user.User, error) {
	if r.getByIDErr != nil {
		return user.User{}, r.getByIDErr
	}
	return r.memUserRepo.GetByID(ctx, id)
}
func (r *errUserRepo) Count(ctx context.Context) (int, error) {
	if r.countErr != nil {
		return 0, r.countErr
	}
	return r.memUserRepo.Count(ctx)
}
func (r *errUserRepo) GetByUsernameHash(ctx context.Context, hash string) (user.User, error) {
	if r.getByUsernameHashErr != nil {
		return user.User{}, r.getByUsernameHashErr
	}
	return r.memUserRepo.GetByUsernameHash(ctx, hash)
}
func (r *errUserRepo) UpsertProfile(ctx context.Context, p user.Profile) error {
	if r.upsertProfileErr != nil {
		return r.upsertProfileErr
	}
	return r.memUserRepo.UpsertProfile(ctx, p)
}
func (r *errUserRepo) ListProfiles(ctx context.Context) ([]user.Profile, error) {
	if r.listProfilesErr != nil {
		return nil, r.listProfilesErr
	}
	return r.memUserRepo.ListProfiles(ctx)
}
func (r *errUserRepo) GetDirectoryKeyEnvelope(ctx context.Context, deviceID string) (user.DirectoryKeyEnvelope, error) {
	if r.getDirectoryKeyEnvelopeErr != nil {
		return user.DirectoryKeyEnvelope{}, r.getDirectoryKeyEnvelopeErr
	}
	return r.memUserRepo.GetDirectoryKeyEnvelope(ctx, deviceID)
}
func (r *errUserRepo) UpsertDirectoryKeyEnvelope(ctx context.Context, env user.DirectoryKeyEnvelope) error {
	if r.upsertDirectoryKeyEnvelopeErr != nil {
		return r.upsertDirectoryKeyEnvelopeErr
	}
	return r.memUserRepo.UpsertDirectoryKeyEnvelope(ctx, env)
}

type errDeviceRepo struct {
	*memDeviceRepo
	createErr     error
	listAllErr    error
	listByUserErr error
}

func (r *errDeviceRepo) Create(ctx context.Context, d device.Device) error {
	if r.createErr != nil {
		return r.createErr
	}
	return r.memDeviceRepo.Create(ctx, d)
}
func (r *errDeviceRepo) ListAll(ctx context.Context) ([]device.Device, error) {
	if r.listAllErr != nil {
		return nil, r.listAllErr
	}
	return r.memDeviceRepo.ListAll(ctx)
}
func (r *errDeviceRepo) ListByUser(ctx context.Context, userID user.ID) ([]device.Device, error) {
	if r.listByUserErr != nil {
		return nil, r.listByUserErr
	}
	return r.memDeviceRepo.ListByUser(ctx, userID)
}

type errChannelRepo struct {
	*memChannelRepo
	getChannelErr         error
	listChannelsErr       error
	deleteChannelErr      error
	updateChannelNameErr  error
	createChannelErr      error
	getKeyEnvelopeErr     error
	upsertKeyEnvelopeErr  error
	listRecentMessagesErr error
}

func (r *errChannelRepo) GetChannel(ctx context.Context, id channel.ID) (channel.Channel, error) {
	if r.getChannelErr != nil {
		return channel.Channel{}, r.getChannelErr
	}
	return r.memChannelRepo.GetChannel(ctx, id)
}
func (r *errChannelRepo) ListChannels(ctx context.Context) ([]channel.Channel, error) {
	if r.listChannelsErr != nil {
		return nil, r.listChannelsErr
	}
	return r.memChannelRepo.ListChannels(ctx)
}
func (r *errChannelRepo) DeleteChannel(ctx context.Context, id channel.ID) error {
	if r.deleteChannelErr != nil {
		return r.deleteChannelErr
	}
	return r.memChannelRepo.DeleteChannel(ctx, id)
}
func (r *errChannelRepo) UpdateChannelName(ctx context.Context, id channel.ID, nameEnc string) error {
	if r.updateChannelNameErr != nil {
		return r.updateChannelNameErr
	}
	return r.memChannelRepo.UpdateChannelName(ctx, id, nameEnc)
}
func (r *errChannelRepo) CreateChannel(ctx context.Context, ch channel.Channel) error {
	if r.createChannelErr != nil {
		return r.createChannelErr
	}
	return r.memChannelRepo.CreateChannel(ctx, ch)
}
func (r *errChannelRepo) GetKeyEnvelope(ctx context.Context, channelID channel.ID, deviceID device.ID) (channel.KeyEnvelope, error) {
	if r.getKeyEnvelopeErr != nil {
		return channel.KeyEnvelope{}, r.getKeyEnvelopeErr
	}
	return r.memChannelRepo.GetKeyEnvelope(ctx, channelID, deviceID)
}
func (r *errChannelRepo) UpsertKeyEnvelope(ctx context.Context, env channel.KeyEnvelope) error {
	if r.upsertKeyEnvelopeErr != nil {
		return r.upsertKeyEnvelopeErr
	}
	return r.memChannelRepo.UpsertKeyEnvelope(ctx, env)
}
func (r *errChannelRepo) ListRecentMessages(ctx context.Context, channelID channel.ID, limit int) ([]channel.Message, error) {
	if r.listRecentMessagesErr != nil {
		return nil, r.listRecentMessagesErr
	}
	return r.memChannelRepo.ListRecentMessages(ctx, channelID, limit)
}

type errInviteRepo struct {
	*memInviteRepo
	createErr error
}

func (r *errInviteRepo) Create(ctx context.Context, invite serverinvite.Invite) error {
	if r.createErr != nil {
		return r.createErr
	}
	return r.memInviteRepo.Create(ctx, invite)
}

type errHTTPTestEnv struct {
	handler     *Handler
	mux         *http.ServeMux
	server      *httptest.Server
	userRepo    *errUserRepo
	deviceRepo  *errDeviceRepo
	channelRepo *errChannelRepo
	inviteRepo  *errInviteRepo
	adminToken  string
}

func newErrHTTPTestEnv(t *testing.T, presence PresenceProvider, notifier ChannelNotifier, userNotify UserNotifier) *errHTTPTestEnv {
	t.Helper()

	userRepo := &errUserRepo{memUserRepo: newMemUserRepo()}
	deviceRepo := &errDeviceRepo{memDeviceRepo: newMemDeviceRepo()}
	channelRepo := &errChannelRepo{memChannelRepo: newMemChannelRepo()}
	inviteRepo := &errInviteRepo{memInviteRepo: newMemInviteRepo()}

	userSvc := user.NewService(userRepo, "test-pepper")
	deviceSvc := device.NewService(deviceRepo)
	channelSvc := channel.NewService(channelRepo, userSvc)
	inviteSvc := serverinvite.NewService(inviteRepo)
	authSvc := auth.NewService(userSvc, deviceSvc, inviteSvc)

	h := NewHandler(userSvc, deviceSvc, channelSvc, authSvc, inviteSvc, presence, notifier, userNotify, "admin-token")
	mux := http.NewServeMux()
	h.Register(mux)

	srv := httptest.NewServer(mux)
	return &errHTTPTestEnv{
		handler:     h,
		mux:         mux,
		server:      srv,
		userRepo:    userRepo,
		deviceRepo:  deviceRepo,
		channelRepo: channelRepo,
		inviteRepo:  inviteRepo,
		adminToken:  "admin-token",
	}
}

func (e *errHTTPTestEnv) close() { e.server.Close() }

// ---------------------------------------------------------------------------
// Tests for remaining uncovered lines in handlers.go
// ---------------------------------------------------------------------------

// L124-125: Register returns a non-categorized (internal) error → 500
func TestHandlers_Register_InternalError(t *testing.T) {
	// Create auth service with nil user/device services so Register returns
	// "services are required" which is an uncategorized error.
	authSvc := auth.NewService(nil, nil, nil)
	h := NewHandler(nil, nil, nil, authSvc, nil, nil, nil, nil, "")
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	body := `{"username":"u","password":"password123","public_key":"pk","invite_token":"tok"}`
	resp, err := http.Post(srv.URL+"/auth/register", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
}

// L167-168: Login returns a non-categorized (internal) error → 500
func TestHandlers_Login_InternalError(t *testing.T) {
	authSvc := auth.NewService(nil, nil, nil)
	h := NewHandler(nil, nil, nil, authSvc, nil, nil, nil, nil, "")
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	body := `{"username":"u","password":"password123","public_key":"pk"}`
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
}

// L191-193: authenticateTrusted h.users==nil is unreachable defensive code;
// both callers (handleUserProfiles, handleDirectoryKeys) check h.users==nil
// before calling authenticateTrusted.

// L195-197: authenticateTrusted when GetByID fails → 401
func TestHandlers_AuthenticateTrusted_GetByIDError(t *testing.T) {
	env := newErrHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	authResp := registerHTTP(t, env.server.URL, "admin", invite)

	// Enable error after registration
	env.userRepo.getByIDErr = errors.New("db connection lost")

	req, _ := http.NewRequest(http.MethodGet, env.server.URL+"/users/profiles", nil)
	req.Header.Set("Authorization", "Bearer "+authResp.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

// L205-207: authenticate when h.auth == nil → 401
func TestHandlers_Authenticate_NilAuth(t *testing.T) {
	h := NewHandler(nil, nil, nil, nil, nil, nil, nil, nil, "")
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/devices", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer some-token")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

// L297-298: UpsertProfile returns default (internal) error → 500
func TestHandlers_UserProfiles_UpsertInternalError(t *testing.T) {
	env := newErrHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	authResp := registerHTTP(t, env.server.URL, "admin", invite)

	env.userRepo.upsertProfileErr = errors.New("db write error")

	body := `{"name_enc":"encrypted-name"}`
	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/users/profiles", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+authResp.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
}

// L310-313: ListProfiles error → 500
func TestHandlers_UserProfiles_ListError(t *testing.T) {
	env := newErrHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	authResp := registerHTTP(t, env.server.URL, "admin", invite)

	env.userRepo.listProfilesErr = errors.New("db read error")

	req, _ := http.NewRequest(http.MethodGet, env.server.URL+"/users/profiles", nil)
	req.Header.Set("Authorization", "Bearer "+authResp.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
}

// L362.43,365.4: handleDevices GetByID returns user.ErrInvalidInput → 400
func TestHandlers_Devices_GetByIDErrInvalidInput(t *testing.T) {
	env := newErrHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	authResp := registerHTTP(t, env.server.URL, "admin", invite)

	env.userRepo.getByIDErr = user.ErrInvalidInput

	body, _ := json.Marshal(map[string]string{
		"user_id": string(authResp.UserID), "public_key": "new-key",
	})
	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/devices", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+authResp.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

// L362-365: handleDevices GetByID internal error → 500
func TestHandlers_Devices_GetByIDInternalError(t *testing.T) {
	env := newErrHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	authResp := registerHTTP(t, env.server.URL, "admin", invite)

	// Set error AFTER registration so auth token is valid but GetByID fails
	env.userRepo.getByIDErr = errors.New("db timeout")

	body, _ := json.Marshal(map[string]string{
		"user_id": string(authResp.UserID), "public_key": "new-key",
	})
	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/devices", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+authResp.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
}

// L370-371: handleDevices Create returns device.ErrInvalidInput → 400
func TestHandlers_Devices_CreateErrInvalidInput(t *testing.T) {
	env := newErrHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	authResp := registerHTTP(t, env.server.URL, "admin", invite)

	// Set device create to return ErrInvalidInput
	env.deviceRepo.createErr = device.ErrInvalidInput

	body, _ := json.Marshal(map[string]string{
		"user_id": string(authResp.UserID), "public_key": "valid-key",
	})
	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/devices", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+authResp.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

// L380-381: handleDevices Create returns internal error → 500
func TestHandlers_Devices_CreateInternalError(t *testing.T) {
	env := newErrHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	authResp := registerHTTP(t, env.server.URL, "admin", invite)

	env.deviceRepo.createErr = errors.New("db write error")

	body, _ := json.Marshal(map[string]string{
		"user_id": string(authResp.UserID), "public_key": "valid-key",
	})
	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/devices", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+authResp.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
}

// L452-455: handleDeviceKeys ListAll error → 500
func TestHandlers_DeviceKeys_ListAllError(t *testing.T) {
	env := newErrHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	authResp := registerHTTP(t, env.server.URL, "admin", invite)

	env.deviceRepo.listAllErr = errors.New("db error")

	req, _ := http.NewRequest(http.MethodGet, env.server.URL+"/devices/keys?all=1", nil)
	req.Header.Set("Authorization", "Bearer "+authResp.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
}

// L470-473: handleDeviceKeys ListByUser error → 500
func TestHandlers_DeviceKeys_ListByUserError(t *testing.T) {
	env := newErrHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	authResp := registerHTTP(t, env.server.URL, "admin", invite)

	env.deviceRepo.listByUserErr = errors.New("db error")

	req, _ := http.NewRequest(http.MethodGet, env.server.URL+"/devices/keys?user_id="+string(authResp.UserID), nil)
	req.Header.Set("Authorization", "Bearer "+authResp.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
}

// L508-509: handleDirectoryKeys GET returns user.ErrInvalidInput → 400
func TestHandlers_DirectoryKeys_GetInvalidInput(t *testing.T) {
	env := newErrHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	authResp := registerHTTP(t, env.server.URL, "admin", invite)

	env.userRepo.getDirectoryKeyEnvelopeErr = user.ErrInvalidInput

	req, _ := http.NewRequest(http.MethodGet, env.server.URL+"/directory/keys", nil)
	req.Header.Set("Authorization", "Bearer "+authResp.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

// L512-513: handleDirectoryKeys GET returns internal error → 500
func TestHandlers_DirectoryKeys_GetInternalError(t *testing.T) {
	env := newErrHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	authResp := registerHTTP(t, env.server.URL, "admin", invite)

	env.userRepo.getDirectoryKeyEnvelopeErr = errors.New("db error")

	req, _ := http.NewRequest(http.MethodGet, env.server.URL+"/directory/keys", nil)
	req.Header.Set("Authorization", "Bearer "+authResp.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
}

// L553-554: handleDirectoryKeys POST UpsertDirectoryKeyEnvelope internal error → 500
func TestHandlers_DirectoryKeys_PostUpsertInternalError(t *testing.T) {
	env := newErrHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	authResp := registerHTTP(t, env.server.URL, "admin", invite)

	env.userRepo.upsertDirectoryKeyEnvelopeErr = errors.New("db write error")

	body, _ := json.Marshal(map[string]any{"envelopes": []map[string]string{{
		"device_id":         "other-dev",
		"sender_device_id":  string(authResp.DeviceID),
		"sender_public_key": "spk",
		"envelope":          "env-data",
	}}})
	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/directory/keys", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+authResp.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
}

// L609-610: handleChannelKeys GET GetKeyEnvelope returns channel.ErrInvalidInput → 400
func TestHandlers_ChannelKeys_GetInvalidInput(t *testing.T) {
	env := newErrHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	authResp := registerHTTP(t, env.server.URL, "admin", invite)

	env.channelRepo.getKeyEnvelopeErr = channel.ErrInvalidInput

	req, _ := http.NewRequest(http.MethodGet, env.server.URL+"/channels/keys?channel_id=ch1", nil)
	req.Header.Set("Authorization", "Bearer "+authResp.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

// L613-614: handleChannelKeys GET GetKeyEnvelope returns internal error → 500
func TestHandlers_ChannelKeys_GetInternalError(t *testing.T) {
	env := newErrHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	authResp := registerHTTP(t, env.server.URL, "admin", invite)

	env.channelRepo.getKeyEnvelopeErr = errors.New("db error")

	req, _ := http.NewRequest(http.MethodGet, env.server.URL+"/channels/keys?channel_id=ch1", nil)
	req.Header.Set("Authorization", "Bearer "+authResp.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
}

// L642-643: handleChannelKeys POST GetChannel returns channel.ErrInvalidInput → 400
func TestHandlers_ChannelKeys_PostGetChannelInvalidInput(t *testing.T) {
	env := newErrHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	authResp := registerHTTP(t, env.server.URL, "admin", invite)

	env.channelRepo.getChannelErr = channel.ErrInvalidInput

	body, _ := json.Marshal(map[string]any{
		"channel_id": "ch1",
		"envelopes": []map[string]string{{
			"device_id":         string(authResp.DeviceID),
			"sender_device_id":  string(authResp.DeviceID),
			"sender_public_key": "spk",
			"envelope":          "env",
		}},
	})
	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/channels/keys", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+authResp.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

// L646-647: handleChannelKeys POST GetChannel returns internal error → 500
func TestHandlers_ChannelKeys_PostGetChannelInternalError(t *testing.T) {
	env := newErrHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	authResp := registerHTTP(t, env.server.URL, "admin", invite)

	env.channelRepo.getChannelErr = errors.New("db error")

	body, _ := json.Marshal(map[string]any{
		"channel_id": "ch1",
		"envelopes": []map[string]string{{
			"device_id":         string(authResp.DeviceID),
			"sender_device_id":  string(authResp.DeviceID),
			"sender_public_key": "spk",
			"envelope":          "env",
		}},
	})
	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/channels/keys", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+authResp.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
}

// L668-669: handleChannelKeys POST UpsertKeyEnvelope returns internal error → 500
func TestHandlers_ChannelKeys_PostUpsertInternalError(t *testing.T) {
	env := newErrHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	authResp := registerHTTP(t, env.server.URL, "admin", invite)

	// Create channel so GetChannel succeeds
	chID := channel.ID("ch-upsert-err")
	_ = env.channelRepo.memChannelRepo.CreateChannel(context.Background(), channel.Channel{
		ID: chID, NameEnc: "enc", CreatedBy: authResp.UserID, CreatedAt: time.Now().UTC(),
	})

	env.channelRepo.upsertKeyEnvelopeErr = errors.New("db write error")

	body, _ := json.Marshal(map[string]any{
		"channel_id": string(chID),
		"envelopes": []map[string]string{{
			"device_id":         string(authResp.DeviceID),
			"sender_device_id":  string(authResp.DeviceID),
			"sender_public_key": "spk",
			"envelope":          "env",
		}},
	})
	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/channels/keys", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+authResp.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
}

// L698-701: handleServerInvites admin user GetByID error → 401
func TestHandlers_ServerInvites_GetByIDError(t *testing.T) {
	env := newErrHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	authResp := registerHTTP(t, env.server.URL, "admin", invite)

	// Break GetByID so the admin user lookup in handleServerInvites fails
	env.userRepo.getByIDErr = errors.New("db error")

	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/server/invites", nil)
	req.Header.Set("Authorization", "Bearer "+authResp.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

// L714-717: handleServerInvites Create error → 500
func TestHandlers_ServerInvites_CreateError(t *testing.T) {
	env := newErrHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	env.inviteRepo.createErr = errors.New("db write error")

	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/server/invites", nil)
	req.Header.Set("X-Admin-Token", env.adminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
}

// L783-786: handleChannels POST admin check GetByID error → 401
func TestHandlers_Channels_AdminCheckGetByIDError(t *testing.T) {
	env := newErrHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	authResp := registerHTTP(t, env.server.URL, "admin", invite)

	env.userRepo.getByIDErr = errors.New("db error")

	body := `{"name_enc":"test-channel"}`
	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/channels", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+authResp.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

// L795-798: handleChannels GET ListChannels error → 500
func TestHandlers_Channels_ListChannelsError(t *testing.T) {
	env := newErrHTTPTestEnv(t, nil, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	authResp := registerHTTP(t, env.server.URL, "admin", invite)

	env.channelRepo.listChannelsErr = errors.New("db error")

	req, _ := http.NewRequest(http.MethodGet, env.server.URL+"/channels", nil)
	req.Header.Set("Authorization", "Bearer "+authResp.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
}

// L820-821, L822-823, L826-827: handleChannels Delete error branches
func TestHandlers_Channels_DeleteInternalErrors(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status int
	}{
		{"ErrInvalidInput", channel.ErrInvalidInput, http.StatusBadRequest},
		{"ErrForbidden", channel.ErrForbidden, http.StatusForbidden},
		{"InternalError", errors.New("db error"), http.StatusInternalServerError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := newErrHTTPTestEnv(t, nil, nil, nil)
			defer env.close()

			invite := createInviteHTTP(t, env.server.URL, env.adminToken)
			authResp := registerHTTP(t, env.server.URL, "admin", invite)

			// Create channel in repo so admin check in service passes
			chID := channel.ID("ch-del-err")
			_ = env.channelRepo.memChannelRepo.CreateChannel(context.Background(), channel.Channel{
				ID: chID, NameEnc: "enc", CreatedBy: authResp.UserID, CreatedAt: time.Now().UTC(),
			})

			env.channelRepo.deleteChannelErr = tc.err

			req, _ := http.NewRequest(http.MethodDelete, env.server.URL+"/channels?channel_id="+string(chID), nil)
			req.Header.Set("Authorization", "Bearer "+authResp.Token)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.status {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.status)
			}
		})
	}
}

// L849-850, L853-854: handleChannels Patch error branches
func TestHandlers_Channels_PatchInternalErrors(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status int
	}{
		{"ErrForbidden", channel.ErrForbidden, http.StatusForbidden},
		{"InternalError", errors.New("db error"), http.StatusInternalServerError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := newErrHTTPTestEnv(t, nil, nil, nil)
			defer env.close()

			invite := createInviteHTTP(t, env.server.URL, env.adminToken)
			authResp := registerHTTP(t, env.server.URL, "admin", invite)

			chID := channel.ID("ch-patch-err")
			_ = env.channelRepo.memChannelRepo.CreateChannel(context.Background(), channel.Channel{
				ID: chID, NameEnc: "enc", CreatedBy: authResp.UserID, CreatedAt: time.Now().UTC(),
			})

			env.channelRepo.updateChannelNameErr = tc.err

			body, _ := json.Marshal(map[string]string{"channel_id": string(chID), "name_enc": "new-name"})
			req, _ := http.NewRequest(http.MethodPatch, env.server.URL+"/channels", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+authResp.Token)
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.status {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.status)
			}
		})
	}
}

// L882-883, L884-885: handleChannels Create error branches
func TestHandlers_Channels_CreateInternalErrors(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status int
	}{
		{"ErrForbidden", channel.ErrForbidden, http.StatusForbidden},
		{"InternalError", errors.New("db error"), http.StatusInternalServerError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := newErrHTTPTestEnv(t, nil, nil, nil)
			defer env.close()

			invite := createInviteHTTP(t, env.server.URL, env.adminToken)
			authResp := registerHTTP(t, env.server.URL, "admin", invite)
			_ = authResp

			env.channelRepo.createChannelErr = tc.err

			body := `{"name_enc":"test-channel"}`
			req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/channels", strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+authResp.Token)
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.status {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.status)
			}
		})
	}
}

// L937-946: handleChannelMessages ListMessages error branches
func TestHandlers_ChannelMessages_ErrorBranches(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status int
	}{
		{"ErrInvalidInput", channel.ErrInvalidInput, http.StatusBadRequest},
		{"ErrNotFound", channel.ErrNotFound, http.StatusNotFound},
		{"StorageNotFound", storage.ErrNotFound, http.StatusNotFound},
		{"InternalError", errors.New("db error"), http.StatusInternalServerError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := newErrHTTPTestEnv(t, nil, nil, nil)
			defer env.close()

			invite := createInviteHTTP(t, env.server.URL, env.adminToken)
			authResp := registerHTTP(t, env.server.URL, "admin", invite)

			env.channelRepo.listRecentMessagesErr = tc.err

			req, _ := http.NewRequest(http.MethodGet, env.server.URL+"/channels/messages?channel_id=ch1", nil)
			req.Header.Set("Authorization", "Bearer "+authResp.Token)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.status {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.status)
			}
		})
	}
}

// L1001-1003: handlePresence admin lookup succeeds → admins map populated
func TestHandlers_Presence_AdminLookupSuccess(t *testing.T) {
	env := newErrHTTPTestEnv(t, fakePresence{online: map[user.ID]bool{}}, nil, nil)
	defer env.close()

	invite := createInviteHTTP(t, env.server.URL, env.adminToken)
	authResp := registerHTTP(t, env.server.URL, "admin", invite)

	body, _ := json.Marshal(map[string][]string{"user_ids": {string(authResp.UserID)}})
	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/presence", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+authResp.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var result presenceResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	isAdmin, ok := result.Admins[authResp.UserID]
	if !ok || !isAdmin {
		t.Fatalf("expected admin=true for %s, got %v (ok=%v)", authResp.UserID, isAdmin, ok)
	}
}
