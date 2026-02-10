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
