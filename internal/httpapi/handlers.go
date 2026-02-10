package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Avicted/dialtone/internal/auth"
	"github.com/Avicted/dialtone/internal/channel"
	"github.com/Avicted/dialtone/internal/device"
	"github.com/Avicted/dialtone/internal/securelog"
	"github.com/Avicted/dialtone/internal/serverinvite"
	"github.com/Avicted/dialtone/internal/storage"
	"github.com/Avicted/dialtone/internal/user"
)

const (
	maxBodyBytes = 1 << 20
	timeLayout   = time.RFC3339Nano
)

type Handler struct {
	users      *user.Service
	devices    *device.Service
	channels   *channel.Service
	auth       *auth.Service
	invites    *serverinvite.Service
	presence   PresenceProvider
	notifier   ChannelNotifier
	adminToken string
}

type PresenceProvider interface {
	IsOnline(userID user.ID) bool
}

type ChannelNotifier interface {
	NotifyChannelUpdated(ch channel.Channel)
	NotifyChannelDeleted(id channel.ID)
}

func NewHandler(users *user.Service, devices *device.Service, channels *channel.Service, auth *auth.Service, invites *serverinvite.Service, presence PresenceProvider, notifier ChannelNotifier, adminToken string) *Handler {
	return &Handler{
		users:      users,
		devices:    devices,
		channels:   channels,
		auth:       auth,
		invites:    invites,
		presence:   presence,
		notifier:   notifier,
		adminToken: adminToken,
	}
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("/users", h.handleUsers)
	mux.HandleFunc("/users/profiles", h.handleUserProfiles)
	mux.HandleFunc("/devices", h.handleDevices)
	mux.HandleFunc("/devices/keys", h.handleDeviceKeys)
	mux.HandleFunc("/auth/register", h.handleRegister)
	mux.HandleFunc("/auth/login", h.handleLogin)
	mux.HandleFunc("/channels", h.handleChannels)
	mux.HandleFunc("/channels/messages", h.handleChannelMessages)
	mux.HandleFunc("/channels/keys", h.handleChannelKeys)
	mux.HandleFunc("/directory/keys", h.handleDirectoryKeys)
	mux.HandleFunc("/presence", h.handlePresence)
	mux.HandleFunc("/server/invites", h.handleServerInvites)
}

type authRequest struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	PublicKey   string `json:"public_key"`
	InviteToken string `json:"invite_token"`
}

type authResponse struct {
	Token        string    `json:"token"`
	UserID       user.ID   `json:"user_id"`
	DeviceID     device.ID `json:"device_id"`
	ExpiresAt    string    `json:"expires_at"`
	Username     string    `json:"username"`
	DevicePubKey string    `json:"device_public_key"`
	IsAdmin      bool      `json:"is_admin"`
	IsTrusted    bool      `json:"is_trusted"`
}

func (h *Handler) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if h.auth == nil {
		writeError(w, http.StatusInternalServerError, errors.New("auth service not configured"))
		return
	}

	var req authRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	createdUser, createdDevice, session, err := h.auth.Register(r.Context(), req.Username, req.Password, req.PublicKey, req.InviteToken)
	if err != nil {
		switch {
		case errors.Is(err, user.ErrInvalidInput), errors.Is(err, device.ErrInvalidInput), errors.Is(err, auth.ErrInvalidInput), errors.Is(err, serverinvite.ErrInvalidInput):
			writeError(w, http.StatusBadRequest, err)
		case errors.Is(err, serverinvite.ErrExpired), errors.Is(err, serverinvite.ErrConsumed):
			writeError(w, http.StatusGone, err)
		case errors.Is(err, serverinvite.ErrNotFound):
			writeError(w, http.StatusNotFound, err)
		default:
			writeError(w, http.StatusInternalServerError, err)
		}
		return
	}

	resp := authResponse{
		Token:        session.Token,
		UserID:       createdUser.ID,
		DeviceID:     createdDevice.ID,
		ExpiresAt:    session.ExpiresAt.UTC().Format(timeLayout),
		Username:     session.Username,
		DevicePubKey: createdDevice.PublicKey,
		IsAdmin:      createdUser.IsAdmin,
		IsTrusted:    createdUser.IsTrusted,
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if h.auth == nil {
		writeError(w, http.StatusInternalServerError, errors.New("auth service not configured"))
		return
	}

	var req authRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	createdUser, createdDevice, session, err := h.auth.Login(r.Context(), req.Username, req.Password, req.PublicKey)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrUnauthorized):
			writeError(w, http.StatusUnauthorized, err)
		case errors.Is(err, user.ErrInvalidInput), errors.Is(err, device.ErrInvalidInput), errors.Is(err, auth.ErrInvalidInput):
			writeError(w, http.StatusBadRequest, err)
		default:
			writeError(w, http.StatusInternalServerError, err)
		}
		return
	}

	resp := authResponse{
		Token:        session.Token,
		UserID:       createdUser.ID,
		DeviceID:     createdDevice.ID,
		ExpiresAt:    session.ExpiresAt.UTC().Format(timeLayout),
		Username:     session.Username,
		DevicePubKey: createdDevice.PublicKey,
		IsAdmin:      createdUser.IsAdmin,
		IsTrusted:    createdUser.IsTrusted,
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) authenticateTrusted(r *http.Request) (auth.Session, error) {
	session, err := h.authenticate(r)
	if err != nil {
		return auth.Session{}, err
	}
	if h.users == nil {
		return auth.Session{}, errors.New("user service not configured")
	}
	current, err := h.users.GetByID(r.Context(), session.UserID)
	if err != nil {
		return auth.Session{}, err
	}
	if !current.IsTrusted {
		return auth.Session{}, errors.New("trusted user required")
	}
	return session, nil
}

func (h *Handler) authenticate(r *http.Request) (auth.Session, error) {
	if h.auth == nil {
		return auth.Session{}, auth.ErrUnauthorized
	}
	if header := strings.TrimSpace(r.Header.Get("Authorization")); header != "" {
		parts := strings.Fields(header)
		if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
			return h.auth.ValidateToken(parts[1])
		}
	}
	return auth.Session{}, auth.ErrUnauthorized
}

type createUserRequest struct {
	Username string `json:"username"`
}

type createUserResponse struct {
	ID        user.ID `json:"id"`
	Username  string  `json:"username"`
	CreatedAt string  `json:"created_at"`
}

type userProfileRequest struct {
	NameEnc string `json:"name_enc"`
}

type userProfileResponse struct {
	UserID    user.ID `json:"user_id"`
	NameEnc   string  `json:"name_enc"`
	UpdatedAt string  `json:"updated_at"`
}

type listUserProfilesResponse struct {
	Profiles []userProfileResponse `json:"profiles"`
}

func (h *Handler) handleUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req createUserRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	created, err := h.users.Create(r.Context(), req.Username)
	if err != nil {
		if errors.Is(err, user.ErrInvalidInput) {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	resp := createUserResponse{
		ID:        created.ID,
		Username:  strings.TrimSpace(req.Username),
		CreatedAt: created.CreatedAt.UTC().Format(timeLayout),
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (h *Handler) handleUserProfiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if h.users == nil {
		writeError(w, http.StatusInternalServerError, errors.New("user service not configured"))
		return
	}

	session, err := h.authenticateTrusted(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}

	if r.Method == http.MethodPost {
		var req userProfileRequest
		if err := decodeJSON(w, r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := h.users.UpsertProfile(r.Context(), session.UserID, req.NameEnc); err != nil {
			switch {
			case errors.Is(err, user.ErrInvalidInput):
				writeError(w, http.StatusBadRequest, err)
			default:
				writeError(w, http.StatusInternalServerError, err)
			}
			return
		}
		writeJSON(w, http.StatusCreated, map[string]string{"status": "ok"})
		return
	}

	profiles, err := h.users.ListProfiles(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	resp := listUserProfilesResponse{Profiles: make([]userProfileResponse, 0, len(profiles))}
	for _, profile := range profiles {
		resp.Profiles = append(resp.Profiles, userProfileResponse{
			UserID:    profile.UserID,
			NameEnc:   profile.NameEnc,
			UpdatedAt: profile.UpdatedAt.UTC().Format(timeLayout),
		})
	}
	writeJSON(w, http.StatusOK, resp)
}

type createDeviceRequest struct {
	UserID    user.ID `json:"user_id"`
	PublicKey string  `json:"public_key"`
}

type createDeviceResponse struct {
	ID        device.ID `json:"id"`
	UserID    user.ID   `json:"user_id"`
	PublicKey string    `json:"public_key"`
	CreatedAt string    `json:"created_at"`
}

func (h *Handler) handleDevices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	session, err := h.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}

	var req createDeviceRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	if req.UserID != session.UserID {
		writeError(w, http.StatusForbidden, errors.New("cannot create device for another user"))
		return
	}

	if _, err := h.users.GetByID(r.Context(), req.UserID); err != nil {
		if errors.Is(err, user.ErrInvalidInput) {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, err)
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	created, err := h.devices.Create(r.Context(), req.UserID, req.PublicKey)
	if err != nil {
		if errors.Is(err, device.ErrInvalidInput) {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	resp := createDeviceResponse{
		ID:        created.ID,
		UserID:    created.UserID,
		PublicKey: created.PublicKey,
		CreatedAt: created.CreatedAt.UTC().Format(timeLayout),
	}
	writeJSON(w, http.StatusCreated, resp)
}

type deviceKeyInfo struct {
	UserID    user.ID   `json:"user_id,omitempty"`
	DeviceID  device.ID `json:"device_id"`
	PublicKey string    `json:"public_key"`
}

type deviceKeysResponse struct {
	UserID user.ID         `json:"user_id"`
	Keys   []deviceKeyInfo `json:"keys"`
}

type directoryKeyEnvelopeRequest struct {
	DeviceID        device.ID `json:"device_id"`
	SenderDeviceID  device.ID `json:"sender_device_id"`
	SenderPublicKey string    `json:"sender_public_key"`
	Envelope        string    `json:"envelope"`
}

type directoryKeyEnvelopesRequest struct {
	Envelopes []directoryKeyEnvelopeRequest `json:"envelopes"`
}

type directoryKeyEnvelopeResponse struct {
	DeviceID        device.ID `json:"device_id"`
	SenderDeviceID  device.ID `json:"sender_device_id"`
	SenderPublicKey string    `json:"sender_public_key"`
	Envelope        string    `json:"envelope"`
	CreatedAt       string    `json:"created_at"`
}

// handleDeviceKeys returns the public keys of all devices belonging to a user.
// GET /devices/keys?user_id=<id>
func (h *Handler) handleDeviceKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	session, err := h.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}

	all := r.URL.Query().Get("all") == "1"
	userID := user.ID(r.URL.Query().Get("user_id"))
	if userID == "" {
		if !all {
			writeError(w, http.StatusBadRequest, errors.New("user_id query parameter is required"))
			return
		}
	} else if userID != session.UserID {
		writeError(w, http.StatusForbidden, errors.New("cannot list devices for another user"))
		return
	}

	if all {
		devices, err := h.devices.ListAll(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		keys := make([]deviceKeyInfo, 0, len(devices))
		for _, d := range devices {
			keys = append(keys, deviceKeyInfo{
				UserID:    d.UserID,
				DeviceID:  d.ID,
				PublicKey: d.PublicKey,
			})
		}
		writeJSON(w, http.StatusOK, deviceKeysResponse{Keys: keys})
		return
	}

	devices, err := h.devices.ListByUser(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	keys := make([]deviceKeyInfo, 0, len(devices))
	for _, d := range devices {
		keys = append(keys, deviceKeyInfo{
			DeviceID:  d.ID,
			PublicKey: d.PublicKey,
		})
	}

	resp := deviceKeysResponse{Keys: keys}
	if !all {
		resp.UserID = userID
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) handleDirectoryKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if h.users == nil {
		writeError(w, http.StatusInternalServerError, errors.New("user service not configured"))
		return
	}

	session, err := h.authenticateTrusted(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}

	if r.Method == http.MethodGet {
		env, err := h.users.GetDirectoryKeyEnvelope(r.Context(), string(session.DeviceID))
		if err != nil {
			switch {
			case errors.Is(err, user.ErrInvalidInput):
				writeError(w, http.StatusBadRequest, err)
			case errors.Is(err, storage.ErrNotFound):
				writeError(w, http.StatusNotFound, err)
			default:
				writeError(w, http.StatusInternalServerError, err)
			}
			return
		}
		resp := directoryKeyEnvelopeResponse{
			DeviceID:        device.ID(env.DeviceID),
			SenderDeviceID:  device.ID(env.SenderDeviceID),
			SenderPublicKey: env.SenderPublicKey,
			Envelope:        env.Envelope,
			CreatedAt:       env.CreatedAt.UTC().Format(timeLayout),
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}

	var req directoryKeyEnvelopesRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if len(req.Envelopes) == 0 {
		writeError(w, http.StatusBadRequest, errors.New("envelopes are required"))
		return
	}
	for _, envReq := range req.Envelopes {
		if envReq.SenderDeviceID != session.DeviceID {
			writeError(w, http.StatusForbidden, errors.New("sender_device_id must match the current device"))
			return
		}
		env := user.DirectoryKeyEnvelope{
			DeviceID:        string(envReq.DeviceID),
			SenderDeviceID:  string(envReq.SenderDeviceID),
			SenderPublicKey: strings.TrimSpace(envReq.SenderPublicKey),
			Envelope:        strings.TrimSpace(envReq.Envelope),
			CreatedAt:       time.Now().UTC(),
		}
		if err := h.users.UpsertDirectoryKeyEnvelope(r.Context(), env); err != nil {
			switch {
			case errors.Is(err, user.ErrInvalidInput):
				writeError(w, http.StatusBadRequest, err)
			default:
				writeError(w, http.StatusInternalServerError, err)
			}
			return
		}
	}
	writeJSON(w, http.StatusCreated, map[string]string{"status": "ok"})
}

type channelKeyEnvelopeRequest struct {
	ChannelID       channel.ID `json:"channel_id"`
	DeviceID        device.ID  `json:"device_id"`
	SenderDeviceID  device.ID  `json:"sender_device_id"`
	SenderPublicKey string     `json:"sender_public_key"`
	Envelope        string     `json:"envelope"`
}

type channelKeyEnvelopesRequest struct {
	ChannelID channel.ID                  `json:"channel_id"`
	Envelopes []channelKeyEnvelopeRequest `json:"envelopes"`
}

type channelKeyEnvelopeResponse struct {
	ChannelID       channel.ID `json:"channel_id"`
	DeviceID        device.ID  `json:"device_id"`
	SenderDeviceID  device.ID  `json:"sender_device_id"`
	SenderPublicKey string     `json:"sender_public_key"`
	Envelope        string     `json:"envelope"`
	CreatedAt       string     `json:"created_at"`
}

func (h *Handler) handleChannelKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if h.channels == nil {
		writeError(w, http.StatusInternalServerError, errors.New("channel service not configured"))
		return
	}

	session, err := h.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}

	if r.Method == http.MethodGet {
		channelID := channel.ID(strings.TrimSpace(r.URL.Query().Get("channel_id")))
		if channelID == "" {
			writeError(w, http.StatusBadRequest, errors.New("channel_id query parameter is required"))
			return
		}
		env, err := h.channels.GetKeyEnvelope(r.Context(), session.UserID, channelID, session.DeviceID)
		if err != nil {
			switch {
			case errors.Is(err, channel.ErrInvalidInput):
				writeError(w, http.StatusBadRequest, err)
			case errors.Is(err, storage.ErrNotFound):
				writeError(w, http.StatusNotFound, err)
			default:
				writeError(w, http.StatusInternalServerError, err)
			}
			return
		}

		resp := channelKeyEnvelopeResponse{
			ChannelID:       env.ChannelID,
			DeviceID:        env.DeviceID,
			SenderDeviceID:  env.SenderDeviceID,
			SenderPublicKey: env.SenderPublicKey,
			Envelope:        env.Envelope,
			CreatedAt:       env.CreatedAt.UTC().Format(timeLayout),
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}

	var req channelKeyEnvelopesRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.ChannelID == "" || len(req.Envelopes) == 0 {
		writeError(w, http.StatusBadRequest, errors.New("channel_id and envelopes are required"))
		return
	}
	if _, err := h.channels.GetChannel(r.Context(), session.UserID, req.ChannelID); err != nil {
		switch {
		case errors.Is(err, channel.ErrInvalidInput):
			writeError(w, http.StatusBadRequest, err)
		case errors.Is(err, storage.ErrNotFound):
			writeError(w, http.StatusNotFound, err)
		default:
			writeError(w, http.StatusInternalServerError, err)
		}
		return
	}
	for _, envReq := range req.Envelopes {
		if envReq.SenderDeviceID != session.DeviceID {
			writeError(w, http.StatusForbidden, errors.New("sender_device_id must match the current device"))
			return
		}
		env := channel.KeyEnvelope{
			ChannelID:       req.ChannelID,
			DeviceID:        envReq.DeviceID,
			SenderDeviceID:  envReq.SenderDeviceID,
			SenderPublicKey: strings.TrimSpace(envReq.SenderPublicKey),
			Envelope:        strings.TrimSpace(envReq.Envelope),
			CreatedAt:       time.Now().UTC(),
		}
		if err := h.channels.UpsertKeyEnvelope(r.Context(), session.UserID, env); err != nil {
			switch {
			case errors.Is(err, channel.ErrInvalidInput):
				writeError(w, http.StatusBadRequest, err)
			default:
				writeError(w, http.StatusInternalServerError, err)
			}
			return
		}
	}
	writeJSON(w, http.StatusCreated, map[string]string{"status": "ok"})
}

type createServerInviteResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
}

func (h *Handler) handleServerInvites(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if h.invites == nil {
		writeError(w, http.StatusInternalServerError, errors.New("invite service not configured"))
		return
	}
	if !h.authenticateAdmin(r) {
		session, err := h.authenticate(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, errors.New("admin token required"))
			return
		}
		adminUser, err := h.users.GetByID(r.Context(), session.UserID)
		if err != nil {
			writeError(w, http.StatusUnauthorized, errors.New("admin token required"))
			return
		}
		if !adminUser.IsAdmin {
			writeError(w, http.StatusForbidden, errors.New("admin access required"))
			return
		}
	}

	invite, err := h.invites.Create(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	resp := createServerInviteResponse{
		Token:     invite.Token,
		ExpiresAt: invite.ExpiresAt.UTC().Format(timeLayout),
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (h *Handler) authenticateAdmin(r *http.Request) bool {
	if strings.TrimSpace(h.adminToken) == "" {
		return false
	}
	return strings.TrimSpace(r.Header.Get("X-Admin-Token")) == h.adminToken
}

type channelResponse struct {
	ID        channel.ID `json:"id"`
	NameEnc   string     `json:"name_enc"`
	CreatedBy user.ID    `json:"created_by"`
	CreatedAt string     `json:"created_at"`
}

type channelMessageResponse struct {
	ID            string     `json:"id"`
	ChannelID     channel.ID `json:"channel_id"`
	SenderID      user.ID    `json:"sender_id"`
	SenderNameEnc string     `json:"sender_name_enc"`
	Body          string     `json:"body"`
	SentAt        string     `json:"sent_at"`
}

type createChannelRequest struct {
	NameEnc string `json:"name_enc"`
}

type updateChannelRequest struct {
	ChannelID channel.ID `json:"channel_id"`
	NameEnc   string     `json:"name_enc"`
}

type createChannelResponse struct {
	Channel channelResponse `json:"channel"`
}

type listChannelsResponse struct {
	Channels []channelResponse `json:"channels"`
}

func (h *Handler) handleChannels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet && r.Method != http.MethodDelete && r.Method != http.MethodPatch {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if h.channels == nil {
		writeError(w, http.StatusInternalServerError, errors.New("channel service not configured"))
		return
	}

	session, err := h.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}
	if r.Method != http.MethodGet {
		adminUser, err := h.users.GetByID(r.Context(), session.UserID)
		if err != nil {
			writeError(w, http.StatusUnauthorized, errors.New("admin access required"))
			return
		}
		if !adminUser.IsAdmin {
			writeError(w, http.StatusForbidden, errors.New("admin access required"))
			return
		}
	}

	if r.Method == http.MethodGet {
		channels, err := h.channels.ListChannels(r.Context(), session.UserID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		resp := listChannelsResponse{Channels: make([]channelResponse, 0, len(channels))}
		for _, ch := range channels {
			resp.Channels = append(resp.Channels, channelResponse{
				ID:        ch.ID,
				NameEnc:   ch.NameEnc,
				CreatedBy: ch.CreatedBy,
				CreatedAt: ch.CreatedAt.UTC().Format(timeLayout),
			})
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}

	if r.Method == http.MethodDelete {
		channelID := channel.ID(strings.TrimSpace(r.URL.Query().Get("channel_id")))
		if channelID == "" {
			writeError(w, http.StatusBadRequest, errors.New("channel_id query parameter is required"))
			return
		}
		if err := h.channels.DeleteChannel(r.Context(), session.UserID, channelID); err != nil {
			switch {
			case errors.Is(err, channel.ErrInvalidInput):
				writeError(w, http.StatusBadRequest, err)
			case errors.Is(err, channel.ErrForbidden):
				writeError(w, http.StatusForbidden, err)
			case errors.Is(err, storage.ErrNotFound):
				writeError(w, http.StatusNotFound, err)
			default:
				writeError(w, http.StatusInternalServerError, err)
			}
			return
		}
		if h.notifier != nil {
			h.notifier.NotifyChannelDeleted(channelID)
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if r.Method == http.MethodPatch {
		var req updateChannelRequest
		if err := decodeJSON(w, r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		updated, err := h.channels.UpdateChannelName(r.Context(), session.UserID, req.ChannelID, req.NameEnc)
		if err != nil {
			switch {
			case errors.Is(err, channel.ErrInvalidInput):
				writeError(w, http.StatusBadRequest, err)
			case errors.Is(err, channel.ErrForbidden):
				writeError(w, http.StatusForbidden, err)
			case errors.Is(err, storage.ErrNotFound):
				writeError(w, http.StatusNotFound, err)
			default:
				writeError(w, http.StatusInternalServerError, err)
			}
			return
		}
		if h.notifier != nil {
			h.notifier.NotifyChannelUpdated(updated)
		}
		resp := createChannelResponse{Channel: channelResponse{
			ID:        updated.ID,
			NameEnc:   updated.NameEnc,
			CreatedBy: updated.CreatedBy,
			CreatedAt: updated.CreatedAt.UTC().Format(timeLayout),
		}}
		writeJSON(w, http.StatusOK, resp)
		return
	}

	var req createChannelRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	created, err := h.channels.CreateChannel(r.Context(), session.UserID, req.NameEnc)
	if err != nil {
		switch {
		case errors.Is(err, channel.ErrInvalidInput):
			writeError(w, http.StatusBadRequest, err)
		case errors.Is(err, channel.ErrForbidden):
			writeError(w, http.StatusForbidden, err)
		default:
			writeError(w, http.StatusInternalServerError, err)
		}
		return
	}

	resp := createChannelResponse{Channel: channelResponse{
		ID:        created.ID,
		NameEnc:   created.NameEnc,
		CreatedBy: created.CreatedBy,
		CreatedAt: created.CreatedAt.UTC().Format(timeLayout),
	}}
	if h.notifier != nil {
		h.notifier.NotifyChannelUpdated(created)
	}
	writeJSON(w, http.StatusCreated, resp)
}

type channelMessagesResponse struct {
	ChannelID channel.ID               `json:"channel_id"`
	Messages  []channelMessageResponse `json:"messages"`
}

func (h *Handler) handleChannelMessages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if h.channels == nil {
		writeError(w, http.StatusInternalServerError, errors.New("channel service not configured"))
		return
	}

	session, err := h.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}

	channelID := channel.ID(strings.TrimSpace(r.URL.Query().Get("channel_id")))
	if channelID == "" {
		writeError(w, http.StatusBadRequest, errors.New("channel_id query parameter is required"))
		return
	}

	limit := 0
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			limit = parsed
		}
	}

	msgs, err := h.channels.ListMessages(r.Context(), session.UserID, channelID, limit)
	if err != nil {
		switch {
		case errors.Is(err, channel.ErrInvalidInput):
			writeError(w, http.StatusBadRequest, err)
		case errors.Is(err, channel.ErrNotFound), errors.Is(err, storage.ErrNotFound):
			writeError(w, http.StatusNotFound, err)
		default:
			writeError(w, http.StatusInternalServerError, err)
		}
		return
	}

	resp := channelMessagesResponse{
		ChannelID: channelID,
		Messages:  make([]channelMessageResponse, 0, len(msgs)),
	}
	for _, msg := range msgs {
		resp.Messages = append(resp.Messages, channelMessageResponse{
			ID:            msg.ID,
			ChannelID:     msg.ChannelID,
			SenderID:      msg.SenderID,
			SenderNameEnc: msg.SenderNameEnc,
			Body:          msg.Body,
			SentAt:        msg.SentAt.UTC().Format(timeLayout),
		})
	}
	writeJSON(w, http.StatusOK, resp)
}

type presenceRequest struct {
	UserIDs []user.ID `json:"user_ids"`
}

type presenceResponse struct {
	Statuses map[user.ID]bool `json:"statuses"`
	Admins   map[user.ID]bool `json:"admins"`
}

func (h *Handler) handlePresence(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if _, err := h.authenticate(r); err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}

	var req presenceRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	statuses := make(map[user.ID]bool, len(req.UserIDs))
	admins := make(map[user.ID]bool, len(req.UserIDs))
	if h.presence != nil {
		for _, id := range req.UserIDs {
			if id == "" {
				continue
			}
			statuses[id] = h.presence.IsOnline(id)
			if h.users != nil {
				if u, err := h.users.GetByID(r.Context(), id); err == nil {
					admins[id] = u.IsAdmin
				}
			}
		}
	}

	writeJSON(w, http.StatusOK, presenceResponse{Statuses: statuses, Admins: admins})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("multiple json objects are not allowed")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, err error) {
	securelog.Error("httpapi", err)
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
