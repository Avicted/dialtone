package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Avicted/dialtone/internal/auth"
	"github.com/Avicted/dialtone/internal/device"
	"github.com/Avicted/dialtone/internal/room"
	"github.com/Avicted/dialtone/internal/storage"
	"github.com/Avicted/dialtone/internal/user"
)

const (
	maxBodyBytes = 1 << 20
	timeLayout   = time.RFC3339Nano
)

type Handler struct {
	users    *user.Service
	devices  *device.Service
	rooms    *room.Service
	auth     *auth.Service
	presence PresenceProvider
}

type PresenceProvider interface {
	IsOnline(userID user.ID) bool
}

func NewHandler(users *user.Service, devices *device.Service, rooms *room.Service, auth *auth.Service, presence PresenceProvider) *Handler {
	return &Handler{
		users:    users,
		devices:  devices,
		rooms:    rooms,
		auth:     auth,
		presence: presence,
	}
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("/users", h.handleUsers)
	mux.HandleFunc("/devices", h.handleDevices)
	mux.HandleFunc("/devices/keys", h.handleDeviceKeys)
	mux.HandleFunc("/auth/register", h.handleRegister)
	mux.HandleFunc("/auth/login", h.handleLogin)
	mux.HandleFunc("/rooms", h.handleRooms)
	mux.HandleFunc("/rooms/invites", h.handleRoomInvites)
	mux.HandleFunc("/rooms/join", h.handleRoomJoin)
	mux.HandleFunc("/rooms/messages", h.handleRoomMessages)
	mux.HandleFunc("/rooms/members", h.handleRoomMembers)
}

type authRequest struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	PublicKey string `json:"public_key"`
}

type authResponse struct {
	Token        string    `json:"token"`
	UserID       user.ID   `json:"user_id"`
	DeviceID     device.ID `json:"device_id"`
	ExpiresAt    string    `json:"expires_at"`
	Username     string    `json:"username"`
	DevicePubKey string    `json:"device_public_key"`
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

	createdUser, createdDevice, session, err := h.auth.Register(r.Context(), req.Username, req.Password, req.PublicKey)
	if err != nil {
		switch {
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
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) authenticate(r *http.Request) (auth.Session, error) {
	if h.auth == nil {
		return auth.Session{}, auth.ErrUnauthorized
	}
	if token := strings.TrimSpace(r.URL.Query().Get("token")); token != "" {
		return h.auth.ValidateToken(token)
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

	var req createDeviceRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
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
	DeviceID  device.ID `json:"device_id"`
	PublicKey string    `json:"public_key"`
}

type deviceKeysResponse struct {
	UserID user.ID         `json:"user_id"`
	Keys   []deviceKeyInfo `json:"keys"`
}

// handleDeviceKeys returns the public keys of all devices belonging to a user.
// GET /devices/keys?user_id=<id>
func (h *Handler) handleDeviceKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	all := r.URL.Query().Get("all") == "1"
	userID := user.ID(r.URL.Query().Get("user_id"))
	if !all && userID == "" {
		writeError(w, http.StatusBadRequest, errors.New("user_id query parameter is required"))
		return
	}

	var (
		devices []device.Device
		err     error
	)
	if all {
		devices, err = h.devices.ListAll(r.Context())
	} else {
		devices, err = h.devices.ListByUser(r.Context(), userID)
	}
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

type roomResponse struct {
	ID        room.ID `json:"id"`
	NameEnc   string  `json:"name_enc"`
	CreatedBy user.ID `json:"created_by"`
	CreatedAt string  `json:"created_at"`
}

type roomMessageResponse struct {
	ID            string  `json:"id"`
	RoomID        room.ID `json:"room_id"`
	SenderID      user.ID `json:"sender_id"`
	SenderNameEnc string  `json:"sender_name_enc"`
	Body          string  `json:"body"`
	SentAt        string  `json:"sent_at"`
}

type createRoomRequest struct {
	NameEnc        string `json:"name_enc"`
	DisplayNameEnc string `json:"display_name_enc"`
}

type createRoomResponse struct {
	Room roomResponse `json:"room"`
}

type listRoomsResponse struct {
	Rooms []roomResponse `json:"rooms"`
}

func (h *Handler) handleRooms(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if h.rooms == nil {
		writeError(w, http.StatusInternalServerError, errors.New("room service not configured"))
		return
	}

	session, err := h.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}

	if r.Method == http.MethodGet {
		rooms, err := h.rooms.ListRooms(r.Context(), session.UserID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		resp := listRoomsResponse{Rooms: make([]roomResponse, 0, len(rooms))}
		for _, rm := range rooms {
			resp.Rooms = append(resp.Rooms, roomResponse{
				ID:        rm.ID,
				NameEnc:   rm.NameEnc,
				CreatedBy: rm.CreatedBy,
				CreatedAt: rm.CreatedAt.UTC().Format(timeLayout),
			})
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}

	var req createRoomRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	created, err := h.rooms.CreateRoom(r.Context(), session.UserID, req.NameEnc, req.DisplayNameEnc)
	if err != nil {
		switch {
		case errors.Is(err, room.ErrInvalidInput):
			writeError(w, http.StatusBadRequest, err)
		default:
			writeError(w, http.StatusInternalServerError, err)
		}
		return
	}

	resp := createRoomResponse{Room: roomResponse{
		ID:        created.ID,
		NameEnc:   created.NameEnc,
		CreatedBy: created.CreatedBy,
		CreatedAt: created.CreatedAt.UTC().Format(timeLayout),
	}}
	writeJSON(w, http.StatusCreated, resp)
}

type createInviteRequest struct {
	RoomID room.ID `json:"room_id"`
}

type createInviteResponse struct {
	Token     string  `json:"token"`
	RoomID    room.ID `json:"room_id"`
	ExpiresAt string  `json:"expires_at"`
}

func (h *Handler) handleRoomInvites(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if h.rooms == nil {
		writeError(w, http.StatusInternalServerError, errors.New("room service not configured"))
		return
	}

	session, err := h.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}

	var req createInviteRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	invite, err := h.rooms.CreateInvite(r.Context(), session.UserID, req.RoomID)
	if err != nil {
		switch {
		case errors.Is(err, room.ErrInvalidInput):
			writeError(w, http.StatusBadRequest, err)
		case errors.Is(err, room.ErrNotFound), errors.Is(err, storage.ErrNotFound):
			writeError(w, http.StatusNotFound, err)
		default:
			writeError(w, http.StatusInternalServerError, err)
		}
		return
	}

	resp := createInviteResponse{
		Token:     invite.Token,
		RoomID:    invite.RoomID,
		ExpiresAt: invite.ExpiresAt.UTC().Format(timeLayout),
	}
	writeJSON(w, http.StatusCreated, resp)
}

type joinRoomRequest struct {
	Token          string `json:"token"`
	DisplayNameEnc string `json:"display_name_enc"`
}

type joinRoomResponse struct {
	Room     roomResponse          `json:"room"`
	JoinedAt string                `json:"joined_at"`
	Messages []roomMessageResponse `json:"messages"`
}

func (h *Handler) handleRoomJoin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if h.rooms == nil {
		writeError(w, http.StatusInternalServerError, errors.New("room service not configured"))
		return
	}

	session, err := h.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}

	var req joinRoomRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	joinedRoom, joinedAt, messages, err := h.rooms.JoinWithInvite(r.Context(), session.UserID, req.Token, req.DisplayNameEnc)
	if err != nil {
		switch {
		case errors.Is(err, room.ErrInvalidInput):
			writeError(w, http.StatusBadRequest, err)
		case errors.Is(err, room.ErrInviteExpired), errors.Is(err, room.ErrInviteConsumed):
			writeError(w, http.StatusGone, err)
		case errors.Is(err, room.ErrNotFound), errors.Is(err, storage.ErrNotFound):
			writeError(w, http.StatusNotFound, err)
		default:
			writeError(w, http.StatusInternalServerError, err)
		}
		return
	}

	resp := joinRoomResponse{
		Room: roomResponse{
			ID:        joinedRoom.ID,
			NameEnc:   joinedRoom.NameEnc,
			CreatedBy: joinedRoom.CreatedBy,
			CreatedAt: joinedRoom.CreatedAt.UTC().Format(timeLayout),
		},
		JoinedAt: joinedAt.UTC().Format(timeLayout),
		Messages: make([]roomMessageResponse, 0, len(messages)),
	}
	for _, msg := range messages {
		resp.Messages = append(resp.Messages, roomMessageResponse{
			ID:            msg.ID,
			RoomID:        msg.RoomID,
			SenderID:      msg.SenderID,
			SenderNameEnc: msg.SenderNameEnc,
			Body:          msg.Body,
			SentAt:        msg.SentAt.UTC().Format(timeLayout),
		})
	}
	writeJSON(w, http.StatusOK, resp)
}

type roomMessagesResponse struct {
	RoomID   room.ID               `json:"room_id"`
	Messages []roomMessageResponse `json:"messages"`
}

func (h *Handler) handleRoomMessages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if h.rooms == nil {
		writeError(w, http.StatusInternalServerError, errors.New("room service not configured"))
		return
	}

	session, err := h.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}

	roomID := room.ID(strings.TrimSpace(r.URL.Query().Get("room_id")))
	if roomID == "" {
		writeError(w, http.StatusBadRequest, errors.New("room_id query parameter is required"))
		return
	}

	limit := 0
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			limit = parsed
		}
	}

	msgs, err := h.rooms.ListMessages(r.Context(), session.UserID, roomID, limit)
	if err != nil {
		switch {
		case errors.Is(err, room.ErrInvalidInput):
			writeError(w, http.StatusBadRequest, err)
		case errors.Is(err, room.ErrNotFound), errors.Is(err, storage.ErrNotFound):
			writeError(w, http.StatusNotFound, err)
		default:
			writeError(w, http.StatusInternalServerError, err)
		}
		return
	}

	resp := roomMessagesResponse{
		RoomID:   roomID,
		Messages: make([]roomMessageResponse, 0, len(msgs)),
	}
	for _, msg := range msgs {
		resp.Messages = append(resp.Messages, roomMessageResponse{
			ID:            msg.ID,
			RoomID:        msg.RoomID,
			SenderID:      msg.SenderID,
			SenderNameEnc: msg.SenderNameEnc,
			Body:          msg.Body,
			SentAt:        msg.SentAt.UTC().Format(timeLayout),
		})
	}
	writeJSON(w, http.StatusOK, resp)
}

type roomMemberResponse struct {
	UserID         user.ID `json:"user_id"`
	DisplayNameEnc string  `json:"display_name_enc"`
	Online         bool    `json:"online"`
}

type roomMembersResponse struct {
	RoomID  room.ID              `json:"room_id"`
	Members []roomMemberResponse `json:"members"`
}

func (h *Handler) handleRoomMembers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if h.rooms == nil {
		writeError(w, http.StatusInternalServerError, errors.New("room service not configured"))
		return
	}

	session, err := h.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}

	roomID := room.ID(strings.TrimSpace(r.URL.Query().Get("room_id")))
	if roomID == "" {
		writeError(w, http.StatusBadRequest, errors.New("room_id query parameter is required"))
		return
	}

	members, err := h.rooms.ListMembers(r.Context(), session.UserID, roomID)
	if err != nil {
		switch {
		case errors.Is(err, room.ErrInvalidInput):
			writeError(w, http.StatusBadRequest, err)
		case errors.Is(err, room.ErrNotFound), errors.Is(err, storage.ErrNotFound):
			writeError(w, http.StatusNotFound, err)
		default:
			writeError(w, http.StatusInternalServerError, err)
		}
		return
	}

	resp := roomMembersResponse{RoomID: roomID, Members: make([]roomMemberResponse, 0, len(members))}
	for _, member := range members {
		online := false
		if h.presence != nil {
			online = h.presence.IsOnline(member.UserID)
		}
		resp.Members = append(resp.Members, roomMemberResponse{UserID: member.UserID, DisplayNameEnc: member.DisplayNameEnc, Online: online})
	}
	writeJSON(w, http.StatusOK, resp)
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
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
