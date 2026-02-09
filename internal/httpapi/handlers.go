package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/Avicted/dialtone/internal/auth"
	"github.com/Avicted/dialtone/internal/device"
	"github.com/Avicted/dialtone/internal/storage"
	"github.com/Avicted/dialtone/internal/user"
)

const (
	maxBodyBytes = 1 << 20
	timeLayout   = time.RFC3339Nano
)

type Handler struct {
	users   *user.Service
	devices *device.Service
	auth    *auth.Service
}

func NewHandler(users *user.Service, devices *device.Service, auth *auth.Service) *Handler {
	return &Handler{
		users:   users,
		devices: devices,
		auth:    auth,
	}
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("/users", h.handleUsers)
	mux.HandleFunc("/devices", h.handleDevices)
	mux.HandleFunc("/devices/keys", h.handleDeviceKeys)
	mux.HandleFunc("/auth/register", h.handleRegister)
	mux.HandleFunc("/auth/login", h.handleLogin)
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
		Username:     createdUser.Username,
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
		Username:     createdUser.Username,
		DevicePubKey: createdDevice.PublicKey,
	}
	writeJSON(w, http.StatusOK, resp)
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
		Username:  created.Username,
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
