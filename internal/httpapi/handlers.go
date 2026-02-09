package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/Avicted/dialtone/internal/device"
	"github.com/Avicted/dialtone/internal/user"
)

const (
	maxBodyBytes = 1 << 20
	timeLayout   = time.RFC3339Nano
)

type Handler struct {
	users   *user.Service
	devices *device.Service
}

func NewHandler(users *user.Service, devices *device.Service) *Handler {
	return &Handler{
		users:   users,
		devices: devices,
	}
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("/users", h.handleUsers)
	mux.HandleFunc("/devices", h.handleDevices)
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
