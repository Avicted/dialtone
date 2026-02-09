package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/Avicted/dialtone/internal/crypto"
)

type APIClient struct {
	serverURL  string
	httpClient *http.Client
}

type AuthResponse struct {
	Token        string `json:"token"`
	UserID       string `json:"user_id"`
	DeviceID     string `json:"device_id"`
	ExpiresAt    string `json:"expires_at"`
	Username     string `json:"username"`
	DevicePubKey string `json:"device_public_key"`
}

type apiError struct {
	Error string `json:"error"`
}

type RoomResponse struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	CreatedBy string `json:"created_by"`
	CreatedAt string `json:"created_at"`
}

type CreateRoomResponse struct {
	Room RoomResponse `json:"room"`
}

type ListRoomsResponse struct {
	Rooms []RoomResponse `json:"rooms"`
}

type CreateInviteResponse struct {
	Token     string `json:"token"`
	RoomID    string `json:"room_id"`
	ExpiresAt string `json:"expires_at"`
}

type JoinRoomResponse struct {
	Room     RoomResponse          `json:"room"`
	JoinedAt string                `json:"joined_at"`
	Messages []RoomMessageResponse `json:"messages"`
}

type RoomMessageResponse struct {
	ID         string `json:"id"`
	RoomID     string `json:"room_id"`
	SenderID   string `json:"sender_id"`
	SenderName string `json:"sender_name"`
	Body       string `json:"body"`
	SentAt     string `json:"sent_at"`
}

type RoomMemberResponse struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Online   bool   `json:"online"`
}

type RoomMembersResponse struct {
	RoomID  string               `json:"room_id"`
	Members []RoomMemberResponse `json:"members"`
}

// DeviceKeysResponse is the response from GET /devices/keys.
type DeviceKeysResponse struct {
	UserID string          `json:"user_id"`
	Keys   []DeviceKeyInfo `json:"keys"`
}

// DeviceKeyInfo is a single device's public key.
type DeviceKeyInfo struct {
	DeviceID  string `json:"device_id"`
	PublicKey string `json:"public_key"`
}

func NewAPIClient(serverURL string) *APIClient {
	return &APIClient{
		serverURL: serverURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (c *APIClient) Register(ctx context.Context, username, password string) (*AuthResponse, *crypto.KeyPair, error) {
	return c.authRequest(ctx, "/auth/register", username, password)
}

func (c *APIClient) Login(ctx context.Context, username, password string) (*AuthResponse, *crypto.KeyPair, error) {
	return c.authRequest(ctx, "/auth/login", username, password)
}

func (c *APIClient) authRequest(ctx context.Context, path, username, password string) (*AuthResponse, *crypto.KeyPair, error) {
	kp, err := loadOrCreateKeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("load device key: %w", err)
	}

	pubKeyB64 := crypto.PublicKeyToBase64(kp.Public)

	body := map[string]string{
		"username":   username,
		"password":   password,
		"public_key": pubKeyB64,
	}
	data, err := json.Marshal(body)
	if err != nil {
		return nil, nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.serverURL+path, bytes.NewReader(data))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		var apiErr apiError
		_ = json.NewDecoder(resp.Body).Decode(&apiErr)
		if apiErr.Error != "" {
			return nil, nil, fmt.Errorf("server: %s", apiErr.Error)
		}
		return nil, nil, fmt.Errorf("server returned %d", resp.StatusCode)
	}

	var authResp AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return nil, nil, fmt.Errorf("decode response: %w", err)
	}
	return &authResp, kp, nil
}

// FetchDeviceKeys retrieves the public keys for all devices of a given user.
func (c *APIClient) FetchDeviceKeys(ctx context.Context, userID string) (*DeviceKeysResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.serverURL+"/devices/keys?user_id="+userID, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		var apiErr apiError
		_ = json.NewDecoder(resp.Body).Decode(&apiErr)
		if apiErr.Error != "" {
			return nil, fmt.Errorf("server: %s", apiErr.Error)
		}
		return nil, fmt.Errorf("server returned %d", resp.StatusCode)
	}

	var keysResp DeviceKeysResponse
	if err := json.NewDecoder(resp.Body).Decode(&keysResp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &keysResp, nil
}

// FetchAllDeviceKeys retrieves public keys for all devices.
func (c *APIClient) FetchAllDeviceKeys(ctx context.Context) (*DeviceKeysResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.serverURL+"/devices/keys?all=1", nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		var apiErr apiError
		_ = json.NewDecoder(resp.Body).Decode(&apiErr)
		if apiErr.Error != "" {
			return nil, fmt.Errorf("server: %s", apiErr.Error)
		}
		return nil, fmt.Errorf("server returned %d", resp.StatusCode)
	}

	var keysResp DeviceKeysResponse
	if err := json.NewDecoder(resp.Body).Decode(&keysResp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &keysResp, nil
}

func (c *APIClient) CreateRoom(ctx context.Context, token, name string) (*RoomResponse, error) {
	payload := map[string]string{"name": name}
	var resp CreateRoomResponse
	if err := c.doJSON(ctx, http.MethodPost, "/rooms", token, payload, &resp); err != nil {
		return nil, err
	}
	return &resp.Room, nil
}

func (c *APIClient) ListRooms(ctx context.Context, token string) ([]RoomResponse, error) {
	var resp ListRoomsResponse
	if err := c.doJSON(ctx, http.MethodGet, "/rooms", token, nil, &resp); err != nil {
		return nil, err
	}
	return resp.Rooms, nil
}

func (c *APIClient) CreateRoomInvite(ctx context.Context, token, roomID string) (*CreateInviteResponse, error) {
	payload := map[string]string{"room_id": roomID}
	var resp CreateInviteResponse
	if err := c.doJSON(ctx, http.MethodPost, "/rooms/invites", token, payload, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *APIClient) JoinRoom(ctx context.Context, token, inviteToken string) (*JoinRoomResponse, error) {
	payload := map[string]string{"token": inviteToken}
	var resp JoinRoomResponse
	if err := c.doJSON(ctx, http.MethodPost, "/rooms/join", token, payload, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *APIClient) ListRoomMessages(ctx context.Context, token, roomID string, limit int) ([]RoomMessageResponse, error) {
	query := url.Values{}
	query.Set("room_id", roomID)
	if limit > 0 {
		query.Set("limit", strconv.Itoa(limit))
	}
	path := "/rooms/messages?" + query.Encode()
	var resp RoomMessagesResponse
	if err := c.doJSON(ctx, http.MethodGet, path, token, nil, &resp); err != nil {
		return nil, err
	}
	return resp.Messages, nil
}

func (c *APIClient) ListRoomMembers(ctx context.Context, token, roomID string) ([]RoomMemberResponse, error) {
	query := url.Values{}
	query.Set("room_id", roomID)
	path := "/rooms/members?" + query.Encode()
	var resp RoomMembersResponse
	if err := c.doJSON(ctx, http.MethodGet, path, token, nil, &resp); err != nil {
		return nil, err
	}
	return resp.Members, nil
}

type RoomMessagesResponse struct {
	RoomID   string                `json:"room_id"`
	Messages []RoomMessageResponse `json:"messages"`
}

func (c *APIClient) doJSON(ctx context.Context, method, path, token string, payload any, out any) error {
	var body *bytes.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	} else {
		body = bytes.NewReader(nil)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.serverURL+path, body)
	if err != nil {
		return err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		var apiErr apiError
		_ = json.NewDecoder(resp.Body).Decode(&apiErr)
		if apiErr.Error != "" {
			return fmt.Errorf("server: %s", apiErr.Error)
		}
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}

	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}
