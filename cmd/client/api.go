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
	IsAdmin      bool   `json:"is_admin"`
}

type apiError struct {
	Error string `json:"error"`
}

type ChannelResponse struct {
	ID        string `json:"id"`
	NameEnc   string `json:"name_enc"`
	CreatedBy string `json:"created_by"`
	CreatedAt string `json:"created_at"`
}

type CreateChannelResponse struct {
	Channel ChannelResponse `json:"channel"`
}

type ListChannelsResponse struct {
	Channels []ChannelResponse `json:"channels"`
}

type ChannelMessageResponse struct {
	ID            string `json:"id"`
	ChannelID     string `json:"channel_id"`
	SenderID      string `json:"sender_id"`
	SenderNameEnc string `json:"sender_name_enc"`
	Body          string `json:"body"`
	SentAt        string `json:"sent_at"`
}

type CreateServerInviteResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
}

type PresenceResponse struct {
	Statuses map[string]bool `json:"statuses"`
	Admins   map[string]bool `json:"admins"`
}

type DeviceKey struct {
	UserID    string `json:"user_id,omitempty"`
	DeviceID  string `json:"device_id"`
	PublicKey string `json:"public_key"`
}

type DeviceKeysResponse struct {
	UserID string      `json:"user_id"`
	Keys   []DeviceKey `json:"keys"`
}

type ChannelKeyEnvelope struct {
	ChannelID       string `json:"channel_id"`
	DeviceID        string `json:"device_id"`
	SenderDeviceID  string `json:"sender_device_id"`
	SenderPublicKey string `json:"sender_public_key"`
	Envelope        string `json:"envelope"`
	CreatedAt       string `json:"created_at"`
}

type ChannelKeyEnvelopeRequest struct {
	DeviceID        string `json:"device_id"`
	SenderDeviceID  string `json:"sender_device_id"`
	SenderPublicKey string `json:"sender_public_key"`
	Envelope        string `json:"envelope"`
}

type ChannelKeyEnvelopesRequest struct {
	ChannelID string                      `json:"channel_id"`
	Envelopes []ChannelKeyEnvelopeRequest `json:"envelopes"`
}

func NewAPIClient(serverURL string) *APIClient {
	return &APIClient{
		serverURL: serverURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (c *APIClient) Register(ctx context.Context, username, password, inviteToken string) (*AuthResponse, *crypto.KeyPair, error) {
	return c.authRequest(ctx, "/auth/register", username, password, inviteToken)
}

func (c *APIClient) Login(ctx context.Context, username, password string) (*AuthResponse, *crypto.KeyPair, error) {
	return c.authRequest(ctx, "/auth/login", username, password, "")
}

func (c *APIClient) authRequest(ctx context.Context, path, username, password, inviteToken string) (*AuthResponse, *crypto.KeyPair, error) {
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
	if inviteToken != "" {
		body["invite_token"] = inviteToken
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

func (c *APIClient) CreateChannel(ctx context.Context, token, nameEnc string) (*ChannelResponse, error) {
	payload := map[string]string{"name_enc": nameEnc}
	var resp CreateChannelResponse
	if err := c.doJSON(ctx, http.MethodPost, "/channels", token, payload, &resp); err != nil {
		return nil, err
	}
	return &resp.Channel, nil
}

func (c *APIClient) ListChannels(ctx context.Context, token string) ([]ChannelResponse, error) {
	var resp ListChannelsResponse
	if err := c.doJSON(ctx, http.MethodGet, "/channels", token, nil, &resp); err != nil {
		return nil, err
	}
	return resp.Channels, nil
}

func (c *APIClient) DeleteChannel(ctx context.Context, token, channelID string) error {
	query := url.Values{}
	query.Set("channel_id", channelID)
	path := "/channels?" + query.Encode()
	return c.doJSON(ctx, http.MethodDelete, path, token, nil, nil)
}

func (c *APIClient) UpdateChannelName(ctx context.Context, token, channelID, nameEnc string) (*ChannelResponse, error) {
	payload := map[string]string{"channel_id": channelID, "name_enc": nameEnc}
	var resp CreateChannelResponse
	if err := c.doJSON(ctx, http.MethodPatch, "/channels", token, payload, &resp); err != nil {
		return nil, err
	}
	return &resp.Channel, nil
}

func (c *APIClient) ListChannelMessages(ctx context.Context, token, channelID string, limit int) ([]ChannelMessageResponse, error) {
	query := url.Values{}
	query.Set("channel_id", channelID)
	if limit > 0 {
		query.Set("limit", strconv.Itoa(limit))
	}
	path := "/channels/messages?" + query.Encode()
	var resp ChannelMessagesResponse
	if err := c.doJSON(ctx, http.MethodGet, path, token, nil, &resp); err != nil {
		return nil, err
	}
	return resp.Messages, nil
}

type ChannelMessagesResponse struct {
	ChannelID string                   `json:"channel_id"`
	Messages  []ChannelMessageResponse `json:"messages"`
}

func (c *APIClient) CreateServerInvite(ctx context.Context, token string) (*CreateServerInviteResponse, error) {
	var resp CreateServerInviteResponse
	if err := c.doJSON(ctx, http.MethodPost, "/server/invites", token, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *APIClient) FetchPresence(ctx context.Context, token string, userIDs []string) (map[string]bool, map[string]bool, error) {
	payload := map[string][]string{"user_ids": userIDs}
	var resp PresenceResponse
	if err := c.doJSON(ctx, http.MethodPost, "/presence", token, payload, &resp); err != nil {
		return nil, nil, err
	}
	if resp.Statuses == nil {
		resp.Statuses = map[string]bool{}
	}
	if resp.Admins == nil {
		resp.Admins = map[string]bool{}
	}
	return resp.Statuses, resp.Admins, nil
}

func (c *APIClient) ListAllDeviceKeys(ctx context.Context, token string) ([]DeviceKey, error) {
	var resp DeviceKeysResponse
	if err := c.doJSON(ctx, http.MethodGet, "/devices/keys?all=1", token, nil, &resp); err != nil {
		return nil, err
	}
	return resp.Keys, nil
}

func (c *APIClient) GetChannelKeyEnvelope(ctx context.Context, token, channelID string) (*ChannelKeyEnvelope, error) {
	query := url.Values{}
	query.Set("channel_id", channelID)
	path := "/channels/keys?" + query.Encode()
	var resp ChannelKeyEnvelope
	if err := c.doJSON(ctx, http.MethodGet, path, token, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *APIClient) PutChannelKeyEnvelopes(ctx context.Context, token, channelID string, envelopes []ChannelKeyEnvelopeRequest) error {
	payload := ChannelKeyEnvelopesRequest{ChannelID: channelID, Envelopes: envelopes}
	return c.doJSON(ctx, http.MethodPost, "/channels/keys", token, payload, nil)
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
