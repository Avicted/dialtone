package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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
