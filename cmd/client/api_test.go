package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAPIClientDoJSONSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected method POST, got %s", r.Method)
			return
		}
		if r.URL.Path != "/channels" {
			t.Errorf("expected path /channels, got %s", r.URL.Path)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer token" {
			t.Errorf("expected auth header, got %q", got)
			return
		}
		var payload map[string]string
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode payload: %v", err)
			return
		}
		if payload["name_enc"] != "encrypted" {
			t.Errorf("unexpected payload: %#v", payload)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(CreateChannelResponse{Channel: ChannelResponse{ID: "ch-1", NameEnc: "encrypted"}})
	}))
	defer server.Close()

	api := &APIClient{serverURL: server.URL, httpClient: server.Client()}
	ctx := context.Background()
	var resp CreateChannelResponse
	if err := api.doJSON(ctx, http.MethodPost, "/channels", "token", map[string]string{"name_enc": "encrypted"}, &resp); err != nil {
		t.Fatalf("doJSON: %v", err)
	}
	if resp.Channel.ID != "ch-1" {
		t.Fatalf("unexpected response: %#v", resp)
	}
}

func TestAPIClientDoJSONServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(apiError{Error: "bad request"})
	}))
	defer server.Close()

	api := &APIClient{serverURL: server.URL, httpClient: server.Client()}
	ctx := context.Background()
	var resp CreateChannelResponse
	err := api.doJSON(ctx, http.MethodPost, "/channels", "token", map[string]string{"name_enc": "x"}, &resp)
	if err == nil || !strings.Contains(err.Error(), "bad request") {
		t.Fatalf("expected server error, got %v", err)
	}
}

func TestAPIClientDoJSONDecodeError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{invalid"))
	}))
	defer server.Close()

	api := &APIClient{serverURL: server.URL, httpClient: server.Client()}
	ctx := context.Background()
	var resp CreateChannelResponse
	err := api.doJSON(ctx, http.MethodGet, "/channels", "token", nil, &resp)
	if err == nil || !strings.Contains(err.Error(), "decode response") {
		t.Fatalf("expected decode error, got %v", err)
	}
}

func TestAPIClientAuthRequest(t *testing.T) {
	setTestConfigDir(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/login" {
			t.Errorf("expected /auth/login, got %s", r.URL.Path)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(AuthResponse{Token: "token", UserID: "user", DeviceID: "dev", Username: "alice", DevicePubKey: "pub"})
	}))
	defer server.Close()

	api := &APIClient{serverURL: server.URL, httpClient: server.Client()}
	resp, kp, err := api.Login(context.Background(), "alice", "password", "passphrase123")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if resp.Token != "token" || kp == nil {
		t.Fatalf("unexpected auth response: %#v", resp)
	}
}
