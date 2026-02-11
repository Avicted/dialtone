package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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

func TestAPIClientRegisterAndChannelOps(t *testing.T) {
	setTestConfigDir(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/auth/register":
			var payload map[string]string
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode payload: %v", err)
			}
			if payload["invite_token"] != "invite" {
				t.Fatalf("unexpected invite token: %q", payload["invite_token"])
			}
			_ = json.NewEncoder(w).Encode(AuthResponse{Token: "token", UserID: "user", DeviceID: "dev"})
		case r.Method == http.MethodGet && r.URL.Path == "/channels":
			_ = json.NewEncoder(w).Encode(ListChannelsResponse{Channels: []ChannelResponse{{ID: "ch-1", NameEnc: "enc"}}})
		case r.Method == http.MethodPatch && r.URL.Path == "/channels":
			var payload map[string]string
			_ = json.NewDecoder(r.Body).Decode(&payload)
			_ = json.NewEncoder(w).Encode(CreateChannelResponse{Channel: ChannelResponse{ID: payload["channel_id"], NameEnc: payload["name_enc"]}})
		case r.Method == http.MethodDelete && r.URL.Path == "/channels":
			if r.URL.Query().Get("channel_id") != "ch-1" {
				t.Fatalf("unexpected channel_id: %s", r.URL.RawQuery)
			}
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	api := &APIClient{serverURL: server.URL, httpClient: server.Client()}
	ctx := context.Background()
	if _, _, err := api.Register(ctx, "alice", "password", "invite", "passphrase123"); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := api.ListChannels(ctx, "token"); err != nil {
		t.Fatalf("ListChannels: %v", err)
	}
	if _, err := api.UpdateChannelName(ctx, "token", "ch-1", "enc"); err != nil {
		t.Fatalf("UpdateChannelName: %v", err)
	}
	if err := api.DeleteChannel(ctx, "token", "ch-1"); err != nil {
		t.Fatalf("DeleteChannel: %v", err)
	}
}

func TestAPIClientMessagesPresenceAndKeys(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/channels/messages"):
			if r.URL.Query().Get("limit") != "10" {
				t.Fatalf("unexpected limit: %s", r.URL.RawQuery)
			}
			_ = json.NewEncoder(w).Encode(ChannelMessagesResponse{Messages: []ChannelMessageResponse{{ID: "m1"}}})
		case r.Method == http.MethodPost && r.URL.Path == "/presence":
			_ = json.NewEncoder(w).Encode(PresenceResponse{})
		case r.Method == http.MethodGet && r.URL.Path == "/devices/keys":
			if r.URL.Query().Get("all") != "1" {
				t.Fatalf("unexpected query: %s", r.URL.RawQuery)
			}
			_ = json.NewEncoder(w).Encode(DeviceKeysResponse{Keys: []DeviceKey{{DeviceID: "dev", PublicKey: "pub"}}})
		case r.Method == http.MethodGet && r.URL.Path == "/channels/keys":
			_ = json.NewEncoder(w).Encode(ChannelKeyEnvelope{ChannelID: "ch-1", Envelope: "ct"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	api := &APIClient{serverURL: server.URL, httpClient: server.Client()}
	ctx := context.Background()
	if _, err := api.ListChannelMessages(ctx, "token", "ch-1", 10); err != nil {
		t.Fatalf("ListChannelMessages: %v", err)
	}
	statuses, admins, err := api.FetchPresence(ctx, "token", []string{"u1"})
	if err != nil {
		t.Fatalf("FetchPresence: %v", err)
	}
	if statuses == nil || admins == nil {
		t.Fatalf("expected non-nil maps")
	}
	if _, err := api.ListAllDeviceKeys(ctx, "token"); err != nil {
		t.Fatalf("ListAllDeviceKeys: %v", err)
	}
	if _, err := api.GetChannelKeyEnvelope(ctx, "token", "ch-1"); err != nil {
		t.Fatalf("GetChannelKeyEnvelope: %v", err)
	}
}

func TestAPIClientProfilesAndDirectoryKeys(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/users/profiles":
			_ = json.NewEncoder(w).Encode(ListUserProfilesResponse{Profiles: []UserProfile{{UserID: "u1"}}})
		case r.Method == http.MethodPost && r.URL.Path == "/users/profiles":
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && r.URL.Path == "/directory/keys":
			var payload DirectoryKeyEnvelopesRequest
			_ = json.NewDecoder(r.Body).Decode(&payload)
			if len(payload.Envelopes) == 0 {
				t.Fatalf("expected envelopes")
			}
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && r.URL.Path == "/channels/keys":
			var payload ChannelKeyEnvelopesRequest
			_ = json.NewDecoder(r.Body).Decode(&payload)
			if payload.ChannelID != "ch-1" {
				t.Fatalf("unexpected channel id: %q", payload.ChannelID)
			}
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Path == "/directory/keys":
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	api := &APIClient{serverURL: server.URL, httpClient: server.Client()}
	ctx := context.Background()
	if _, err := api.ListUserProfiles(ctx, "token"); err != nil {
		t.Fatalf("ListUserProfiles: %v", err)
	}
	if err := api.UpsertUserProfile(ctx, "token", "enc"); err != nil {
		t.Fatalf("UpsertUserProfile: %v", err)
	}
	if err := api.PutDirectoryKeyEnvelopes(ctx, "token", []DirectoryKeyEnvelopeRequest{{DeviceID: "dev"}}); err != nil {
		t.Fatalf("PutDirectoryKeyEnvelopes: %v", err)
	}
	if err := api.PutChannelKeyEnvelopes(ctx, "token", "ch-1", []ChannelKeyEnvelopeRequest{{DeviceID: "dev"}}); err != nil {
		t.Fatalf("PutChannelKeyEnvelopes: %v", err)
	}
	if _, err := api.GetDirectoryKeyEnvelope(ctx, "token"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected not found error, got %v", err)
	}
}

func TestNewAPIClientDefaults(t *testing.T) {
	api := NewAPIClient("http://server")
	if api.serverURL != "http://server" {
		t.Fatalf("unexpected server url: %s", api.serverURL)
	}
	if api.httpClient == nil || api.httpClient.Timeout != 10*time.Second {
		t.Fatalf("unexpected http client")
	}
}

func TestAPIClientLoginServerError(t *testing.T) {
	setTestConfigDir(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(apiError{Error: "bad login"})
	}))
	defer server.Close()

	api := &APIClient{serverURL: server.URL, httpClient: server.Client()}
	if _, _, err := api.Login(context.Background(), "alice", "password", "passphrase123"); err == nil {
		t.Fatalf("expected login error")
	}
}

func TestAPIClientAuthRequestDecodeError(t *testing.T) {
	setTestConfigDir(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("{invalid"))
	}))
	defer server.Close()

	api := &APIClient{serverURL: server.URL, httpClient: server.Client()}
	if _, _, err := api.Login(context.Background(), "alice", "password", "passphrase123"); err == nil {
		t.Fatalf("expected decode error")
	}
}

func TestAPIClientDoJSONPayloadMarshalError(t *testing.T) {
	api := &APIClient{serverURL: "http://server", httpClient: http.DefaultClient}
	payload := map[string]any{"bad": make(chan int)}
	if err := api.doJSON(context.Background(), http.MethodPost, "/x", "", payload, nil); err == nil {
		t.Fatalf("expected marshal error")
	}
}

func TestAPIClientGetDirectoryKeyEnvelopeErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(apiError{Error: "boom"})
	}))
	defer server.Close()

	api := &APIClient{serverURL: server.URL, httpClient: server.Client()}
	if _, err := api.GetDirectoryKeyEnvelope(context.Background(), "token"); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected error")
	}
}

func TestAPIClientGetDirectoryKeyEnvelopeDecodeError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{invalid"))
	}))
	defer server.Close()

	api := &APIClient{serverURL: server.URL, httpClient: server.Client()}
	if _, err := api.GetDirectoryKeyEnvelope(context.Background(), "token"); err == nil {
		t.Fatalf("expected decode error")
	}
}

func TestAPIClientListChannelMessagesNoLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "channel_id=ch-1" {
			t.Fatalf("unexpected query: %s", r.URL.RawQuery)
		}
		_ = json.NewEncoder(w).Encode(ChannelMessagesResponse{Messages: nil})
	}))
	defer server.Close()

	api := &APIClient{serverURL: server.URL, httpClient: server.Client()}
	if _, err := api.ListChannelMessages(context.Background(), "token", "ch-1", 0); err != nil {
		t.Fatalf("ListChannelMessages: %v", err)
	}
}
