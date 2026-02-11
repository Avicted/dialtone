package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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
