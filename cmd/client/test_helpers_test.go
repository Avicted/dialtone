package main

import (
	"testing"

	"github.com/Avicted/dialtone/internal/crypto"
)

func setTestConfigDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	return dir
}

func newTestKeyPair(t *testing.T) *crypto.KeyPair {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	return kp
}

func newTestAuth() *AuthResponse {
	return &AuthResponse{
		Token:     "token",
		UserID:    "user-1",
		DeviceID:  "device-1",
		Username:  "alice",
		IsAdmin:   true,
		IsTrusted: true,
	}
}

func lastSystemMessage(m chatModel) string {
	var msgs []chatMessage
	if m.activeChannel != "" {
		msgs = m.channelMsgs[m.activeChannel]
	} else {
		msgs = m.messages
	}
	if len(msgs) == 0 {
		return ""
	}
	return msgs[len(msgs)-1].body
}
