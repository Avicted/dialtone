package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Avicted/dialtone/internal/crypto"
)

func TestEncryptDecryptKeystoreJSON(t *testing.T) {
	value := storedKey{PrivateKey: "secret"}
	data, err := encryptKeystoreJSON("passphrase123", value)
	if err != nil {
		t.Fatalf("encryptKeystoreJSON: %v", err)
	}

	var decoded storedKey
	wasEncrypted, err := decryptKeystoreJSON("passphrase123", data, &decoded)
	if err != nil {
		t.Fatalf("decryptKeystoreJSON: %v", err)
	}
	if !wasEncrypted || decoded.PrivateKey != "secret" {
		t.Fatalf("unexpected decode: %#v", decoded)
	}

	_, err = decryptKeystoreJSON("wrong", data, &decoded)
	if err == nil {
		t.Fatalf("expected error for wrong passphrase")
	}
}

func TestLoadOrCreateKeyPair(t *testing.T) {
	setTestConfigDir(t)
	kp1, err := loadOrCreateKeyPair("passphrase123")
	if err != nil {
		t.Fatalf("loadOrCreateKeyPair: %v", err)
	}
	kp2, err := loadOrCreateKeyPair("passphrase123")
	if err != nil {
		t.Fatalf("loadOrCreateKeyPair: %v", err)
	}
	if crypto.PublicKeyToBase64(kp1.Public) != crypto.PublicKeyToBase64(kp2.Public) {
		t.Fatalf("expected same key pair")
	}
}

func TestChannelKeysSaveLoad(t *testing.T) {
	setTestConfigDir(t)
	key := make([]byte, crypto.KeySize)
	keys := map[string][]byte{
		"ch-1": key,
		"":     key,
		"ch-2": make([]byte, 10),
	}
	if err := saveChannelKeys(keys, "passphrase123"); err != nil {
		t.Fatalf("saveChannelKeys: %v", err)
	}
	loaded, err := loadChannelKeys("passphrase123")
	if err != nil {
		t.Fatalf("loadChannelKeys: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("expected 1 key, got %d", len(loaded))
	}
}

func TestDirectoryKeySaveLoad(t *testing.T) {
	setTestConfigDir(t)
	key := make([]byte, crypto.KeySize)
	if err := saveDirectoryKey(key, "passphrase123"); err != nil {
		t.Fatalf("saveDirectoryKey: %v", err)
	}
	loaded, err := loadDirectoryKey("passphrase123")
	if err != nil {
		t.Fatalf("loadDirectoryKey: %v", err)
	}
	if len(loaded) != crypto.KeySize {
		t.Fatalf("unexpected key size: %d", len(loaded))
	}
}

func TestLoadChannelKeysInvalidPayload(t *testing.T) {
	configDir := setTestConfigDir(t)
	path := filepath.Join(configDir, "dialtone", "channel_keys.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	payload := storedChannelKeys{Keys: map[string]string{"ch": "not-base64"}}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	loaded, err := loadChannelKeys("")
	if err != nil {
		t.Fatalf("loadChannelKeys: %v", err)
	}
	if len(loaded) != 0 {
		t.Fatalf("expected empty keys, got %d", len(loaded))
	}
}
