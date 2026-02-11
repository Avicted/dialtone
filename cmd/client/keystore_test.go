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

func TestKeystoreEncryptedStoredInConfigDir(t *testing.T) {
	configDir := setTestConfigDir(t)
	passphrase := "passphrase123"

	kp, err := loadOrCreateKeyPair(passphrase)
	if err != nil {
		t.Fatalf("loadOrCreateKeyPair: %v", err)
	}

	path, err := deviceKeyPath()
	if err != nil {
		t.Fatalf("deviceKeyPath: %v", err)
	}
	expectedPath := filepath.Join(configDir, "dialtone", "device_key.json")
	if path != expectedPath {
		t.Fatalf("unexpected path: %q", path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read keystore: %v", err)
	}
	var stored storedKey
	wasEncrypted, err := decryptKeystoreJSON(passphrase, data, &stored)
	if err != nil {
		t.Fatalf("decryptKeystoreJSON: %v", err)
	}
	if !wasEncrypted {
		t.Fatalf("expected encrypted keystore")
	}
	if stored.PrivateKey != crypto.PrivateKeyToBase64(kp.Private) {
		t.Fatalf("unexpected private key payload")
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

func TestLoadOrCreateKeyPairMissingPassphrase(t *testing.T) {
	if _, err := loadOrCreateKeyPair(""); err == nil {
		t.Fatalf("expected passphrase error")
	}
}

func TestSaveDirectoryKeyInvalidSize(t *testing.T) {
	setTestConfigDir(t)
	if err := saveDirectoryKey([]byte{1, 2, 3}, "passphrase123"); err == nil {
		t.Fatalf("expected invalid size error")
	}
}

func TestDecryptKeystoreJSONFormatErrors(t *testing.T) {
	payload := encryptedBlob{Version: keystoreVersion, KDF: "bad", Cipher: keystoreCipher, Data: "ZGF0YQ=="}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out storedKey
	if _, err := decryptKeystoreJSON("passphrase123", data, &out); err == nil {
		t.Fatalf("expected format error")
	}

	payload = encryptedBlob{Version: keystoreVersion, KDF: keystoreKDF, Cipher: keystoreCipher, Data: "ZGF0YQ=="}
	data, err = json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := decryptKeystoreJSON("", data, &out); err == nil {
		t.Fatalf("expected passphrase error")
	}
}

func TestLoadKeyPairMissingPrivateKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "device.json")
	data, err := json.Marshal(storedKey{PrivateKey: ""})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := loadKeyPair(path, "passphrase123"); err == nil {
		t.Fatalf("expected missing private key error")
	}
}

func TestDecryptKeystoreJSONSaltErrors(t *testing.T) {
	payload := encryptedBlob{Version: keystoreVersion, KDF: keystoreKDF, Cipher: keystoreCipher, Salt: "@@@", Data: "ZGF0YQ=="}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out storedKey
	if _, err := decryptKeystoreJSON("passphrase123", data, &out); err == nil {
		t.Fatalf("expected format error")
	}
}

func TestEncryptKeystoreJSONRoundTrip(t *testing.T) {
	value := storedKey{PrivateKey: crypto.PrivateKeyToBase64(newTestKeyPair(t).Private)}
	data, err := encryptKeystoreJSON("passphrase123", value)
	if err != nil {
		t.Fatalf("encryptKeystoreJSON: %v", err)
	}
	var decoded storedKey
	if _, err := decryptKeystoreJSON("passphrase123", data, &decoded); err != nil {
		t.Fatalf("decryptKeystoreJSON: %v", err)
	}
}

func TestDecryptKeystoreJSONVersionMismatch(t *testing.T) {
	payload := encryptedBlob{Version: 0, Data: "ZGF0YQ=="}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out storedKey
	wasEncrypted, err := decryptKeystoreJSON("passphrase123", data, &out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if wasEncrypted {
		t.Fatalf("expected not encrypted")
	}
}

func TestLoadDirectoryKeyInvalidPayload(t *testing.T) {
	configDir := setTestConfigDir(t)
	path := filepath.Join(configDir, "dialtone", "directory_key.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	payload := storedDirectoryKey{Key: "not-base64"}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	key, err := loadDirectoryKey("passphrase123")
	if err == nil {
		t.Fatalf("expected decode error")
	}
	if key != nil {
		t.Fatalf("expected nil key")
	}
}
