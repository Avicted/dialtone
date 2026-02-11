package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Avicted/dialtone/internal/crypto"
)

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
