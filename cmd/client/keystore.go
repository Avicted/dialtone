package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Avicted/dialtone/internal/crypto"
)

type storedKey struct {
	PrivateKey string `json:"private_key"`
}

type storedChannelKeys struct {
	Keys map[string]string `json:"keys"`
}

type storedDirectoryKey struct {
	Key string `json:"key"`
}

func loadOrCreateKeyPair() (*crypto.KeyPair, error) {
	path, err := deviceKeyPath()
	if err == nil {
		if kp, err := loadKeyPair(path); err == nil {
			return kp, nil
		}
	}

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate device key: %w", err)
	}

	if path != "" {
		_ = saveKeyPair(path, kp)
	}

	return kp, nil
}

func deviceKeyPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "dialtone", "device_key.json"), nil
}

func loadKeyPair(path string) (*crypto.KeyPair, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var stored storedKey
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil, err
	}
	if stored.PrivateKey == "" {
		return nil, fmt.Errorf("missing private key")
	}

	priv, err := crypto.PrivateKeyFromBase64(stored.PrivateKey)
	if err != nil {
		return nil, err
	}

	return &crypto.KeyPair{Private: priv, Public: priv.PublicKey()}, nil
}

func saveKeyPair(path string, kp *crypto.KeyPair) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}

	stored := storedKey{PrivateKey: crypto.PrivateKeyToBase64(kp.Private)}
	data, err := json.Marshal(stored)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0o600)
}

func channelKeysPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "dialtone", "channel_keys.json"), nil
}

func loadChannelKeys() (map[string][]byte, error) {
	path, err := channelKeysPath()
	if err != nil {
		return map[string][]byte{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string][]byte{}, nil
		}
		return map[string][]byte{}, err
	}

	var stored storedChannelKeys
	if err := json.Unmarshal(data, &stored); err != nil {
		return map[string][]byte{}, err
	}

	keys := make(map[string][]byte)
	for channelID, encoded := range stored.Keys {
		if strings.TrimSpace(channelID) == "" || strings.TrimSpace(encoded) == "" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(raw) != crypto.KeySize {
			continue
		}
		keys[channelID] = raw
	}
	return keys, nil
}

func saveChannelKeys(keys map[string][]byte) error {
	path, err := channelKeysPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}

	encoded := make(map[string]string)
	for channelID, key := range keys {
		if strings.TrimSpace(channelID) == "" || len(key) != crypto.KeySize {
			continue
		}
		encoded[channelID] = base64.StdEncoding.EncodeToString(key)
	}
	data, err := json.Marshal(storedChannelKeys{Keys: encoded})
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func directoryKeyPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "dialtone", "directory_key.json"), nil
}

func loadDirectoryKey() ([]byte, error) {
	path, err := directoryKeyPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var stored storedDirectoryKey
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil, err
	}
	if strings.TrimSpace(stored.Key) == "" {
		return nil, nil
	}
	key, err := base64.StdEncoding.DecodeString(stored.Key)
	if err != nil {
		return nil, err
	}
	if len(key) != crypto.KeySize {
		return nil, nil
	}
	return key, nil
}

func saveDirectoryKey(key []byte) error {
	path, err := directoryKeyPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if len(key) != crypto.KeySize {
		return fmt.Errorf("invalid directory key size")
	}
	stored := storedDirectoryKey{Key: base64.StdEncoding.EncodeToString(key)}
	data, err := json.Marshal(stored)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
