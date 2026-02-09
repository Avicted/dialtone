package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Avicted/dialtone/internal/crypto"
)

type storedKey struct {
	PrivateKey string `json:"private_key"`
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
