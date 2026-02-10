package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Avicted/dialtone/internal/crypto"
	"golang.org/x/crypto/scrypt"
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

type encryptedBlob struct {
	Version int    `json:"version"`
	KDF     string `json:"kdf"`
	Salt    string `json:"salt"`
	N       int    `json:"n"`
	R       int    `json:"r"`
	P       int    `json:"p"`
	Cipher  string `json:"cipher"`
	Data    string `json:"data"`
}

const (
	keystoreVersion  = 1
	keystoreSaltSize = 16
	keystoreKDF      = "scrypt"
	keystoreCipher   = "aes-256-gcm"
	keystoreScryptN  = 32768
	keystoreScryptR  = 8
	keystoreScryptP  = 1
)

var (
	errKeystorePassphrase = errors.New("keystore passphrase required")
	errKeystoreDecrypt    = errors.New("keystore decryption failed")
	errKeystoreFormat     = errors.New("keystore format invalid")
)

func loadOrCreateKeyPair(passphrase string) (*crypto.KeyPair, error) {
	if passphrase == "" {
		return nil, errKeystorePassphrase
	}

	path, err := deviceKeyPath()
	if err == nil {
		if kp, err := loadKeyPair(path, passphrase); err == nil {
			return kp, nil
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate device key: %w", err)
	}

	if path != "" {
		_ = saveKeyPair(path, kp, passphrase)
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

func loadKeyPair(path, passphrase string) (*crypto.KeyPair, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var stored storedKey
	wasEncrypted, err := decryptKeystoreJSON(passphrase, data, &stored)
	if err != nil {
		return nil, err
	}
	if !wasEncrypted {
		if err := json.Unmarshal(data, &stored); err != nil {
			return nil, err
		}
	}
	if stored.PrivateKey == "" {
		return nil, fmt.Errorf("missing private key")
	}

	priv, err := crypto.PrivateKeyFromBase64(stored.PrivateKey)
	if err != nil {
		return nil, err
	}

	kp := &crypto.KeyPair{Private: priv, Public: priv.PublicKey()}
	if !wasEncrypted && passphrase != "" {
		_ = saveKeyPair(path, kp, passphrase)
	}
	return kp, nil
}

func saveKeyPair(path string, kp *crypto.KeyPair, passphrase string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}

	stored := storedKey{PrivateKey: crypto.PrivateKeyToBase64(kp.Private)}
	data, err := encryptKeystoreJSON(passphrase, stored)
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

func loadChannelKeys(passphrase string) (map[string][]byte, error) {
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
	wasEncrypted, err := decryptKeystoreJSON(passphrase, data, &stored)
	if err != nil {
		return map[string][]byte{}, err
	}
	if !wasEncrypted {
		if err := json.Unmarshal(data, &stored); err != nil {
			return map[string][]byte{}, err
		}
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
	if !wasEncrypted && passphrase != "" {
		_ = saveChannelKeys(keys, passphrase)
	}
	return keys, nil
}

func saveChannelKeys(keys map[string][]byte, passphrase string) error {
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
	data, err := encryptKeystoreJSON(passphrase, storedChannelKeys{Keys: encoded})
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

func loadDirectoryKey(passphrase string) ([]byte, error) {
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
	wasEncrypted, err := decryptKeystoreJSON(passphrase, data, &stored)
	if err != nil {
		return nil, err
	}
	if !wasEncrypted {
		if err := json.Unmarshal(data, &stored); err != nil {
			return nil, err
		}
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
	if !wasEncrypted && passphrase != "" {
		_ = saveDirectoryKey(key, passphrase)
	}
	return key, nil
}

func saveDirectoryKey(key []byte, passphrase string) error {
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
	data, err := encryptKeystoreJSON(passphrase, stored)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func encryptKeystoreJSON(passphrase string, value any) ([]byte, error) {
	if passphrase == "" {
		return nil, errKeystorePassphrase
	}

	plaintext, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}

	salt := make([]byte, keystoreSaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("keystore salt: %w", err)
	}

	key, err := scrypt.Key([]byte(passphrase), salt, keystoreScryptN, keystoreScryptR, keystoreScryptP, crypto.KeySize)
	if err != nil {
		return nil, fmt.Errorf("keystore kdf: %w", err)
	}

	ct, err := crypto.Encrypt(key, plaintext)
	if err != nil {
		return nil, fmt.Errorf("keystore encrypt: %w", err)
	}

	payload := encryptedBlob{
		Version: keystoreVersion,
		KDF:     keystoreKDF,
		Salt:    base64.StdEncoding.EncodeToString(salt),
		N:       keystoreScryptN,
		R:       keystoreScryptR,
		P:       keystoreScryptP,
		Cipher:  keystoreCipher,
		Data:    base64.StdEncoding.EncodeToString(ct),
	}
	return json.Marshal(payload)
}

func decryptKeystoreJSON(passphrase string, data []byte, out any) (bool, error) {
	var payload encryptedBlob
	if err := json.Unmarshal(data, &payload); err != nil {
		return false, err
	}
	if payload.Version != keystoreVersion || payload.Data == "" {
		return false, nil
	}
	if payload.KDF != keystoreKDF || payload.Cipher != keystoreCipher {
		return false, errKeystoreFormat
	}
	if passphrase == "" {
		return false, errKeystorePassphrase
	}

	salt, err := base64.StdEncoding.DecodeString(payload.Salt)
	if err != nil || len(salt) == 0 {
		return false, errKeystoreFormat
	}
	if payload.N <= 0 || payload.R <= 0 || payload.P <= 0 {
		return false, errKeystoreFormat
	}

	key, err := scrypt.Key([]byte(passphrase), salt, payload.N, payload.R, payload.P, crypto.KeySize)
	if err != nil {
		return false, fmt.Errorf("keystore kdf: %w", err)
	}

	ct, err := base64.StdEncoding.DecodeString(payload.Data)
	if err != nil {
		return false, errKeystoreFormat
	}
	plaintext, err := crypto.Decrypt(key, ct)
	if err != nil {
		return false, errKeystoreDecrypt
	}

	if err := json.Unmarshal(plaintext, out); err != nil {
		return false, err
	}
	return true, nil
}
