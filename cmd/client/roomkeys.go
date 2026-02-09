package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
)

type storedRoomKeys struct {
	Rooms map[string]string `json:"rooms"`
}

func roomKeysPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "dialtone", "room_keys.json"), nil
}

func loadRoomKeys() map[string][]byte {
	path, err := roomKeysPath()
	if err != nil {
		return map[string][]byte{}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return map[string][]byte{}
	}
	var stored storedRoomKeys
	if err := json.Unmarshal(data, &stored); err != nil {
		return map[string][]byte{}
	}
	keys := make(map[string][]byte, len(stored.Rooms))
	for roomID, encoded := range stored.Rooms {
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			continue
		}
		keys[roomID] = raw
	}
	return keys
}

func saveRoomKeys(keys map[string][]byte) error {
	path, err := roomKeysPath()
	if err != nil {
		return err
	}
	stored := storedRoomKeys{Rooms: make(map[string]string, len(keys))}
	for roomID, key := range keys {
		if len(key) == 0 {
			continue
		}
		stored.Rooms[roomID] = base64.StdEncoding.EncodeToString(key)
	}
	data, err := json.Marshal(stored)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
