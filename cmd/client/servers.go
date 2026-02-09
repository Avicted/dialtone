package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

type serverHistory struct {
	Servers []string `json:"servers"`
}

func loadServerHistory() []string {
	path, err := serverHistoryPath()
	if err != nil {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var stored serverHistory
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil
	}
	return filterServers(stored.Servers)
}

func saveServerHistory(servers []string) error {
	path, err := serverHistoryPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	payload := serverHistory{Servers: filterServers(servers)}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func updateServerHistory(servers []string, server string, max int) []string {
	value := strings.TrimSpace(server)
	if value == "" {
		return filterServers(servers)
	}
	cleaned := make([]string, 0, len(servers)+1)
	cleaned = append(cleaned, value)
	for _, existing := range servers {
		if strings.EqualFold(existing, value) {
			continue
		}
		cleaned = append(cleaned, existing)
		if max > 0 && len(cleaned) >= max {
			break
		}
	}
	return filterServers(cleaned)
}

func serverHistoryPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "dialtone", "servers.json"), nil
}

func filterServers(servers []string) []string {
	filtered := make([]string, 0, len(servers))
	seen := make(map[string]struct{}, len(servers))
	for _, server := range servers {
		value := strings.TrimSpace(server)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		filtered = append(filtered, value)
	}
	return filtered
}
