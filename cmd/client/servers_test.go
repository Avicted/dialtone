package main

import (
	"testing"
)

func TestUpdateServerHistory(t *testing.T) {
	servers := []string{"http://one", "HTTP://two", "http://one"}
	updated := updateServerHistory(servers, "http://two", 2)
	if len(updated) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(updated))
	}
	if updated[0] != "http://two" {
		t.Fatalf("expected newest server first, got %q", updated[0])
	}
}

func TestFilterServers(t *testing.T) {
	servers := []string{"http://one", "", "HTTP://one", " http://two "}
	filtered := filterServers(servers)
	if len(filtered) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(filtered))
	}
	if filtered[0] != "http://one" || filtered[1] != "http://two" {
		t.Fatalf("unexpected filtered servers: %#v", filtered)
	}
}

func TestSaveLoadServerHistory(t *testing.T) {
	setTestConfigDir(t)
	servers := []string{"http://one", "http://two"}
	if err := saveServerHistory(servers); err != nil {
		t.Fatalf("saveServerHistory: %v", err)
	}
	loaded := loadServerHistory()
	if len(loaded) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(loaded))
	}
}
