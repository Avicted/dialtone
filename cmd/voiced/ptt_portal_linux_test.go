//go:build linux

package main

import "testing"

func TestPortalSessionHandleTokenStable(t *testing.T) {
	if portalSessionHandleToken != "dialtone_session" {
		t.Fatalf("unexpected portal session token: %q", portalSessionHandleToken)
	}
}

func TestPortalParentWindow(t *testing.T) {
	t.Setenv("DIALTONE_PORTAL_PARENT_WINDOW", "")
	t.Setenv("WINDOWID", "")
	t.Setenv("ALACRITTY_WINDOW_ID", "")
	if got := portalParentWindow(); got != "" {
		t.Fatalf("expected empty parent window, got %q", got)
	}

	t.Setenv("DIALTONE_PORTAL_PARENT_WINDOW", "x11:0xabc")
	t.Setenv("WINDOWID", "123")
	if got := portalParentWindow(); got != "x11:0xabc" {
		t.Fatalf("expected explicit parent window override, got %q", got)
	}

	t.Setenv("DIALTONE_PORTAL_PARENT_WINDOW", "")
	t.Setenv("WINDOWID", "123")
	t.Setenv("ALACRITTY_WINDOW_ID", "")
	if got := portalParentWindow(); got != "x11:0x7b" {
		t.Fatalf("expected decimal WINDOWID converted to x11 handle, got %q", got)
	}

	t.Setenv("WINDOWID", "")
	t.Setenv("ALACRITTY_WINDOW_ID", "0x2A")
	if got := portalParentWindow(); got != "x11:0x2a" {
		t.Fatalf("expected ALACRITTY_WINDOW_ID converted to x11 handle, got %q", got)
	}
}

func TestNormalizeWindowIdentifier(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "empty", input: "", want: ""},
		{name: "already prefixed", input: "wayland:abc", want: "wayland:abc"},
		{name: "hex", input: "0xFF", want: "x11:0xff"},
		{name: "decimal", input: "42", want: "x11:0x2a"},
		{name: "invalid", input: "not-a-window", want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeWindowIdentifier(tc.input); got != tc.want {
				t.Fatalf("normalizeWindowIdentifier(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestPortalPreferredTrigger(t *testing.T) {
	tests := []struct {
		name    string
		binding string
		want    string
	}{
		{name: "ctrl+v", binding: "ctrl+v", want: "<Ctrl>v"},
		{name: "shift+space", binding: "shift+space", want: "<Shift>space"},
		{name: "caps unsupported", binding: "caps", want: ""},
		{name: "ctrl+caps unsupported", binding: "ctrl+caps", want: ""},
		{name: "invalid key", binding: "alt+v", want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := portalPreferredTrigger(tc.binding); got != tc.want {
				t.Fatalf("portalPreferredTrigger(%q) = %q, want %q", tc.binding, got, tc.want)
			}
		})
	}
}
