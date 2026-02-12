//go:build linux

package main

import "testing"

func TestPortalSessionHandleTokenStable(t *testing.T) {
	if portalSessionHandleToken != "dialtone_session" {
		t.Fatalf("unexpected portal session token: %q", portalSessionHandleToken)
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
