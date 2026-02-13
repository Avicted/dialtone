//go:build linux

package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

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

func TestPortalSessionPath(t *testing.T) {
	validPath := dbus.ObjectPath("/org/freedesktop/portal/desktop/session/1")

	t.Run("object path variant", func(t *testing.T) {
		got, err := portalSessionPath(dbus.MakeVariant(validPath))
		if err != nil {
			t.Fatalf("portalSessionPath(object path) error: %v", err)
		}
		if got != validPath {
			t.Fatalf("unexpected path: %q", got)
		}
	})

	t.Run("string variant", func(t *testing.T) {
		got, err := portalSessionPath(dbus.MakeVariant(string(validPath)))
		if err != nil {
			t.Fatalf("portalSessionPath(string) error: %v", err)
		}
		if got != validPath {
			t.Fatalf("unexpected path: %q", got)
		}
	})

	t.Run("invalid string", func(t *testing.T) {
		_, err := portalSessionPath(dbus.MakeVariant("not/a/valid/path"))
		if err == nil {
			t.Fatal("expected invalid path error")
		}
	})

	t.Run("unexpected type", func(t *testing.T) {
		_, err := portalSessionPath(dbus.MakeVariant(123))
		if err == nil {
			t.Fatal("expected unexpected type error")
		}
	})
}

func TestPortalToken(t *testing.T) {
	t1 := portalToken("request")
	time.Sleep(time.Microsecond)
	t2 := portalToken("request")

	if !strings.HasPrefix(t1, "dialtone_request_") {
		t.Fatalf("unexpected token prefix: %q", t1)
	}
	if !strings.HasPrefix(t2, "dialtone_request_") {
		t.Fatalf("unexpected token prefix: %q", t2)
	}
	if t1 == t2 {
		t.Fatalf("expected unique tokens, got %q and %q", t1, t2)
	}
}

func TestClosePortalSessionNilSafe(t *testing.T) {
	if err := closePortalSession(nil, ""); err != nil {
		t.Fatalf("closePortalSession(nil, empty) error: %v", err)
	}
	if err := closePortalSession(nil, dbus.ObjectPath("/org/freedesktop/portal/desktop/session/1")); err != nil {
		t.Fatalf("closePortalSession(nil, path) error: %v", err)
	}
}

func TestPortalBackendGuards(t *testing.T) {
	ctx := context.Background()
	validPath := dbus.ObjectPath("/org/freedesktop/portal/desktop/request/1")

	t.Run("newPortalPTTBackend requires binding", func(t *testing.T) {
		backend, err := newPortalPTTBackend("   ")
		if err == nil {
			t.Fatalf("expected binding validation error, got backend=%v", backend)
		}
	})

	t.Run("Run requires initialized conn", func(t *testing.T) {
		p := &portalPTTBackend{}
		err := p.Run(ctx, nil, nil)
		if err == nil {
			t.Fatal("expected Run() init error")
		}
	})

	t.Run("createPortalSession nil conn", func(t *testing.T) {
		_, err := createPortalSession(ctx, nil)
		if err == nil {
			t.Fatal("expected createPortalSession nil-conn error")
		}
	})

	t.Run("bindPortalShortcut guards", func(t *testing.T) {
		err := bindPortalShortcut(ctx, nil, validPath, "ctrl+v")
		if err == nil {
			t.Fatal("expected bindPortalShortcut nil-conn error")
		}

		err = bindPortalShortcut(ctx, nil, dbus.ObjectPath(""), "ctrl+v")
		if err == nil {
			t.Fatal("expected bindPortalShortcut invalid-path error")
		}
	})

	t.Run("bindPortalShortcutWithTrigger guards", func(t *testing.T) {
		err := bindPortalShortcutWithTrigger(ctx, nil, validPath, "<Ctrl>v")
		if err == nil {
			t.Fatal("expected bindPortalShortcutWithTrigger nil-conn error")
		}

		err = bindPortalShortcutWithTrigger(ctx, nil, dbus.ObjectPath(""), "<Ctrl>v")
		if err == nil {
			t.Fatal("expected bindPortalShortcutWithTrigger invalid-path error")
		}
	})

	t.Run("waitPortalResponse guards", func(t *testing.T) {
		_, _, err := waitPortalResponse(ctx, nil, validPath)
		if err == nil {
			t.Fatal("expected waitPortalResponse nil-conn error")
		}

		_, _, err = waitPortalResponse(ctx, nil, dbus.ObjectPath(""))
		if err == nil {
			t.Fatal("expected waitPortalResponse invalid-path error")
		}
	})
}
