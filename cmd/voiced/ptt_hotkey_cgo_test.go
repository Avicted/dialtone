package main

import (
	"context"
	"testing"
	"time"
)

func TestParseHotkeyVariants(t *testing.T) {
	tests := []struct {
		name    string
		binding string
		wantErr bool
	}{
		{name: "ctrl+v", binding: "ctrl+v"},
		{name: "control+v", binding: "control+v"},
		{name: "shift+space", binding: "shift+space"},
		{name: "caps", binding: "caps"},
		{name: "capslock alias", binding: "capslock"},
		{name: "caps_lock alias", binding: "caps_lock"},
		{name: "trim and case normalize", binding: "  ConTRol + Shift + V  "},
		{name: "missing key", binding: "ctrl", wantErr: true},
		{name: "modifiers only", binding: "ctrl+shift", wantErr: true},
		{name: "empty segment", binding: "ctrl++v", wantErr: true},
		{name: "unsupported key", binding: "alt+v", wantErr: true},
		{name: "empty", binding: "", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mods, key, err := parseHotkey(tc.binding)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseHotkey(%q) expected error", tc.binding)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseHotkey(%q) error: %v", tc.binding, err)
			}
			if key == 0 {
				t.Fatalf("parseHotkey(%q) returned empty key", tc.binding)
			}
			if tc.binding == "ctrl+v" && len(mods) == 0 {
				t.Fatalf("expected ctrl modifier for %q", tc.binding)
			}
		})
	}
}

func TestParseHotkeyModifierCounts(t *testing.T) {
	mods, key, err := parseHotkey("control+shift+space")
	if err != nil {
		t.Fatalf("parseHotkey(control+shift+space) error: %v", err)
	}
	if key == 0 {
		t.Fatalf("expected non-zero key")
	}
	if len(mods) != 2 {
		t.Fatalf("expected two modifiers, got %d", len(mods))
	}

	mods, key, err = parseHotkey("capslock")
	if err != nil {
		t.Fatalf("parseHotkey(capslock) error: %v", err)
	}
	if key == 0 {
		t.Fatalf("expected non-zero key for capslock")
	}
	if len(mods) != 0 {
		t.Fatalf("expected no modifiers for capslock, got %d", len(mods))
	}
}

func TestHotkeyCodeHelpers(t *testing.T) {
	if got := hotkeyModifierFromCode(123); uint32(got) != 123 {
		t.Fatalf("hotkeyModifierFromCode mismatch: got %d", got)
	}
	if got := hotkeyKeyFromCode(456); uint32(got) != 456 {
		t.Fatalf("hotkeyKeyFromCode mismatch: got %d", got)
	}

	if _, err := hotkeyModifierCtrl(); err != nil {
		t.Fatalf("hotkeyModifierCtrl error: %v", err)
	}
	if _, err := hotkeyModifierShift(); err != nil {
		t.Fatalf("hotkeyModifierShift error: %v", err)
	}
	if _, err := hotkeySpaceKey(); err != nil {
		t.Fatalf("hotkeySpaceKey error: %v", err)
	}
	if _, err := hotkeyVKey(); err != nil {
		t.Fatalf("hotkeyVKey error: %v", err)
	}
	if _, err := capsLockHotkeyKey(); err != nil {
		t.Fatalf("capsLockHotkeyKey error: %v", err)
	}
}

func TestNewHotkeyPTTBackendAndRunCanceled(t *testing.T) {
	b, err := newHotkeyPTTBackend("ctrl+v")
	if err != nil {
		t.Fatalf("newHotkeyPTTBackend error: %v", err)
	}

	hkBackend, ok := b.(*hotkeyPTTBackend)
	if !ok || hkBackend.hk == nil {
		t.Fatalf("unexpected backend type/value: %#v", b)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan error, 1)
	go func() {
		done <- hkBackend.Run(ctx, nil, nil)
	}()

	select {
	case <-time.After(3 * time.Second):
		t.Fatal("hotkey backend Run did not return promptly")
	case <-done:
	}
}

func TestNewHotkeyPTTBackendValidationError(t *testing.T) {
	backend, err := newHotkeyPTTBackend("alt+v")
	if err == nil {
		t.Fatalf("expected backend validation to fail")
	}
	if backend != nil {
		t.Fatalf("expected nil backend on validation failure, got %#v", backend)
	}
}
