package main

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type testPTTBackend struct{}

func (testPTTBackend) Run(context.Context, func(), func()) error {
	return nil
}

func TestNewPTTControllerAutoWaylandRequiresPortalByDefault(t *testing.T) {
	t.Setenv("WAYLAND_DISPLAY", "wayland-1")
	t.Setenv("XDG_SESSION_TYPE", "wayland")
	t.Setenv("DIALTONE_PTT_WAYLAND_HOTKEY_FALLBACK", "")

	portalCalled := false
	hotkeyCalled := false
	prevPortal := newPortalBackend
	prevHotkey := newHotkeyBackend
	newPortalBackend = func(string) (pttBackend, error) {
		portalCalled = true
		return nil, errors.New("portal unavailable")
	}
	newHotkeyBackend = func(string) (pttBackend, error) {
		hotkeyCalled = true
		return testPTTBackend{}, nil
	}
	t.Cleanup(func() {
		newPortalBackend = prevPortal
		newHotkeyBackend = prevHotkey
	})

	_, err := newPTTController("caps", pttBackendAuto)
	if err == nil {
		t.Fatalf("expected error when portal unavailable on wayland")
	}
	if !portalCalled {
		t.Fatalf("expected portal backend attempted")
	}
	if hotkeyCalled {
		t.Fatalf("did not expect hotkey fallback on wayland by default")
	}
	if !strings.Contains(err.Error(), "ptt portal backend unavailable on wayland") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewPTTControllerAutoWaylandAllowsFallbackWhenEnabled(t *testing.T) {
	t.Setenv("WAYLAND_DISPLAY", "wayland-1")
	t.Setenv("XDG_SESSION_TYPE", "wayland")
	t.Setenv("DIALTONE_PTT_WAYLAND_HOTKEY_FALLBACK", "1")

	portalCalled := false
	hotkeyCalled := false
	prevPortal := newPortalBackend
	prevHotkey := newHotkeyBackend
	newPortalBackend = func(string) (pttBackend, error) {
		portalCalled = true
		return nil, errors.New("portal unavailable")
	}
	newHotkeyBackend = func(string) (pttBackend, error) {
		hotkeyCalled = true
		return testPTTBackend{}, nil
	}
	t.Cleanup(func() {
		newPortalBackend = prevPortal
		newHotkeyBackend = prevHotkey
	})

	controller, err := newPTTController("caps", pttBackendAuto)
	if err != nil {
		t.Fatalf("expected hotkey fallback enabled, got error: %v", err)
	}
	if controller == nil || controller.backend == nil {
		t.Fatalf("expected controller backend configured")
	}
	if !portalCalled || !hotkeyCalled {
		t.Fatalf("expected portal attempt and hotkey fallback")
	}
}

func TestAllowWaylandHotkeyFallback(t *testing.T) {
	t.Setenv("DIALTONE_PTT_WAYLAND_HOTKEY_FALLBACK", "yes")
	if !allowWaylandHotkeyFallback() {
		t.Fatalf("expected yes to enable fallback")
	}
	t.Setenv("DIALTONE_PTT_WAYLAND_HOTKEY_FALLBACK", "")
	if allowWaylandHotkeyFallback() {
		t.Fatalf("expected empty value to disable fallback")
	}
}

func TestNewPTTControllerIncludesStartupInfo(t *testing.T) {
	prevHotkey := newHotkeyBackend
	newHotkeyBackend = func(string) (pttBackend, error) {
		return testPTTBackend{}, nil
	}
	t.Cleanup(func() {
		newHotkeyBackend = prevHotkey
	})

	controller, err := newPTTController("caps", pttBackendHotkey)
	if err != nil {
		t.Fatalf("expected hotkey controller created: %v", err)
	}
	if controller == nil {
		t.Fatalf("expected controller")
	}
	if !strings.Contains(controller.startupInfo, "selected=hotkey") {
		t.Fatalf("expected startup diagnostic to include selected backend, got %q", controller.startupInfo)
	}
}

func TestPTTStartupDiagnostic(t *testing.T) {
	msg := pttStartupDiagnostic(pttBackendAuto, true, "unavailable", "none", errors.New("portal unavailable"))
	if !strings.Contains(msg, "mode=auto") {
		t.Fatalf("expected mode field in diagnostic: %q", msg)
	}
	if !strings.Contains(msg, "wayland=true") {
		t.Fatalf("expected wayland field in diagnostic: %q", msg)
	}
	if !strings.Contains(msg, "portal=unavailable") {
		t.Fatalf("expected portal field in diagnostic: %q", msg)
	}
	if !strings.Contains(msg, "selected=none") {
		t.Fatalf("expected selected field in diagnostic: %q", msg)
	}
	if !strings.Contains(msg, "reason=portal unavailable") {
		t.Fatalf("expected reason field in diagnostic: %q", msg)
	}
}

func TestPTTControllerRun(t *testing.T) {
	var nilController *pttController
	if err := nilController.Run(context.Background(), func() {}, func() {}); err == nil {
		t.Fatalf("expected nil controller run to fail")
	}

	controller := &pttController{backend: testPTTBackend{}}
	if err := controller.Run(context.Background(), func() {}, func() {}); err != nil {
		t.Fatalf("expected backend run to succeed: %v", err)
	}
}
