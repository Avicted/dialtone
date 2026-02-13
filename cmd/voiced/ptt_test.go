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

func TestNewPTTControllerPortalMode(t *testing.T) {
	portalErr := errors.New("portal unavailable")

	t.Run("success", func(t *testing.T) {
		portalCalled := false
		hotkeyCalled := false
		prevPortal := newPortalBackend
		prevHotkey := newHotkeyBackend
		newPortalBackend = func(binding string) (pttBackend, error) {
			portalCalled = true
			if binding != "caps" {
				t.Fatalf("expected binding caps, got %q", binding)
			}
			return testPTTBackend{}, nil
		}
		newHotkeyBackend = func(string) (pttBackend, error) {
			hotkeyCalled = true
			return testPTTBackend{}, nil
		}
		t.Cleanup(func() {
			newPortalBackend = prevPortal
			newHotkeyBackend = prevHotkey
		})

		controller, err := newPTTController("caps", pttBackendPortal)
		if err != nil {
			t.Fatalf("newPTTController portal mode success error: %v", err)
		}
		if controller == nil || controller.backend == nil {
			t.Fatalf("expected configured controller")
		}
		if !portalCalled || hotkeyCalled {
			t.Fatalf("expected only portal backend to be used")
		}
		if !strings.Contains(controller.startupInfo, "selected=portal") {
			t.Fatalf("expected portal startup diagnostic, got %q", controller.startupInfo)
		}
	})

	t.Run("failure wraps", func(t *testing.T) {
		prevPortal := newPortalBackend
		newPortalBackend = func(string) (pttBackend, error) {
			return nil, portalErr
		}
		t.Cleanup(func() {
			newPortalBackend = prevPortal
		})

		controller, err := newPTTController("caps", pttBackendPortal)
		if err == nil {
			t.Fatalf("expected portal mode failure")
		}
		if controller != nil {
			t.Fatalf("expected nil controller on portal mode failure")
		}
		if !errors.Is(err, portalErr) {
			t.Fatalf("expected wrapped portal error, got %v", err)
		}
		if !strings.Contains(err.Error(), "ptt portal backend unavailable") {
			t.Fatalf("unexpected portal failure error: %v", err)
		}
	})
}

func TestNewPTTControllerHotkeyModeFailure(t *testing.T) {
	hotkeyErr := errors.New("hotkey unavailable")
	portalCalled := false
	prevPortal := newPortalBackend
	prevHotkey := newHotkeyBackend
	newPortalBackend = func(string) (pttBackend, error) {
		portalCalled = true
		return testPTTBackend{}, nil
	}
	newHotkeyBackend = func(string) (pttBackend, error) {
		return nil, hotkeyErr
	}
	t.Cleanup(func() {
		newPortalBackend = prevPortal
		newHotkeyBackend = prevHotkey
	})

	controller, err := newPTTController("caps", pttBackendHotkey)
	if err == nil {
		t.Fatalf("expected hotkey mode failure")
	}
	if controller != nil {
		t.Fatalf("expected nil controller on hotkey mode failure")
	}
	if !errors.Is(err, hotkeyErr) {
		t.Fatalf("expected wrapped hotkey error, got %v", err)
	}
	if portalCalled {
		t.Fatalf("did not expect portal backend call in hotkey mode")
	}
}

func TestNewPTTControllerAutoLinuxPortalAndFallbackFailures(t *testing.T) {
	t.Setenv("WAYLAND_DISPLAY", "")
	t.Setenv("XDG_SESSION_TYPE", "x11")
	t.Setenv("DIALTONE_PTT_WAYLAND_HOTKEY_FALLBACK", "")

	t.Run("portal success preferred", func(t *testing.T) {
		portalCalled := false
		hotkeyCalled := false
		prevPortal := newPortalBackend
		prevHotkey := newHotkeyBackend
		newPortalBackend = func(string) (pttBackend, error) {
			portalCalled = true
			return testPTTBackend{}, nil
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
			t.Fatalf("auto mode portal success error: %v", err)
		}
		if controller == nil || controller.backend == nil {
			t.Fatalf("expected configured controller")
		}
		if !portalCalled || hotkeyCalled {
			t.Fatalf("expected portal preferred without hotkey fallback")
		}
		if !strings.Contains(controller.startupInfo, "selected=portal") {
			t.Fatalf("expected portal startup diagnostic, got %q", controller.startupInfo)
		}
	})

	t.Run("both backends fail", func(t *testing.T) {
		portalErr := errors.New("portal unavailable")
		hotkeyErr := errors.New("hotkey unavailable")
		portalCalled := false
		hotkeyCalled := false
		prevPortal := newPortalBackend
		prevHotkey := newHotkeyBackend
		newPortalBackend = func(string) (pttBackend, error) {
			portalCalled = true
			return nil, portalErr
		}
		newHotkeyBackend = func(string) (pttBackend, error) {
			hotkeyCalled = true
			return nil, hotkeyErr
		}
		t.Cleanup(func() {
			newPortalBackend = prevPortal
			newHotkeyBackend = prevHotkey
		})

		controller, err := newPTTController("caps", pttBackendAuto)
		if err == nil {
			t.Fatalf("expected auto mode failure when both backends fail")
		}
		if controller != nil {
			t.Fatalf("expected nil controller when both backends fail")
		}
		if !errors.Is(err, hotkeyErr) {
			t.Fatalf("expected hotkey failure to be returned, got %v", err)
		}
		if !portalCalled || !hotkeyCalled {
			t.Fatalf("expected both portal and hotkey backends attempted")
		}
	})
}

func TestNormalizePTTBackendMode(t *testing.T) {
	mode, err := normalizePTTBackendMode("")
	if err != nil || mode != pttBackendAuto {
		t.Fatalf("normalize empty mode = %q, err=%v; want %q", mode, err, pttBackendAuto)
	}

	mode, err = normalizePTTBackendMode("  HOTKEY  ")
	if err != nil || mode != pttBackendHotkey {
		t.Fatalf("normalize HOTKEY mode = %q, err=%v; want %q", mode, err, pttBackendHotkey)
	}

	if _, err = normalizePTTBackendMode("invalid"); err == nil {
		t.Fatalf("expected invalid backend mode to fail")
	}
}

func TestIsWaylandSessionLinuxEnvCombos(t *testing.T) {
	t.Setenv("WAYLAND_DISPLAY", "")
	t.Setenv("XDG_SESSION_TYPE", "x11")
	if isWaylandSession() {
		t.Fatalf("expected non-wayland session when env indicates x11")
	}

	t.Setenv("XDG_SESSION_TYPE", "wayland")
	if !isWaylandSession() {
		t.Fatalf("expected wayland session from XDG_SESSION_TYPE")
	}

	t.Setenv("WAYLAND_DISPLAY", "wayland-1")
	t.Setenv("XDG_SESSION_TYPE", "")
	if !isWaylandSession() {
		t.Fatalf("expected wayland session from WAYLAND_DISPLAY")
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
