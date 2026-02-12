package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
)

type pttBackend interface {
	Run(ctx context.Context, onDown, onUp func()) error
}

const (
	pttBackendAuto   = "auto"
	pttBackendPortal = "portal"
	pttBackendHotkey = "hotkey"
)

type pttController struct {
	backend     pttBackend
	startupInfo string
}

var (
	newPortalBackend = newPortalPTTBackend
	newHotkeyBackend = newHotkeyPTTBackend
)

func newPTTController(binding, mode string) (*pttController, error) {
	resolvedMode, err := normalizePTTBackendMode(mode)
	if err != nil {
		return nil, err
	}
	wayland := isWaylandSession()

	switch resolvedMode {
	case pttBackendPortal:
		backend, portalErr := newPortalBackend(binding)
		if portalErr != nil {
			log.Printf("%s", pttStartupDiagnostic(resolvedMode, wayland, "unavailable", "none", portalErr))
			return nil, fmt.Errorf("ptt portal backend unavailable: %w", portalErr)
		}
		diagnostic := pttStartupDiagnostic(resolvedMode, wayland, "available", pttBackendPortal, nil)
		log.Printf("%s", diagnostic)
		return &pttController{backend: backend, startupInfo: diagnostic}, nil
	case pttBackendHotkey:
		hotkeyBackend, hotkeyErr := newHotkeyBackend(binding)
		if hotkeyErr != nil {
			log.Printf("%s", pttStartupDiagnostic(resolvedMode, wayland, "skipped", "none", hotkeyErr))
			return nil, hotkeyErr
		}
		diagnostic := pttStartupDiagnostic(resolvedMode, wayland, "skipped", pttBackendHotkey, nil)
		log.Printf("%s", diagnostic)
		return &pttController{backend: hotkeyBackend, startupInfo: diagnostic}, nil
	default:
		if runtime.GOOS == "linux" {
			backend, portalErr := newPortalBackend(binding)
			if portalErr == nil {
				diagnostic := pttStartupDiagnostic(resolvedMode, wayland, "available", pttBackendPortal, nil)
				log.Printf("%s", diagnostic)
				return &pttController{backend: backend, startupInfo: diagnostic}, nil
			}
			if isWaylandSession() && !allowWaylandHotkeyFallback() {
				log.Printf("%s", pttStartupDiagnostic(resolvedMode, wayland, "unavailable", "none", portalErr))
				return nil, fmt.Errorf("ptt portal backend unavailable on wayland: %w", portalErr)
			}
			log.Printf("%s", pttStartupDiagnostic(resolvedMode, wayland, "unavailable", pttBackendHotkey, portalErr))
		}

		hotkeyBackend, hotkeyErr := newHotkeyBackend(binding)
		if hotkeyErr != nil {
			portalStatus := "unsupported"
			if runtime.GOOS == "linux" {
				portalStatus = "unavailable"
			}
			log.Printf("%s", pttStartupDiagnostic(resolvedMode, wayland, portalStatus, "none", hotkeyErr))
			return nil, hotkeyErr
		}
		portalStatus := "unsupported"
		if runtime.GOOS == "linux" {
			portalStatus = "unavailable"
		}
		diagnostic := pttStartupDiagnostic(resolvedMode, wayland, portalStatus, pttBackendHotkey, nil)
		log.Printf("%s", diagnostic)
		return &pttController{backend: hotkeyBackend, startupInfo: diagnostic}, nil
	}
}

func pttStartupDiagnostic(mode string, wayland bool, portalStatus, selected string, reason error) string {
	message := fmt.Sprintf("ptt startup mode=%s wayland=%t portal=%s selected=%s", mode, wayland, portalStatus, selected)
	if reason != nil {
		message += fmt.Sprintf(" reason=%v", reason)
	}
	return message
}

func isWaylandSession() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	if strings.TrimSpace(os.Getenv("WAYLAND_DISPLAY")) != "" {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(os.Getenv("XDG_SESSION_TYPE")), "wayland")
}

func allowWaylandHotkeyFallback() bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv("DIALTONE_PTT_WAYLAND_HOTKEY_FALLBACK")))
	switch value {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func normalizePTTBackendMode(mode string) (string, error) {
	mode = strings.TrimSpace(strings.ToLower(mode))
	if mode == "" {
		mode = pttBackendAuto
	}
	switch mode {
	case pttBackendAuto, pttBackendPortal, pttBackendHotkey:
		return mode, nil
	default:
		return "", fmt.Errorf("invalid ptt-backend %q (expected: auto, portal, hotkey)", mode)
	}
}

func (p *pttController) Run(ctx context.Context, onDown, onUp func()) error {
	if p == nil || p.backend == nil {
		return fmt.Errorf("ptt backend is not configured")
	}
	return p.backend.Run(ctx, onDown, onUp)
}
