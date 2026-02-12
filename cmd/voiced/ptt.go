package main

import (
	"context"
	"fmt"
	"log"
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
	backend pttBackend
}

func newPTTController(binding, mode string) (*pttController, error) {
	resolvedMode, err := normalizePTTBackendMode(mode)
	if err != nil {
		return nil, err
	}

	switch resolvedMode {
	case pttBackendPortal:
		backend, portalErr := newPortalPTTBackend(binding)
		if portalErr != nil {
			return nil, fmt.Errorf("ptt portal backend unavailable: %w", portalErr)
		}
		log.Printf("ptt backend: xdg portal global shortcuts")
		return &pttController{backend: backend}, nil
	case pttBackendHotkey:
		hotkeyBackend, hotkeyErr := newHotkeyPTTBackend(binding)
		if hotkeyErr != nil {
			return nil, hotkeyErr
		}
		log.Printf("ptt backend: direct hotkey")
		return &pttController{backend: hotkeyBackend}, nil
	default:
		if runtime.GOOS == "linux" {
			backend, portalErr := newPortalPTTBackend(binding)
			if portalErr == nil {
				log.Printf("ptt backend: xdg portal global shortcuts")
				return &pttController{backend: backend}, nil
			}
			log.Printf("ptt portal unavailable, falling back to direct hotkey: %v", portalErr)
		}

		hotkeyBackend, hotkeyErr := newHotkeyPTTBackend(binding)
		if hotkeyErr != nil {
			return nil, hotkeyErr
		}
		log.Printf("ptt backend: direct hotkey")
		return &pttController{backend: hotkeyBackend}, nil
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
