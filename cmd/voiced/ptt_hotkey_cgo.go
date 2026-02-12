package main

import (
	"context"
	"fmt"
	"runtime"
	"strings"

	"golang.design/x/hotkey"
)

type hotkeyPTTBackend struct {
	hk *hotkey.Hotkey
}

func newHotkeyPTTBackend(binding string) (pttBackend, error) {
	mods, key, err := parseHotkey(binding)
	if err != nil {
		return nil, err
	}
	return &hotkeyPTTBackend{hk: hotkey.New(mods, key)}, nil
}

func (p *hotkeyPTTBackend) Run(ctx context.Context, onDown, onUp func()) error {
	if err := p.hk.Register(); err != nil {
		return err
	}
	defer p.hk.Unregister()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-p.hk.Keydown():
			if onDown != nil {
				onDown()
			}
		case <-p.hk.Keyup():
			if onUp != nil {
				onUp()
			}
		}
	}
}

func parseHotkey(binding string) ([]hotkey.Modifier, hotkey.Key, error) {
	binding = strings.TrimSpace(strings.ToLower(binding))
	if binding == "" {
		return nil, 0, fmt.Errorf("hotkey binding is required")
	}

	parts := strings.Split(binding, "+")
	mods := make([]hotkey.Modifier, 0, len(parts))
	var key hotkey.Key
	hasKey := false

	for _, part := range parts {
		part = strings.TrimSpace(part)
		switch part {
		case "ctrl", "control":
			mod, err := hotkeyModifierCtrl()
			if err != nil {
				return nil, 0, err
			}
			mods = append(mods, mod)
		case "shift":
			mod, err := hotkeyModifierShift()
			if err != nil {
				return nil, 0, err
			}
			mods = append(mods, mod)
		case "space":
			spaceKey, err := hotkeySpaceKey()
			if err != nil {
				return nil, 0, err
			}
			key = spaceKey
			hasKey = true
		case "v":
			vKey, err := hotkeyVKey()
			if err != nil {
				return nil, 0, err
			}
			key = vKey
			hasKey = true
		case "caps", "capslock", "caps_lock":
			capsKey, err := capsLockHotkeyKey()
			if err != nil {
				return nil, 0, err
			}
			key = capsKey
			hasKey = true
		default:
			return nil, 0, fmt.Errorf("unsupported key: %s", part)
		}
	}
	if !hasKey {
		return nil, 0, fmt.Errorf("missing key")
	}
	return mods, key, nil
}

func hotkeyModifierCtrl() (hotkey.Modifier, error) {
	switch runtime.GOOS {
	case "linux":
		return hotkeyModifierFromCode(1 << 2), nil
	case "darwin":
		return hotkeyModifierFromCode(0x1000), nil
	case "windows":
		return hotkeyModifierFromCode(0x2), nil
	default:
		return 0, fmt.Errorf("hotkey ctrl modifier is unsupported on %s", runtime.GOOS)
	}
}

func hotkeyModifierShift() (hotkey.Modifier, error) {
	switch runtime.GOOS {
	case "linux":
		return hotkeyModifierFromCode(1 << 0), nil
	case "darwin":
		return hotkeyModifierFromCode(0x200), nil
	case "windows":
		return hotkeyModifierFromCode(0x4), nil
	default:
		return 0, fmt.Errorf("hotkey shift modifier is unsupported on %s", runtime.GOOS)
	}
}

func hotkeySpaceKey() (hotkey.Key, error) {
	switch runtime.GOOS {
	case "linux", "windows":
		return hotkeyKeyFromCode(0x20), nil
	case "darwin":
		return hotkeyKeyFromCode(49), nil
	default:
		return 0, fmt.Errorf("hotkey space key is unsupported on %s", runtime.GOOS)
	}
}

func hotkeyVKey() (hotkey.Key, error) {
	switch runtime.GOOS {
	case "linux":
		return hotkeyKeyFromCode(0x76), nil
	case "darwin":
		return hotkeyKeyFromCode(9), nil
	case "windows":
		return hotkeyKeyFromCode(0x56), nil
	default:
		return 0, fmt.Errorf("hotkey v key is unsupported on %s", runtime.GOOS)
	}
}

func capsLockHotkeyKey() (hotkey.Key, error) {
	switch runtime.GOOS {
	case "linux":
		return hotkeyKeyFromCode(0xffe5), nil
	case "darwin":
		return hotkeyKeyFromCode(0x39), nil
	case "windows":
		return hotkeyKeyFromCode(0x14), nil
	default:
		return 0, fmt.Errorf("capslock is unsupported on %s", runtime.GOOS)
	}
}

func hotkeyModifierFromCode(code uint32) hotkey.Modifier {
	return hotkey.Modifier(code)
}

func hotkeyKeyFromCode(code uint32) hotkey.Key {
	return hotkey.Key(code)
}
