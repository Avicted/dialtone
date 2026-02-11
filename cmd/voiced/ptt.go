package main

import (
	"context"
	"fmt"
	"strings"

	"golang.design/x/hotkey"
)

type pttController struct {
	hk *hotkey.Hotkey
}

func newPTTController(binding string) (*pttController, error) {
	mods, key, err := parseHotkey(binding)
	if err != nil {
		return nil, err
	}
	return &pttController{hk: hotkey.New(mods, key)}, nil
}

func (p *pttController) Run(ctx context.Context, onDown, onUp func()) error {
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
	for _, part := range parts {
		part = strings.TrimSpace(part)
		switch part {
		case "ctrl", "control":
			mods = append(mods, hotkey.ModCtrl)
		case "shift":
			mods = append(mods, hotkey.ModShift)
		case "space":
			key = hotkey.KeySpace
		case "v":
			key = hotkey.KeyV
		default:
			return nil, 0, fmt.Errorf("unsupported key: %s", part)
		}
	}
	if key == 0 {
		return nil, 0, fmt.Errorf("missing key")
	}
	return mods, key, nil
}
