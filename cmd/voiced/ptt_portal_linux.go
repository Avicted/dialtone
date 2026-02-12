//go:build linux

package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
)

const (
	portalService                  = "org.freedesktop.portal.Desktop"
	portalObjectPath               = dbus.ObjectPath("/org/freedesktop/portal/desktop")
	portalGlobalShortcutsInterface = "org.freedesktop.portal.GlobalShortcuts"
	portalRequestInterface         = "org.freedesktop.portal.Request"
	portalSessionInterface         = "org.freedesktop.portal.Session"
	portalShortcutID               = "dialtone_ptt"
	portalActivationSignalSuffix   = ".Activated"
	portalDeactivationSignalSuffix = ".Deactivated"
	portalResponseSignal           = "org.freedesktop.portal.Request.Response"
	portalRequestTimeout           = 45 * time.Second
)

type portalPTTBackend struct {
	binding     string
	conn        *dbus.Conn
	sessionPath dbus.ObjectPath
}

func newPortalPTTBackend(binding string) (pttBackend, error) {
	if strings.TrimSpace(binding) == "" {
		return nil, fmt.Errorf("hotkey binding is required")
	}

	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return nil, fmt.Errorf("connect session bus: %w", err)
	}

	createCtx, cancelCreate := context.WithTimeout(context.Background(), portalRequestTimeout)
	sessionPath, err := createPortalSession(createCtx, conn)
	cancelCreate()
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	bindCtx, cancelBind := context.WithTimeout(context.Background(), portalRequestTimeout)
	if err := bindPortalShortcut(bindCtx, conn, sessionPath, binding); err != nil {
		cancelBind()
		_ = closePortalSession(conn, sessionPath)
		_ = conn.Close()
		return nil, err
	}
	cancelBind()
	return &portalPTTBackend{binding: binding, conn: conn, sessionPath: sessionPath}, nil
}

func (p *portalPTTBackend) Run(ctx context.Context, onDown, onUp func()) error {
	if p == nil || p.conn == nil {
		return fmt.Errorf("portal ptt backend not initialized")
	}

	signals := make(chan *dbus.Signal, 32)
	p.conn.Signal(signals)
	defer p.conn.RemoveSignal(signals)

	if err := p.conn.AddMatchSignal(
		dbus.WithMatchObjectPath(portalObjectPath),
		dbus.WithMatchInterface(portalGlobalShortcutsInterface),
		dbus.WithMatchMember("Activated"),
	); err != nil {
		return fmt.Errorf("portal add Activated match: %w", err)
	}
	defer func() {
		_ = p.conn.RemoveMatchSignal(
			dbus.WithMatchObjectPath(portalObjectPath),
			dbus.WithMatchInterface(portalGlobalShortcutsInterface),
			dbus.WithMatchMember("Activated"),
		)
	}()

	if err := p.conn.AddMatchSignal(
		dbus.WithMatchObjectPath(portalObjectPath),
		dbus.WithMatchInterface(portalGlobalShortcutsInterface),
		dbus.WithMatchMember("Deactivated"),
	); err != nil {
		return fmt.Errorf("portal add Deactivated match: %w", err)
	}
	defer func() {
		_ = p.conn.RemoveMatchSignal(
			dbus.WithMatchObjectPath(portalObjectPath),
			dbus.WithMatchInterface(portalGlobalShortcutsInterface),
			dbus.WithMatchMember("Deactivated"),
		)
	}()

	defer func() {
		_ = closePortalSession(p.conn, p.sessionPath)
		_ = p.conn.Close()
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		case sig := <-signals:
			if sig == nil {
				continue
			}
			if sig.Name != portalGlobalShortcutsInterface+portalActivationSignalSuffix &&
				sig.Name != portalGlobalShortcutsInterface+portalDeactivationSignalSuffix {
				continue
			}
			if len(sig.Body) < 2 {
				continue
			}
			session, ok := sig.Body[0].(dbus.ObjectPath)
			if !ok || session != p.sessionPath {
				continue
			}
			shortcutID, ok := sig.Body[1].(string)
			if !ok || shortcutID != portalShortcutID {
				continue
			}
			switch sig.Name {
			case portalGlobalShortcutsInterface + portalActivationSignalSuffix:
				if onDown != nil {
					onDown()
				}
			case portalGlobalShortcutsInterface + portalDeactivationSignalSuffix:
				if onUp != nil {
					onUp()
				}
			}
		}
	}
}

func createPortalSession(ctx context.Context, conn *dbus.Conn) (dbus.ObjectPath, error) {
	handleToken := portalToken("request")
	sessionToken := portalToken("session")
	options := map[string]dbus.Variant{
		"handle_token":         dbus.MakeVariant(handleToken),
		"session_handle_token": dbus.MakeVariant(sessionToken),
	}

	var requestPath dbus.ObjectPath
	call := conn.Object(portalService, portalObjectPath).CallWithContext(
		ctx,
		portalGlobalShortcutsInterface+".CreateSession",
		0,
		options,
	)
	if call.Err != nil {
		return "", fmt.Errorf("portal CreateSession call failed: %w", call.Err)
	}
	if err := call.Store(&requestPath); err != nil {
		return "", fmt.Errorf("portal CreateSession decode failed: %w", err)
	}

	responseCode, results, err := waitPortalResponse(ctx, conn, requestPath)
	if err != nil {
		return "", err
	}
	if responseCode != 0 {
		return "", fmt.Errorf("portal CreateSession denied: response=%d", responseCode)
	}

	rawSession, ok := results["session_handle"]
	if !ok {
		return "", fmt.Errorf("portal CreateSession response missing session_handle")
	}
	sessionPath, err := portalSessionPath(rawSession)
	if err != nil {
		return "", err
	}
	return sessionPath, nil
}

func portalSessionPath(raw dbus.Variant) (dbus.ObjectPath, error) {
	switch value := raw.Value().(type) {
	case dbus.ObjectPath:
		if !value.IsValid() {
			return "", fmt.Errorf("portal session_handle is not a valid object path: %q", string(value))
		}
		return value, nil
	case string:
		path := dbus.ObjectPath(value)
		if !path.IsValid() {
			return "", fmt.Errorf("portal session_handle string is not a valid object path: %q", value)
		}
		return path, nil
	default:
		return "", fmt.Errorf("portal session_handle has unexpected type %T", raw.Value())
	}
}

func bindPortalShortcut(ctx context.Context, conn *dbus.Conn, sessionPath dbus.ObjectPath, binding string) error {
	trigger := portalPreferredTrigger(binding)
	if trigger != "" {
		if err := bindPortalShortcutWithTrigger(ctx, conn, sessionPath, trigger); err == nil {
			return nil
		}
	}
	return bindPortalShortcutWithTrigger(ctx, conn, sessionPath, "")
}

func bindPortalShortcutWithTrigger(ctx context.Context, conn *dbus.Conn, sessionPath dbus.ObjectPath, trigger string) error {
	details := map[string]dbus.Variant{
		"description": dbus.MakeVariant("Dialtone push-to-talk"),
	}
	if trigger != "" {
		details["preferred_trigger"] = dbus.MakeVariant(trigger)
	}

	shortcuts := []portalShortcutSpec{{ID: portalShortcutID, Details: details}}
	options := map[string]dbus.Variant{
		"handle_token": dbus.MakeVariant(portalToken("bind")),
	}

	var requestPath dbus.ObjectPath
	call := conn.Object(portalService, portalObjectPath).CallWithContext(
		ctx,
		portalGlobalShortcutsInterface+".BindShortcuts",
		0,
		sessionPath,
		shortcuts,
		"",
		options,
	)
	if call.Err != nil {
		return fmt.Errorf("portal BindShortcuts call failed: %w", call.Err)
	}
	if err := call.Store(&requestPath); err != nil {
		return fmt.Errorf("portal BindShortcuts decode failed: %w", err)
	}

	responseCode, _, err := waitPortalResponse(ctx, conn, requestPath)
	if err != nil {
		return err
	}
	if responseCode != 0 {
		if trigger != "" {
			return fmt.Errorf("portal BindShortcuts denied for preferred trigger %q: response=%d", trigger, responseCode)
		}
		return fmt.Errorf("portal BindShortcuts denied: response=%d", responseCode)
	}
	return nil
}

func waitPortalResponse(ctx context.Context, conn *dbus.Conn, requestPath dbus.ObjectPath) (uint32, map[string]dbus.Variant, error) {
	signals := make(chan *dbus.Signal, 8)
	conn.Signal(signals)
	defer conn.RemoveSignal(signals)

	if err := conn.AddMatchSignal(
		dbus.WithMatchObjectPath(requestPath),
		dbus.WithMatchInterface(portalRequestInterface),
		dbus.WithMatchMember("Response"),
	); err != nil {
		return 0, nil, fmt.Errorf("portal response match failed: %w", err)
	}
	defer func() {
		_ = conn.RemoveMatchSignal(
			dbus.WithMatchObjectPath(requestPath),
			dbus.WithMatchInterface(portalRequestInterface),
			dbus.WithMatchMember("Response"),
		)
	}()

	for {
		select {
		case <-ctx.Done():
			return 0, nil, fmt.Errorf("portal response timeout: %w", ctx.Err())
		case sig := <-signals:
			if sig == nil || sig.Name != portalResponseSignal || sig.Path != requestPath {
				continue
			}
			if len(sig.Body) < 2 {
				return 0, nil, fmt.Errorf("portal response malformed")
			}
			responseCode, ok := sig.Body[0].(uint32)
			if !ok {
				return 0, nil, fmt.Errorf("portal response code type is %T", sig.Body[0])
			}
			results, ok := sig.Body[1].(map[string]dbus.Variant)
			if !ok {
				return responseCode, map[string]dbus.Variant{}, nil
			}
			return responseCode, results, nil
		}
	}
}

func closePortalSession(conn *dbus.Conn, sessionPath dbus.ObjectPath) error {
	if conn == nil || sessionPath == "" {
		return nil
	}
	call := conn.Object(portalService, sessionPath).Call(portalSessionInterface+".Close", 0)
	if call.Err != nil {
		return fmt.Errorf("portal session close failed: %w", call.Err)
	}
	return nil
}

func portalPreferredTrigger(binding string) string {
	binding = strings.TrimSpace(strings.ToLower(binding))
	if binding == "" {
		return ""
	}
	parts := strings.Split(binding, "+")
	mods := make([]string, 0, len(parts)-1)
	key := ""
	for _, part := range parts {
		part = strings.TrimSpace(part)
		switch part {
		case "ctrl", "control":
			mods = append(mods, "<Ctrl>")
		case "shift":
			mods = append(mods, "<Shift>")
		case "space":
			key = "space"
		case "v":
			key = "v"
		case "caps", "capslock", "caps_lock":
			return ""
		default:
			return ""
		}
	}
	if key == "" {
		return ""
	}
	return strings.Join(mods, "") + key
}

func portalToken(prefix string) string {
	return fmt.Sprintf("dialtone_%s_%d", prefix, time.Now().UnixNano())
}

type portalShortcutSpec struct {
	ID      string
	Details map[string]dbus.Variant
}
