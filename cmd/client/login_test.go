package main

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestLoginValidateSubmit(t *testing.T) {
	m := newLoginModel("http://server")
	m.usernameInput.SetValue("alice")
	m.passwordInput.SetValue("password")
	m.passphraseInp.SetValue("passphrase")
	if msg := m.validateSubmit(); msg != "" {
		t.Fatalf("unexpected error: %s", msg)
	}

	m.passphraseInp.SetValue("short")
	if msg := m.validateSubmit(); msg == "" {
		t.Fatalf("expected passphrase error")
	}
}

func TestLoginMoveFocus(t *testing.T) {
	m := newLoginModel("http://server")
	m.isRegister = true
	m.focusIdx = 0
	m.moveFocus(1)
	if m.focusIdx != 1 {
		t.Fatalf("expected focus 1, got %d", m.focusIdx)
	}
	m.moveFocus(-1)
	if m.focusIdx != 0 {
		t.Fatalf("expected focus 0, got %d", m.focusIdx)
	}
}

func TestLoginHandleServerSelectKey(t *testing.T) {
	m := newLoginModel("http://server")
	m.serverHistory = []string{"http://one", "http://two"}
	m.selectActive = true
	m.selectIndex = 0
	m.handleServerSelectKey(tea.KeyMsg{Type: tea.KeyDown})
	if m.selectIndex != 1 {
		t.Fatalf("expected index 1, got %d", m.selectIndex)
	}
	m.handleServerSelectKey(tea.KeyMsg{Type: tea.KeyEnter})
	if m.selectActive {
		t.Fatalf("expected select inactive")
	}
	if m.serverInput.Value() != "http://two" {
		t.Fatalf("unexpected server value: %s", m.serverInput.Value())
	}
}
