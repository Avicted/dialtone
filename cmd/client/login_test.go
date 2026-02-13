package main

import (
	"strings"
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

	m.usernameInput.SetValue("a")
	if msg := m.validateSubmit(); msg == "" {
		t.Fatalf("expected username length error")
	}

	m.usernameInput.CharLimit = 0
	m.usernameInput.SetValue(strings.Repeat("a", 21))
	if msg := m.validateSubmit(); msg == "" {
		t.Fatalf("expected username max length error")
	}

	m.usernameInput.SetValue("alice")

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

func TestLoginUpdateValidationErrors(t *testing.T) {
	m := newLoginModel("")
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if updated.errMsg == "" {
		t.Fatalf("expected validation error")
	}
}

func TestLoginUpdateToggleRegisterAndSelectServers(t *testing.T) {
	m := newLoginModel("http://server")
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyCtrlR})
	if !updated.isRegister {
		t.Fatalf("expected register mode")
	}

	updated.serverHistory = nil
	updated, _ = updated.Update(tea.KeyMsg{Type: tea.KeyCtrlS})
	if updated.errMsg == "" {
		t.Fatalf("expected no saved servers error")
	}
}

func TestLoginUpdateServerSelectEsc(t *testing.T) {
	m := newLoginModel("http://server")
	m.serverHistory = []string{"http://one"}
	m.selectActive = true
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if updated.selectActive {
		t.Fatalf("expected selection canceled")
	}
}

func TestLoginInputCountRegister(t *testing.T) {
	m := newLoginModel("")
	if m.inputCount() != 4 {
		t.Fatalf("unexpected input count")
	}
	m.isRegister = true
	if m.inputCount() != 6 {
		t.Fatalf("unexpected register input count")
	}
}

func TestLoginEnsureFocusIndex(t *testing.T) {
	m := newLoginModel("")
	m.focusIdx = 10
	m.ensureFocusIndex()
	if m.focusIdx != 3 {
		t.Fatalf("unexpected focus index: %d", m.focusIdx)
	}

	m.isRegister = true
	m.focusIdx = 10
	m.ensureFocusIndex()
	if m.focusIdx != 5 {
		t.Fatalf("unexpected register focus index: %d", m.focusIdx)
	}
}

func TestLoginUpdateTabMovesFocus(t *testing.T) {
	m := newLoginModel("")
	m.focusIdx = 0
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyTab})
	if updated.focusIdx != 1 {
		t.Fatalf("expected focus move")
	}
}

func TestLoginViewWithErrorsAndLoading(t *testing.T) {
	m := newLoginModel("http://server")
	m.width = 80
	m.height = 24
	m.errMsg = "bad"
	m.loading = true
	view := m.View()
	if view == "" {
		t.Fatalf("expected view")
	}
}

func TestLoginConfirmPasswordGetter(t *testing.T) {
	m := newLoginModel("http://server")
	m.confirmInput.SetValue("secret-confirm")
	if got := m.confirmPassword(); got != "secret-confirm" {
		t.Fatalf("confirmPassword() = %q, want %q", got, "secret-confirm")
	}
}
