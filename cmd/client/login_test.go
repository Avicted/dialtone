package main

import (
	"context"
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

func TestLoginUpdateAdditionalBranches(t *testing.T) {
	m := newLoginModel("http://server")
	updated, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 40})
	if updated.width != 100 || updated.height != 40 {
		t.Fatalf("unexpected size: %dx%d", updated.width, updated.height)
	}

	updated, _ = updated.Update(authErrorMsg{err: context.Canceled})
	if updated.loading {
		t.Fatalf("expected loading cleared on auth error")
	}
	if updated.errMsg == "" {
		t.Fatalf("expected auth error message")
	}

	updated.serverHistory = []string{"http://one", "http://two"}
	updated, _ = updated.Update(tea.KeyMsg{Type: tea.KeyCtrlS})
	if !updated.selectActive || updated.selectIndex != 0 {
		t.Fatalf("expected server selector activated")
	}

	updated.loading = true
	updated, _ = updated.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if updated.submitting {
		t.Fatalf("expected no submit while already loading")
	}

	updated.loading = false
	updated.selectActive = false
	updated.serverInput.SetValue("http://server")
	updated.usernameInput.SetValue("alice")
	updated.passwordInput.SetValue("password")
	updated.passphraseInp.SetValue("passphrase123")
	updated, _ = updated.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if !updated.loading || !updated.submitting {
		t.Fatalf("expected submit to set loading and submitting")
	}
}

func TestLoginHandleServerSelectKeyEdges(t *testing.T) {
	m := newLoginModel("http://server")
	m.selectActive = true
	m.handleServerSelectKey(tea.KeyMsg{Type: tea.KeyEsc})
	if m.selectActive {
		t.Fatalf("expected empty-history selector to close")
	}

	m.serverHistory = []string{"http://one", "http://two"}
	m.selectActive = true
	m.selectIndex = 0
	m.handleServerSelectKey(tea.KeyMsg{Type: tea.KeyUp})
	if m.selectIndex != 0 {
		t.Fatalf("expected upper bound to hold index at 0")
	}
	m.handleServerSelectKey(tea.KeyMsg{Type: tea.KeyDown})
	m.handleServerSelectKey(tea.KeyMsg{Type: tea.KeyDown})
	if m.selectIndex != 1 {
		t.Fatalf("expected lower bound to hold index at 1, got %d", m.selectIndex)
	}
	m.handleServerSelectKey(tea.KeyMsg{Type: tea.KeyEsc})
	if m.selectActive {
		t.Fatalf("expected selector to close on esc")
	}
}

func TestLoginApplyFocusModes(t *testing.T) {
	m := newLoginModel("http://server")

	m.focusIdx = 3
	m.isRegister = false
	m.applyFocus()
	if !m.passphraseInp.Focused() {
		t.Fatalf("expected passphrase focused in login mode at index 3")
	}

	m.focusIdx = 4
	m.isRegister = false
	m.applyFocus()
	if !m.serverInput.Focused() {
		t.Fatalf("expected server focused in login mode at index 4")
	}

	m.focusIdx = 3
	m.isRegister = true
	m.applyFocus()
	if !m.confirmInput.Focused() {
		t.Fatalf("expected confirm focused in register mode at index 3")
	}

	m.focusIdx = 4
	m.applyFocus()
	if !m.passphraseInp.Focused() {
		t.Fatalf("expected passphrase focused in register mode at index 4")
	}

	m.focusIdx = 5
	m.applyFocus()
	if !m.inviteInput.Focused() {
		t.Fatalf("expected invite focused in register mode at index 5")
	}
}

func TestLoginValidateSubmitRegisterRequirements(t *testing.T) {
	m := newLoginModel("http://server")
	m.isRegister = true
	m.usernameInput.SetValue("alice")
	m.passwordInput.SetValue("password")
	m.passphraseInp.SetValue("passphrase123")
	m.confirmInput.SetValue("different")
	m.inviteInput.SetValue("invite")

	if got := m.validateSubmit(); !strings.Contains(got, "passwords do not match") {
		t.Fatalf("expected mismatch error, got %q", got)
	}

	m.confirmInput.SetValue("password")
	m.inviteInput.SetValue("  ")
	if got := m.validateSubmit(); !strings.Contains(got, "invite token is required") {
		t.Fatalf("expected invite token error, got %q", got)
	}

	m.serverInput.SetValue("")
	if got := m.validateSubmit(); !strings.Contains(got, "server url is required") {
		t.Fatalf("expected server url error, got %q", got)
	}

	m.serverInput.SetValue("http://server")
	m.usernameInput.SetValue(" ")
	if got := m.validateSubmit(); !strings.Contains(got, "username and password are required") {
		t.Fatalf("expected required credentials error, got %q", got)
	}
}

func TestLoginUpdateFocusSwitchCases(t *testing.T) {
	runeMsg := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("x")}

	m := newLoginModel("http://server")
	m.focusIdx = 0
	m.applyFocus()
	m, _ = m.Update(runeMsg)
	if !strings.Contains(m.serverInput.Value(), "x") {
		t.Fatalf("expected server input update at focus 0")
	}

	m = newLoginModel("http://server")
	m.focusIdx = 1
	m.applyFocus()
	m, _ = m.Update(runeMsg)
	if !strings.Contains(m.usernameInput.Value(), "x") {
		t.Fatalf("expected username input update at focus 1")
	}

	m = newLoginModel("http://server")
	m.focusIdx = 2
	m.applyFocus()
	m, _ = m.Update(runeMsg)
	if !strings.Contains(m.passwordInput.Value(), "x") {
		t.Fatalf("expected password input update at focus 2")
	}

	m = newLoginModel("http://server")
	m.focusIdx = 3
	m.isRegister = false
	m.applyFocus()
	m, _ = m.Update(runeMsg)
	if !strings.Contains(m.passphraseInp.Value(), "x") {
		t.Fatalf("expected passphrase input update at focus 3 login mode")
	}

	m = newLoginModel("http://server")
	m.focusIdx = 3
	m.isRegister = true
	m.applyFocus()
	m, _ = m.Update(runeMsg)
	if !strings.Contains(m.confirmInput.Value(), "x") {
		t.Fatalf("expected confirm input update at focus 3 register mode")
	}

	m = newLoginModel("http://server")
	m.focusIdx = 4
	m.isRegister = true
	m.applyFocus()
	m, _ = m.Update(runeMsg)
	if !strings.Contains(m.passphraseInp.Value(), "x") {
		t.Fatalf("expected passphrase input update at focus 4 register mode")
	}

	m = newLoginModel("http://server")
	m.focusIdx = 5
	m.isRegister = true
	m.applyFocus()
	m, _ = m.Update(runeMsg)
	if !strings.Contains(m.inviteInput.Value(), "x") {
		t.Fatalf("expected invite input update at focus 5 register mode")
	}

	m = newLoginModel("http://server")
	m.focusIdx = 99
	m.applyFocus()
	m, _ = m.Update(runeMsg)
	if !strings.Contains(m.serverInput.Value(), "x") {
		t.Fatalf("expected default branch to update server input")
	}
}

func TestLoginViewRegisterSelectionRendering(t *testing.T) {
	m := newLoginModel("http://server")
	m.width = 100
	m.height = 40
	m.isRegister = true
	m.serverHistory = []string{"http://one", "http://two"}
	m.selectActive = true
	m.selectIndex = 1

	view := m.View()
	if !strings.Contains(view, "Register") || !strings.Contains(view, "Invite Token") {
		t.Fatalf("expected register labels in view")
	}
	if !strings.Contains(view, "Select server") {
		t.Fatalf("expected server selection section in view")
	}
}
