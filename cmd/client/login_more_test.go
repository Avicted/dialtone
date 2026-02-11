package main

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

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
