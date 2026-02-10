package main

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

type loginModel struct {
	serverInput   textinput.Model
	usernameInput textinput.Model
	passwordInput textinput.Model
	confirmInput  textinput.Model
	inviteInput   textinput.Model
	focusIdx      int
	isRegister    bool
	submitting    bool
	errMsg        string
	loading       bool
	width         int
	height        int
	serverHistory []string
	selectActive  bool
	selectIndex   int
}

func newLoginModel(defaultServer string) loginModel {
	server := textinput.New()
	server.Placeholder = "http://localhost:8080"
	server.CharLimit = 256
	server.Width = 40
	serverHistory := loadServerHistory()
	if strings.TrimSpace(defaultServer) != "" {
		server.SetValue(strings.TrimSpace(defaultServer))
	} else if len(serverHistory) > 0 {
		server.SetValue(serverHistory[0])
	}
	server.Focus()

	username := textinput.New()
	username.Placeholder = "username"
	username.CharLimit = 64
	username.Width = 30

	password := textinput.New()
	password.Placeholder = "password (min 8 chars)"
	password.EchoMode = textinput.EchoPassword
	password.EchoCharacter = '*'
	password.CharLimit = 128
	password.Width = 30

	confirm := textinput.New()
	confirm.Placeholder = "confirm password"
	confirm.EchoMode = textinput.EchoPassword
	confirm.EchoCharacter = '*'
	confirm.CharLimit = 128
	confirm.Width = 30

	invite := textinput.New()
	invite.Placeholder = "invite token"
	invite.CharLimit = 256
	invite.Width = 40

	return loginModel{
		serverInput:   server,
		usernameInput: username,
		passwordInput: password,
		confirmInput:  confirm,
		inviteInput:   invite,
		focusIdx:      0,
		serverHistory: serverHistory,
	}
}

func (m loginModel) Init() tea.Cmd {
	return textinput.Blink
}

func (m loginModel) serverURL() string { return m.serverInput.Value() }
func (m loginModel) username() string  { return m.usernameInput.Value() }
func (m loginModel) password() string  { return m.passwordInput.Value() }
func (m loginModel) confirmPassword() string {
	return m.confirmInput.Value()
}

func (m loginModel) inviteToken() string {
	return m.inviteInput.Value()
}

func (m loginModel) inputCount() int {
	count := 3
	if m.isRegister {
		count = 5
	}
	return count
}

func (m loginModel) Update(msg tea.Msg) (loginModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case authErrorMsg:
		m.loading = false
		m.errMsg = msg.err.Error()
		return m, nil

	case tea.KeyMsg:
		m.errMsg = ""
		if m.selectActive {
			m.handleServerSelectKey(msg)
			return m, nil
		}

		switch msg.Type {
		case tea.KeyTab, tea.KeyShiftTab, tea.KeyUp, tea.KeyDown, tea.KeyCtrlN, tea.KeyCtrlP:
			dir := 1
			if msg.Type == tea.KeyUp || msg.Type == tea.KeyShiftTab || msg.Type == tea.KeyCtrlP {
				dir = -1
			}
			m.moveFocus(dir)
			return m, nil
		}

		switch msg.String() {
		case "tab", "shift+tab", "down", "up", "ctrl+n", "ctrl+p":
			dir := 1
			if msg.String() == "up" || msg.String() == "shift+tab" || msg.String() == "ctrl+p" {
				dir = -1
			}
			m.moveFocus(dir)
			return m, nil

		case "ctrl+r":
			m.isRegister = !m.isRegister
			m.ensureFocusIndex()
			return m, nil

		case "ctrl+s":
			if len(m.serverHistory) == 0 {
				m.errMsg = "no saved servers yet"
				return m, nil
			}
			m.selectActive = true
			m.selectIndex = 0
			return m, nil

		case "enter":
			if m.loading {
				return m, nil
			}
			if strings.TrimSpace(m.serverURL()) == "" {
				m.errMsg = "server url is required"
				return m, nil
			}
			if m.username() == "" || m.password() == "" {
				m.errMsg = "username and password are required"
				return m, nil
			}
			if m.isRegister && m.password() != m.confirmPassword() {
				m.errMsg = "passwords do not match"
				return m, nil
			}
			if m.isRegister && strings.TrimSpace(m.inviteToken()) == "" {
				m.errMsg = "invite token is required"
				return m, nil
			}
			m.loading = true
			m.submitting = true
			return m, nil
		}
	}

	var cmd tea.Cmd
	switch m.focusIdx {
	case 0:
		m.serverInput, cmd = m.serverInput.Update(msg)
	case 1:
		m.usernameInput, cmd = m.usernameInput.Update(msg)
	case 2:
		m.passwordInput, cmd = m.passwordInput.Update(msg)
	case 3:
		m.confirmInput, cmd = m.confirmInput.Update(msg)
	case 4:
		m.inviteInput, cmd = m.inviteInput.Update(msg)
	default:
		m.serverInput, cmd = m.serverInput.Update(msg)
	}
	return m, cmd
}

func (m *loginModel) handleServerSelectKey(msg tea.KeyMsg) {
	if len(m.serverHistory) == 0 {
		m.selectActive = false
		return
	}
	switch msg.String() {
	case "up", "k":
		if m.selectIndex > 0 {
			m.selectIndex--
		}
	case "down", "j":
		if m.selectIndex < len(m.serverHistory)-1 {
			m.selectIndex++
		}
	case "enter":
		m.serverInput.SetValue(m.serverHistory[m.selectIndex])
		m.selectActive = false
	case "esc":
		m.selectActive = false
	}
}

func (m *loginModel) applyFocus() {
	m.serverInput.Blur()
	m.usernameInput.Blur()
	m.passwordInput.Blur()
	m.confirmInput.Blur()
	m.inviteInput.Blur()

	switch m.focusIdx {
	case 0:
		m.serverInput.Focus()
	case 1:
		m.usernameInput.Focus()
	case 2:
		m.passwordInput.Focus()
	case 3:
		if m.isRegister {
			m.confirmInput.Focus()
		} else {
			m.serverInput.Focus()
		}
	case 4:
		if m.isRegister {
			m.inviteInput.Focus()
		} else {
			m.serverInput.Focus()
		}
	default:
		m.serverInput.Focus()
	}
}

func (m loginModel) View() string {
	var b strings.Builder

	topPad := 0
	if m.height > 15 {
		topPad = (m.height - 15) / 3
	}
	b.WriteString(strings.Repeat("\n", topPad))

	b.WriteString(centerText(appNameStyle.Render("*  dialtone"), m.width))
	b.WriteString("\n")
	b.WriteString(centerText(subtitleStyle.Render("encrypted messaging"), m.width))
	b.WriteString("\n\n")

	mode := "Login"
	if m.isRegister {
		mode = "Register"
	}
	b.WriteString(centerText(headerStyle.Render(fmt.Sprintf("[ %s ]", mode)), m.width))
	b.WriteString("\n\n")

	labels := []string{"Server", "Username", "Password"}
	inputs := []textinput.Model{m.serverInput, m.usernameInput, m.passwordInput}
	if m.isRegister {
		labels = append(labels, "Confirm Password", "Invite Token")
		inputs = append(inputs, m.confirmInput, m.inviteInput)
	}
	for i, input := range inputs {
		line := labelStyle.Render(fmt.Sprintf("  %s: ", labels[i])) + input.View()
		b.WriteString(centerText(line, m.width))
		b.WriteString("\n")
	}
	b.WriteString("\n")

	if m.selectActive {
		b.WriteString(centerText(labelStyle.Render("Select server"), m.width))
		b.WriteString("\n")
		for i, server := range m.serverHistory {
			prefix := "  "
			if i == m.selectIndex {
				prefix = "> "
			}
			line := prefix + trimLine(server, clampMin(m.width-6, 20))
			b.WriteString(centerText(labelStyle.Render(line), m.width))
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}

	if m.errMsg != "" {
		b.WriteString(centerText(errorStyle.Render("  x "+m.errMsg), m.width))
		b.WriteString("\n\n")
	}

	if m.loading {
		b.WriteString(centerText(labelStyle.Render("  connecting..."), m.width))
		b.WriteString("\n\n")
	}

	b.WriteString(centerText(helpStyle.Render("up/down or tab: switch field - ctrl+r: register/login - ctrl+s: servers - enter: submit - ctrl+q: quit"), m.width))

	return b.String()
}

func (m *loginModel) moveFocus(dir int) {
	count := m.inputCount()
	if count == 0 {
		return
	}
	m.focusIdx = (m.focusIdx + dir + count) % count
	m.applyFocus()
}

func (m *loginModel) ensureFocusIndex() {
	count := m.inputCount()
	if count == 0 {
		m.focusIdx = 0
		m.applyFocus()
		return
	}
	if m.focusIdx >= count {
		m.focusIdx = count - 1
	}
	m.applyFocus()
}
