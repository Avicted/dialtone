package main

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

type loginModel struct {
	inputs     [2]textinput.Model
	focusIdx   int
	isRegister bool
	submitting bool
	errMsg     string
	loading    bool
	width      int
	height     int
}

func newLoginModel() loginModel {
	username := textinput.New()
	username.Placeholder = "username"
	username.Focus()
	username.CharLimit = 64
	username.Width = 30

	password := textinput.New()
	password.Placeholder = "password (min 8 chars)"
	password.EchoMode = textinput.EchoPassword
	password.EchoCharacter = '*'
	password.CharLimit = 128
	password.Width = 30

	return loginModel{
		inputs:   [2]textinput.Model{username, password},
		focusIdx: 0,
	}
}

func (m loginModel) Init() tea.Cmd {
	return textinput.Blink
}

func (m loginModel) username() string { return m.inputs[0].Value() }
func (m loginModel) password() string { return m.inputs[1].Value() }

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

		switch msg.String() {
		case "tab", "shift+tab", "down", "up":
			dir := 1
			if msg.String() == "up" || msg.String() == "shift+tab" {
				dir = -1
			}
			m.focusIdx = (m.focusIdx + dir + len(m.inputs)) % len(m.inputs)
			for i := range m.inputs {
				if i == m.focusIdx {
					m.inputs[i].Focus()
				} else {
					m.inputs[i].Blur()
				}
			}
			return m, nil

		case "ctrl+r":
			m.isRegister = !m.isRegister
			return m, nil

		case "enter":
			if m.loading {
				return m, nil
			}
			if m.username() == "" || m.password() == "" {
				m.errMsg = "username and password are required"
				return m, nil
			}
			m.loading = true
			m.submitting = true
			return m, nil
		}
	}

	var cmd tea.Cmd
	m.inputs[m.focusIdx], cmd = m.inputs[m.focusIdx].Update(msg)
	return m, cmd
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

	labels := [2]string{"Username", "Password"}
	for i, input := range m.inputs {
		line := labelStyle.Render(fmt.Sprintf("  %s: ", labels[i])) + input.View()
		b.WriteString(centerText(line, m.width))
		b.WriteString("\n")
	}
	b.WriteString("\n")

	if m.errMsg != "" {
		b.WriteString(centerText(errorStyle.Render("  x "+m.errMsg), m.width))
		b.WriteString("\n\n")
	}

	if m.loading {
		b.WriteString(centerText(labelStyle.Render("  connecting..."), m.width))
		b.WriteString("\n\n")
	}

	b.WriteString(centerText(helpStyle.Render("tab: switch field - ctrl+r: register/login - enter: submit - ctrl+q: quit"), m.width))

	return b.String()
}
