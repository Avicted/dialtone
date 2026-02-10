package main

import (
	"context"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/Avicted/dialtone/internal/crypto"
)

type appState int

const (
	stateLogin appState = iota
	stateChat
)

type rootModel struct {
	api    *APIClient
	state  appState
	login  loginModel
	chat   chatModel
	width  int
	height int
}

type authSuccessMsg struct {
	auth *AuthResponse
	kp   *crypto.KeyPair
}

type authErrorMsg struct {
	err error
}

func newRootModel(api *APIClient) rootModel {
	return rootModel{
		api:   api,
		state: stateLogin,
		login: newLoginModel(api.serverURL),
	}
}

func (m rootModel) Init() tea.Cmd {
	return m.login.Init()
}

func (m rootModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if wsm, ok := msg.(tea.WindowSizeMsg); ok {
		m.width = wsm.Width
		m.height = wsm.Height
	}

	if km, ok := msg.(tea.KeyMsg); ok && km.String() == "ctrl+q" {
		if m.state == stateChat && m.chat.ws != nil {
			m.chat.ws.Close()
		}
		return m, tea.Quit
	}

	if auth, ok := msg.(authSuccessMsg); ok {
		serverURL := strings.TrimSpace(m.login.serverURL())
		if serverURL != "" {
			m.login.serverHistory = updateServerHistory(m.login.serverHistory, serverURL, 8)
			_ = saveServerHistory(m.login.serverHistory)
		}
		m.state = stateChat
		m.chat = newChatModel(m.api, auth.auth, auth.kp, m.login.passphrase(), m.width, m.height)
		return m, m.chat.Init()
	}

	switch m.state {
	case stateLogin:
		var cmd tea.Cmd
		m.login, cmd = m.login.Update(msg)
		if m.login.submitting {
			m.login.submitting = false
			m.api.serverURL = strings.TrimSpace(m.login.serverURL())
			return m, tea.Batch(cmd, m.doAuth(m.login.isRegister, m.login.username(), m.login.password(), m.login.inviteToken(), m.login.passphrase()))
		}
		return m, cmd

	case stateChat:
		var cmd tea.Cmd
		m.chat, cmd = m.chat.Update(msg)
		return m, cmd
	}

	return m, nil
}

func (m rootModel) View() string {
	switch m.state {
	case stateLogin:
		return m.login.View()
	case stateChat:
		return m.chat.View()
	}
	return ""
}

func (m rootModel) doAuth(register bool, username, password, inviteToken, passphrase string) tea.Cmd {
	api := m.api
	return func() tea.Msg {
		ctx := context.Background()
		var resp *AuthResponse
		var kp *crypto.KeyPair
		var err error
		if register {
			resp, kp, err = api.Register(ctx, username, password, inviteToken, passphrase)
		} else {
			resp, kp, err = api.Login(ctx, username, password, passphrase)
		}
		if err != nil {
			return authErrorMsg{err: err}
		}
		return authSuccessMsg{auth: resp, kp: kp}
	}
}
