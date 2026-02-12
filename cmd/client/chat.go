package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/Avicted/dialtone/internal/crypto"
	"github.com/Avicted/dialtone/internal/ipc"
)

const (
	sidebarWidth             = 26
	shareKeysInterval        = 30 * time.Second
	channelRefreshDelay      = 3 * time.Second
	channelRefreshMaxRetries = 6
)

type chatMessage struct {
	sender     string
	senderName string
	body       string
	sentAt     string
	isHistory  bool
	isMine     bool
	isSystem   bool
	highlight  bool
}

type channelInfo struct {
	ID   string
	Name string
}

type userEntry struct {
	ID     string
	Name   string
	Online bool
	Known  bool
	Admin  bool
	Speak  bool
}

type chatModel struct {
	api                   *APIClient
	auth                  *AuthResponse
	kp                    *crypto.KeyPair
	keystorePassphrase    string
	wsConnect             func(serverURL, token string) (*WSClient, error)
	ws                    *WSClient
	wsCh                  chan ServerMessage
	voiceIPCAddr          string
	voiceIPC              *voiceIPC
	voiceRoom             string
	voiceCh               chan ipc.Message
	voiceMembers          map[string]bool
	voiceSpeaking         map[string]bool
	voiceAutoStart        bool
	voicedPath            string
	voiceArgs             []string
	voiceDebug            bool
	voiceLogPath          string
	voiceLogNotified      bool
	voiceAutoStarting     bool
	voicePendingCmd       *ipc.Message
	voicePendingRoom      string
	voicePendingNotice    string
	voiceProc             *voiceAutoProcess
	messages              []chatMessage
	channels              map[string]channelInfo
	channelMsgs           map[string][]chatMessage
	channelHistoryLoaded  map[string]bool
	userNames             map[string]string
	userPresence          map[string]bool
	userAdmins            map[string]bool
	channelKeys           map[string][]byte
	directoryKey          []byte
	pendingProfilePush    bool
	activeChannel         string
	channelUnread         map[string]int
	sidebarVisible        bool
	sidebarIndex          int
	selectActive          bool
	selectOptions         []channelInfo
	selectIndex           int
	viewport              viewport.Model
	input                 textinput.Model
	connected             bool
	errMsg                string
	width                 int
	height                int
	channelRefreshNeeded  bool
	channelRefreshRetries int
	voiceReconnectAttempt int
}

type wsConnectedMsg struct {
	ws *WSClient
	ch chan ServerMessage
}

type wsMessageMsg ServerMessage

type wsErrorMsg struct{ err error }

type voiceIPCConnectedMsg struct{ ch chan ipc.Message }
type voiceReconnectTick struct{}

type voiceIPCMsg ipc.Message

type voiceIPCErrorMsg struct{ err error }

type presenceTick struct{}

type shareTick struct{}

type voicePingTick struct{}

type shareKeysMsg struct{ err error }

type shareDirectoryMsg struct{ err error }

type directorySyncMsg struct {
	profiles []UserProfile
	pushed   bool
	err      error
}

type directoryTick struct{}

type channelRefreshTick struct{}

var errDirectoryKeyPending = fmt.Errorf("directory key pending")

func newChatModel(api *APIClient, auth *AuthResponse, kp *crypto.KeyPair, keystorePassphrase string, width, height int, voiceIPCAddr string) chatModel {
	input := textinput.New()
	input.Placeholder = "type a message..."
	input.CharLimit = 16384
	input.Width = clampMin(width-8, 20)
	input.Focus()

	vpHeight := clampMin(height-7, 1)
	vpWidth := clampMin(width-4, 10)
	vp := viewport.New(vpWidth, vpHeight)

	keys, keysErr := loadChannelKeys(keystorePassphrase)
	dirKey, dirErr := loadDirectoryKey(keystorePassphrase)

	model := chatModel{
		api:                  api,
		auth:                 auth,
		kp:                   kp,
		keystorePassphrase:   keystorePassphrase,
		wsConnect:            ConnectWS,
		voiceIPCAddr:         voiceIPCAddr,
		voiceIPC:             newVoiceIPC(voiceIPCAddr),
		voiceMembers:         make(map[string]bool),
		voiceSpeaking:        make(map[string]bool),
		viewport:             vp,
		input:                input,
		width:                width,
		height:               height,
		channels:             make(map[string]channelInfo),
		channelMsgs:          make(map[string][]chatMessage),
		channelHistoryLoaded: make(map[string]bool),
		userNames:            make(map[string]string),
		userPresence:         make(map[string]bool),
		userAdmins:           make(map[string]bool),
		channelKeys:          keys,
		directoryKey:         dirKey,
		channelUnread:        make(map[string]int),
		sidebarVisible:       true,
		sidebarIndex:         0,
	}
	if auth != nil && auth.IsTrusted {
		model.pendingProfilePush = true
	}
	model.updateLayout()
	if keysErr != nil {
		model.errMsg = "failed to load channel keys"
	}
	if dirErr != nil {
		model.errMsg = "failed to load directory key"
	}
	return model
}

func (m chatModel) Init() tea.Cmd {
	cmds := []tea.Cmd{textinput.Blink, m.connectWS()}
	if m.isTrusted() {
		cmds = append(cmds, m.syncDirectoryCmd(m.pendingProfilePush), m.scheduleDirectoryTick())
	}
	return tea.Batch(cmds...)
}

func (m *chatModel) isTrusted() bool {
	return m.auth != nil && m.auth.IsTrusted
}

func (m chatModel) connectWS() tea.Cmd {
	serverURL := m.api.serverURL
	token := m.auth.Token
	return func() tea.Msg {
		connector := m.wsConnect
		if connector == nil {
			return wsErrorMsg{err: fmt.Errorf("missing websocket connector")}
		}
		ws, err := connector(serverURL, token)
		if err != nil {
			return wsErrorMsg{err: err}
		}
		ch := make(chan ServerMessage, 64)
		go ws.ReadLoop(ch)
		return wsConnectedMsg{ws: ws, ch: ch}
	}
}

func waitForWSMsg(ch <-chan ServerMessage) tea.Cmd {
	return func() tea.Msg {
		msg, ok := <-ch
		if !ok {
			return wsErrorMsg{err: fmt.Errorf("connection closed")}
		}
		return wsMessageMsg(msg)
	}
}

func waitForVoiceMsg(ch <-chan ipc.Message) tea.Cmd {
	return func() tea.Msg {
		msg, ok := <-ch
		if !ok {
			return voiceIPCErrorMsg{err: fmt.Errorf("voice daemon disconnected")}
		}
		return voiceIPCMsg(msg)
	}
}

func (m chatModel) connectVoiceIPC() tea.Cmd {
	if m.voiceIPC == nil {
		return nil
	}
	return func() tea.Msg {
		if err := m.voiceIPC.ensureConn(); err != nil {
			return voiceIPCErrorMsg{err: err}
		}
		ch := make(chan ipc.Message, 16)
		go m.voiceIPC.readLoop(ch)
		return voiceIPCConnectedMsg{ch: ch}
	}
}

func (m chatModel) Update(msg tea.Msg) (chatModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.updateLayout()
		m.refreshViewport()
		return m, nil

	case tea.KeyMsg:
		if m.selectActive {
			m.handleChannelSelectKey(msg)
			return m, nil
		}
		if m.sidebarVisible && m.input.Value() == "" {
			switch msg.String() {
			case "up", "k":
				m.moveSidebarSelection(-1)
				return m, nil
			case "down", "j":
				m.moveSidebarSelection(1)
				return m, nil
			case "enter":
				if m.selectSidebarChannel() {
					return m, nil
				}
			}
		}
		switch msg.String() {
		case "enter":
			if m.connected {
				cmd := m.sendCurrentMessage()
				return m, cmd
			}
			return m, nil
		case "ctrl+h", "ctrl+u":
			m.sidebarVisible = !m.sidebarVisible
			m.updateLayout()
			m.refreshViewport()
			if m.sidebarVisible {
				m.refreshPresence()
				return m, m.schedulePresenceTick()
			}
			return m, nil

		case "pgup", "pgdown":
			var cmd tea.Cmd
			m.viewport, cmd = m.viewport.Update(msg)
			return m, cmd
		}

	case wsConnectedMsg:
		m.ws = msg.ws
		m.wsCh = msg.ch
		m.connected = true
		m.errMsg = ""
		m.refreshChannels(false)
		m.channelRefreshRetries = 0
		if m.activeChannel == "" && len(m.messages) == 0 {
			m.appendSystemMessage("no global chat; select a channel with the sidebar or /channel list")
		}
		cmds := []tea.Cmd{waitForWSMsg(m.wsCh), m.shareKnownChannelKeysCmd(), m.scheduleShareTick()}
		if m.sidebarVisible {
			m.refreshPresence()
			cmds = append(cmds, m.schedulePresenceTick())
		}
		if m.channelRefreshNeeded {
			cmds = append(cmds, m.scheduleChannelRefresh())
		}
		return m, tea.Batch(cmds...)

	case wsMessageMsg:
		serverMsg := ServerMessage(msg)
		if serverMsg.Type == "device.joined" {
			if serverMsg.DeviceID == m.auth.DeviceID {
				m.refreshChannels(false)
				m.channelRefreshRetries = 0
			}
			cmds := []tea.Cmd{waitForWSMsg(m.wsCh), m.shareKnownChannelKeysCmd()}
			if m.isTrusted() {
				cmds = append(cmds, m.shareDirectoryKeyCmd(), m.syncDirectoryCmd(m.pendingProfilePush))
			}
			if m.channelRefreshNeeded {
				cmds = append(cmds, m.scheduleChannelRefresh())
			}
			m.refreshViewport()
			return m, tea.Batch(cmds...)
		}
		if serverMsg.Type == "user.profile.updated" && m.isTrusted() {
			return m, tea.Batch(waitForWSMsg(m.wsCh), m.syncDirectoryCmd(false))
		}
		m.handleServerMessage(serverMsg)
		m.refreshViewport()
		return m, waitForWSMsg(m.wsCh)

	case wsErrorMsg:
		m.connected = false
		m.errMsg = msg.err.Error()
		return m, nil

	case voiceIPCConnectedMsg:
		m.voiceReconnectAttempt = 0
		m.voiceCh = msg.ch
		m.voiceAutoStarting = false
		if m.auth != nil && m.auth.UserID != "" && m.voiceIPC != nil {
			if err := m.voiceIPC.send(ipc.Message{Cmd: ipc.CommandIdentify, User: m.auth.UserID}); err != nil {
				m.appendSystemMessage(fmt.Sprintf("voice identity send failed: %v", err))
			}
		}
		if m.voicePendingCmd != nil && m.voiceIPC != nil {
			if err := m.voiceIPC.send(*m.voicePendingCmd); err != nil {
				m.appendSystemMessage(fmt.Sprintf("voice command pending (retrying): %v", err))
				m.voiceIPC.reset()
				m.voiceCh = nil
				m.voiceReconnectAttempt++
				return m, m.scheduleVoiceReconnect(m.voiceReconnectAttempt)
			}
			if m.voicePendingCmd.Cmd == ipc.CommandVoiceJoin && m.voicePendingRoom != "" {
				m.voiceRoom = m.voicePendingRoom
			}
			if m.voicePendingNotice != "" {
				m.appendSystemMessage(m.voicePendingNotice)
			}
			m.clearPendingVoiceCommand()
		}
		return m, tea.Batch(waitForVoiceMsg(m.voiceCh), m.scheduleVoicePing())

	case voiceIPCMsg:
		m.handleVoiceEvent(ipc.Message(msg))
		return m, waitForVoiceMsg(m.voiceCh)

	case voiceIPCErrorMsg:
		if !m.voiceAutoStarting {
			m.appendSystemMessage("voice daemon disconnected")
		}
		m.clearVoiceMembers()
		m.voiceCh = nil
		if m.voiceIPC == nil {
			return m, nil
		}
		m.voiceIPC.reset()
		m.voiceReconnectAttempt++
		return m, m.scheduleVoiceReconnect(m.voiceReconnectAttempt)

	case voiceReconnectTick:
		return m, m.connectVoiceIPC()

	case voicePingTick:
		if m.voiceIPC == nil {
			m.voiceReconnectAttempt++
			return m, m.scheduleVoiceReconnect(m.voiceReconnectAttempt)
		}
		if err := m.voiceIPC.send(ipc.Message{Cmd: ipc.CommandPing}); err != nil {
			m.errMsg = fmt.Sprintf("voice ping failed: %v", err)
			m.voiceIPC.reset()
			m.voiceReconnectAttempt++
			return m, m.scheduleVoiceReconnect(m.voiceReconnectAttempt)
		}
		return m, m.scheduleVoicePing()

	case directorySyncMsg:
		if msg.err != nil {
			if !errors.Is(msg.err, errDirectoryKeyPending) {
				m.errMsg = msg.err.Error()
			}
			return m, nil
		}
		if msg.pushed {
			m.pendingProfilePush = false
		}
		for _, profile := range msg.profiles {
			name := m.decryptDirectoryName(profile.NameEnc)
			if name != "" {
				m.userNames[profile.UserID] = name
			}
		}
		if m.sidebarVisible {
			m.refreshPresence()
		}
		return m, nil

	case directoryTick:
		if m.isTrusted() {
			return m, tea.Batch(m.syncDirectoryCmd(m.pendingProfilePush), m.scheduleDirectoryTick())
		}
		return m, nil

	case shareKeysMsg:
		if msg.err != nil {
			m.errMsg = fmt.Sprintf("share channel keys: %v", msg.err)
		}
		return m, nil

	case shareDirectoryMsg:
		if msg.err != nil {
			m.errMsg = fmt.Sprintf("share directory key: %v", msg.err)
		}
		return m, nil

	case shareTick:
		if m.connected {
			m.refreshChannels(false)
			return m, tea.Batch(m.shareKnownChannelKeysCmd(), m.scheduleShareTick())
		}
		return m, nil

	case channelRefreshTick:
		m.refreshChannels(false)
		if m.channelRefreshNeeded && m.channelRefreshRetries < channelRefreshMaxRetries {
			m.channelRefreshRetries++
			return m, m.scheduleChannelRefresh()
		}
		if !m.channelRefreshNeeded {
			m.channelRefreshRetries = 0
		}
		return m, nil

	case presenceTick:
		if m.sidebarVisible {
			m.refreshPresence()
			return m, m.schedulePresenceTick()
		}
		return m, nil

	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m *chatModel) sendCurrentMessage() tea.Cmd {
	body := strings.TrimSpace(m.input.Value())
	if body == "" || m.ws == nil {
		return nil
	}
	if strings.HasPrefix(body, "/") {
		cmd := m.handleCommand(body)
		m.input.Reset()
		return cmd
	}

	if m.activeChannel != "" {
		key, err := m.ensureChannelKey(m.activeChannel)
		if err != nil {
			m.errMsg = fmt.Sprintf("channel key: %v", err)
			return nil
		}
		encryptedBody, err := encryptChannelField(key, body)
		if err != nil {
			m.errMsg = fmt.Sprintf("encrypt channel message: %v", err)
			return nil
		}
		senderNameEnc, err := encryptChannelField(key, m.auth.Username)
		if err != nil {
			m.errMsg = fmt.Sprintf("encrypt sender name: %v", err)
			return nil
		}
		_ = m.ws.Send(SendMessage{
			Type:          "channel.message.send",
			ChannelID:     m.activeChannel,
			Body:          encryptedBody,
			SenderNameEnc: senderNameEnc,
		})
		m.input.Reset()
		return nil
	}
	m.appendSystemMessage("no global chat; select a channel with the sidebar or /channel list")
	return nil
}

func (m *chatModel) handleCommand(raw string) tea.Cmd {
	parts := strings.Fields(raw)
	if len(parts) == 0 {
		return nil
	}
	cmd := strings.ToLower(parts[0])
	if cmd == "/voice" {
		return m.handleVoiceCommand(raw, parts)
	}
	if cmd == "/help" {
		m.appendSystemMessage(m.helpText())
		return nil
	}
	if cmd == "/server" {
		if len(parts) < 2 {
			m.appendSystemMessage(m.serverHelpText())
			return nil
		}
		if !m.auth.IsAdmin {
			m.appendSystemMessage("admin only: server invites")
			return nil
		}
		action := strings.ToLower(parts[1])
		switch action {
		case "invite":
			m.createServerInvite()
		default:
			m.appendSystemMessage("unknown server command")
		}
		return nil
	}
	if cmd != "/channel" {
		m.appendSystemMessage("unknown command")
		return nil
	}
	if len(parts) < 2 {
		m.appendSystemMessage(m.channelHelpText())
		return nil
	}
	action := strings.ToLower(parts[1])

	switch action {
	case "help":
		m.appendSystemMessage(m.channelHelpText())
	case "list":
		m.refreshChannels(true)
	case "create":
		if !m.auth.IsAdmin {
			m.appendSystemMessage("admin only")
			return nil
		}
		if len(parts) < 3 {
			m.appendSystemMessage("usage: /channel create <name>")
			return nil
		}
		name := strings.TrimSpace(strings.TrimPrefix(raw, parts[0]+" "+parts[1]))
		m.createChannel(name)
	case "delete":
		if !m.auth.IsAdmin {
			m.appendSystemMessage("admin only")
			return nil
		}
		if len(parts) < 3 {
			m.appendSystemMessage("usage: /channel delete <channel_id|name>")
			return nil
		}
		nameOrID := strings.TrimSpace(strings.TrimPrefix(raw, parts[0]+" "+parts[1]))
		m.deleteChannel(nameOrID)
	case "rename":
		if !m.auth.IsAdmin {
			m.appendSystemMessage("admin only")
			return nil
		}
		remaining := strings.TrimSpace(strings.TrimPrefix(raw, parts[0]+" "+parts[1]))
		if remaining == "" {
			m.appendSystemMessage("usage: /channel rename <channel_id|name> <new name>")
			return nil
		}
		bits := strings.SplitN(remaining, " ", 2)
		if len(bits) < 2 || strings.TrimSpace(bits[1]) == "" {
			m.appendSystemMessage("usage: /channel rename <channel_id|name> <new name>")
			return nil
		}
		m.renameChannel(strings.TrimSpace(bits[0]), strings.TrimSpace(bits[1]))
	default:
		m.appendSystemMessage("unknown channel command")
	}
	return nil
}

func (m *chatModel) helpText() string {
	if m.auth.IsAdmin {
		return "commands: /help | /voice join [channel] | /voice leave | /voice mute | /voice unmute | /channel list | /channel create <name> | /channel rename <channel_id|name> <new name> | /channel delete <channel_id|name> | /server invite"
	}
	return "commands: /help | /voice join [channel] | /voice leave | /voice mute | /voice unmute | /channel list"
}

func (m *chatModel) handleVoiceEvent(msg ipc.Message) {
	switch msg.Event {
	case ipc.EventVoiceReady:
		m.appendSystemMessage("voice daemon ready")
		if msg.Room != "" && m.voiceRoom == msg.Room {
			m.voiceRoom = ""
		}
		m.clearVoiceMembers()
	case ipc.EventVoiceConnected:
		if msg.Room != "" {
			m.voiceRoom = msg.Room
		}
		m.resetVoiceMembersForRoom(m.voiceRoom)
		m.appendSystemMessage("voice connected")
	case ipc.EventVoiceMembers:
		indicatorRoom := m.voiceChannelIndicatorID()
		if indicatorRoom == "" {
			indicatorRoom = m.voiceRoom
		}
		if msg.Room != "" && indicatorRoom != "" && msg.Room != indicatorRoom {
			return
		}
		m.setVoiceMembers(msg.Users)
	case ipc.EventUserSpeaking:
		if msg.User == "" {
			return
		}
		if m.voiceSpeaking == nil {
			m.voiceSpeaking = make(map[string]bool)
		}
		m.voiceSpeaking[msg.User] = msg.Active
	case ipc.EventError:
		if msg.Error != "" {
			if m.voiceAutoStarting && isVoiceIPCNotRunning(errors.New(msg.Error)) {
				return
			}
			m.appendSystemMessage(fmt.Sprintf("voice error: %s", msg.Error))
		}
	case ipc.EventPong:
		return
	}
}

func (m *chatModel) handleVoiceCommand(raw string, parts []string) tea.Cmd {
	if len(parts) < 2 {
		m.appendSystemMessage("voice commands: /voice join [channel] | /voice leave | /voice mute | /voice unmute")
		return nil
	}
	if m.voiceIPC == nil {
		m.appendSystemMessage("voice daemon not configured")
		return nil
	}
	action := strings.ToLower(parts[1])
	switch action {
	case "join":
		room := ""
		if len(parts) > 2 {
			room = strings.TrimSpace(strings.TrimPrefix(raw, parts[0]+" "+parts[1]))
		} else {
			room = m.activeChannel
		}
		if room == "" {
			m.appendSystemMessage("usage: /voice join [channel] (or select a channel)")
			return nil
		}
		resolvedID, _, ok := m.resolveChannel(room, false)
		if !ok {
			return nil
		}
		return m.dispatchVoiceCommand(
			ipc.Message{Cmd: ipc.CommandVoiceJoin, Room: resolvedID},
			resolvedID,
			"voice join requested",
			"voice join",
		)
	case "leave":
		return m.dispatchVoiceCommand(
			ipc.Message{Cmd: ipc.CommandVoiceLeave, Room: m.voiceRoom},
			"",
			"voice leave requested",
			"voice leave",
		)
	case "mute":
		return m.dispatchVoiceCommand(
			ipc.Message{Cmd: ipc.CommandMute},
			"",
			"voice mute requested",
			"voice mute",
		)
	case "unmute":
		return m.dispatchVoiceCommand(
			ipc.Message{Cmd: ipc.CommandUnmute},
			"",
			"voice unmute requested",
			"voice unmute",
		)
	default:
		m.appendSystemMessage("voice commands: /voice join [channel] | /voice leave | /voice mute | /voice unmute")
		return nil
	}
}

func (m *chatModel) dispatchVoiceCommand(cmd ipc.Message, pendingRoom, notice, label string) tea.Cmd {
	if m.voiceIPC == nil {
		m.appendSystemMessage("voice daemon not configured")
		return nil
	}
	if err := m.voiceIPC.send(cmd); err != nil {
		m.voiceIPC.reset()
		m.voiceCh = nil
		if m.voiceAutoStart && isVoiceIPCNotRunning(err) {
			if startErr := m.startVoiceDaemon(); startErr != nil {
				m.appendSystemMessage(fmt.Sprintf("voice auto-start failed: %v", startErr))
				return nil
			}
			if m.voiceLogPath != "" && !m.voiceLogNotified {
				m.appendSystemMessage(fmt.Sprintf("voice log: %s", m.voiceLogPath))
				m.voiceLogNotified = true
			}
			m.queueVoiceCommand(cmd, pendingRoom, notice)
			m.appendSystemMessage("starting voice daemon...")
			m.voiceReconnectAttempt = 0
			return m.connectVoiceIPC()
		}
		m.appendSystemMessage(fmt.Sprintf("%s failed: %v", label, err))
		return nil
	}
	if cmd.Cmd == ipc.CommandVoiceJoin && pendingRoom != "" {
		m.voiceRoom = pendingRoom
		m.resetVoiceMembersForRoom(pendingRoom)
	}
	if notice != "" {
		m.appendSystemMessage(notice)
	}
	if m.voiceCh == nil {
		return m.connectVoiceIPC()
	}
	return nil
}

func (m *chatModel) queueVoiceCommand(cmd ipc.Message, pendingRoom, notice string) {
	m.voicePendingCmd = &cmd
	m.voicePendingRoom = pendingRoom
	m.voicePendingNotice = notice
}

func (m *chatModel) clearPendingVoiceCommand() {
	m.voicePendingCmd = nil
	m.voicePendingRoom = ""
	m.voicePendingNotice = ""
}

func (m *chatModel) channelHelpText() string {
	if m.auth.IsAdmin {
		return "channel commands: /channel list | create <name> | rename <channel_id|name> <new name> | delete <channel_id|name>"
	}
	return "channel commands: /channel list"
}

func (m *chatModel) serverHelpText() string {
	if m.auth.IsAdmin {
		return "server commands: /server invite"
	}
	return "admin only: server invites"
}

func (m *chatModel) createServerInvite() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	invite, err := m.api.CreateServerInvite(ctx, m.auth.Token)
	if err != nil {
		m.errMsg = fmt.Sprintf("server invite: %v", err)
		return
	}
	m.appendSystemMessage(fmt.Sprintf("server invite (expires %s):", formatTime(invite.ExpiresAt)))
	m.appendHighlightedMessage(invite.Token)
}

func (m *chatModel) refreshChannels(showMessage bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	channels, err := m.api.ListChannels(ctx, m.auth.Token)
	if err != nil {
		m.errMsg = fmt.Sprintf("list channels: %v", err)
		m.channelRefreshNeeded = false
		return
	}
	if len(channels) == 0 {
		if showMessage {
			m.appendSystemMessage("no channels yet")
		}
		m.channelRefreshNeeded = false
		return
	}
	needsRefresh := false
	allEncrypted := true
	for _, ch := range channels {
		if _, err := m.ensureChannelKey(ch.ID); err != nil {
			needsRefresh = true
		}
		name := m.decryptChannelName(ch.ID, ch.NameEnc)
		if name == "<encrypted>" {
			needsRefresh = true
		} else {
			allEncrypted = false
		}
		m.channels[ch.ID] = channelInfo{ID: ch.ID, Name: name}
	}
	if showMessage {
		var b strings.Builder
		b.WriteString("channels:")
		for _, ch := range channels {
			name := m.decryptChannelName(ch.ID, ch.NameEnc)
			b.WriteString("\n  ")
			b.WriteString(name)
			b.WriteString(" (")
			b.WriteString(shortID(ch.ID))
			b.WriteString(")")
		}
		m.appendSystemMessage(b.String())
		if allEncrypted {
			m.appendSystemMessage("All channels are <encrypted> because no other online user has shared channel keys yet. They will decrypt once another user comes online and shares keys (or an admin re-shares them).")
		}
	}
	m.ensureSidebarIndex()
	m.channelRefreshNeeded = needsRefresh
}

func (m *chatModel) createChannel(name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	key, err := generateChannelKey()
	if err != nil {
		m.errMsg = fmt.Sprintf("generate channel key: %v", err)
		return
	}
	nameEnc, err := encryptChannelField(key, name)
	if err != nil {
		m.errMsg = fmt.Sprintf("encrypt channel name: %v", err)
		return
	}
	created, err := m.api.CreateChannel(ctx, m.auth.Token, nameEnc)
	if err != nil {
		m.errMsg = fmt.Sprintf("create channel: %v", err)
		return
	}
	m.setChannelKey(created.ID, key)
	if err := m.persistChannelKeys(); err != nil {
		m.errMsg = fmt.Sprintf("save channel key: %v", err)
	}
	if err := m.shareChannelKey(created.ID); err != nil {
		m.errMsg = fmt.Sprintf("share channel key: %v", err)
	}
	info := channelInfo{ID: created.ID, Name: name}
	m.channels[created.ID] = info
	m.activeChannel = created.ID
	m.ensureSidebarIndex()
	m.appendSystemMessage(fmt.Sprintf("created channel '%s' (%s)", name, shortID(created.ID)))
	m.refreshViewport()
}

func (m *chatModel) shareChannelKey(channelID string) error {
	if channelID == "" {
		return fmt.Errorf("missing channel id")
	}
	key := m.getChannelKey(channelID)
	if len(key) != crypto.KeySize {
		return fmt.Errorf("missing channel key")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	devices, err := m.api.ListAllDeviceKeys(ctx, m.auth.Token)
	if err != nil {
		return err
	}
	if len(devices) == 0 {
		return fmt.Errorf("no devices available")
	}
	envelopes, err := buildChannelKeyEnvelopes(m.kp, m.auth.DeviceID, key, devices)
	if err != nil {
		return err
	}
	if len(envelopes) == 0 {
		return fmt.Errorf("no valid devices for key share")
	}

	return m.api.PutChannelKeyEnvelopes(ctx, m.auth.Token, channelID, envelopes)
}

func (m *chatModel) shareKnownChannelKeysCmd() tea.Cmd {
	if len(m.channelKeys) == 0 {
		return nil
	}
	return func() tea.Msg {
		return shareKeysMsg{err: m.shareKnownChannelKeys()}
	}
}

func (m *chatModel) shareKnownChannelKeys() error {
	if m.api == nil || m.auth == nil || m.kp == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	channels, err := m.api.ListChannels(ctx, m.auth.Token)
	if err != nil {
		return err
	}
	allowed := make(map[string]struct{}, len(channels))
	for _, ch := range channels {
		allowed[ch.ID] = struct{}{}
	}
	devices, err := m.api.ListAllDeviceKeys(ctx, m.auth.Token)
	if err != nil {
		return err
	}
	if len(devices) == 0 {
		return nil
	}
	for channelID, key := range m.channelKeys {
		if channelID == "" || len(key) != crypto.KeySize {
			continue
		}
		if _, ok := allowed[channelID]; !ok {
			delete(m.channelKeys, channelID)
			continue
		}
		envelopes, err := buildChannelKeyEnvelopes(m.kp, m.auth.DeviceID, key, devices)
		if err != nil {
			return err
		}
		if len(envelopes) == 0 {
			continue
		}
		if err := m.api.PutChannelKeyEnvelopes(ctx, m.auth.Token, channelID, envelopes); err != nil {
			return err
		}
	}
	return m.persistChannelKeys()
}

func (m *chatModel) shareDirectoryKeyCmd() tea.Cmd {
	if !m.isTrusted() || len(m.directoryKey) != crypto.KeySize {
		return nil
	}
	return func() tea.Msg {
		return shareDirectoryMsg{err: m.shareDirectoryKey()}
	}
}

func (m *chatModel) shareDirectoryKey() error {
	if m.api == nil || m.auth == nil || m.kp == nil {
		return nil
	}
	if len(m.directoryKey) != crypto.KeySize {
		return fmt.Errorf("missing directory key")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	devices, err := m.api.ListAllDeviceKeys(ctx, m.auth.Token)
	if err != nil {
		return err
	}
	if len(devices) == 0 {
		return nil
	}
	envelopes, err := buildDirectoryKeyEnvelopes(m.kp, m.auth.DeviceID, m.directoryKey, devices)
	if err != nil {
		return err
	}
	if len(envelopes) == 0 {
		return nil
	}
	return m.api.PutDirectoryKeyEnvelopes(ctx, m.auth.Token, envelopes)
}

func (m *chatModel) syncDirectoryCmd(pushProfile bool) tea.Cmd {
	if !m.isTrusted() {
		return nil
	}
	return func() tea.Msg {
		profiles, pushed, err := m.syncDirectory(pushProfile)
		return directorySyncMsg{profiles: profiles, pushed: pushed, err: err}
	}
}

func (m *chatModel) syncDirectory(pushProfile bool) ([]UserProfile, bool, error) {
	key, err := m.ensureDirectoryKey()
	if err != nil {
		return nil, false, err
	}
	if m.auth == nil {
		return nil, false, fmt.Errorf("missing auth")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if pushProfile {
		nameEnc, err := encryptChannelField(key, m.auth.Username)
		if err != nil {
			return nil, false, fmt.Errorf("encrypt username: %w", err)
		}
		if err := m.api.UpsertUserProfile(ctx, m.auth.Token, nameEnc); err != nil {
			return nil, false, err
		}
	}
	profiles, err := m.api.ListUserProfiles(ctx, m.auth.Token)
	if err != nil {
		return nil, false, err
	}
	return profiles, pushProfile, nil
}

func (m *chatModel) ensureDirectoryKey() ([]byte, error) {
	if len(m.directoryKey) == crypto.KeySize {
		return m.directoryKey, nil
	}
	if m.api == nil || m.auth == nil || m.kp == nil {
		return nil, fmt.Errorf("missing directory key dependencies")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	env, err := m.api.GetDirectoryKeyEnvelope(ctx, m.auth.Token)
	if err == nil {
		senderPub, err := crypto.PublicKeyFromBase64(env.SenderPublicKey)
		if err != nil {
			return nil, fmt.Errorf("invalid sender public key: %v", err)
		}
		key, err := crypto.DecryptFromPeer(m.kp.Private, senderPub, env.Envelope)
		if err != nil {
			return nil, fmt.Errorf("decrypt directory key: %v", err)
		}
		if len(key) != crypto.KeySize {
			return nil, fmt.Errorf("invalid directory key size")
		}
		m.setDirectoryKey(key)
		if err := m.persistDirectoryKey(); err != nil {
			return nil, err
		}
		return key, nil
	}
	if !isNotFoundErr(err) {
		return nil, err
	}

	profiles, listErr := m.api.ListUserProfiles(ctx, m.auth.Token)
	if listErr == nil && len(profiles) > 0 {
		return nil, errDirectoryKeyPending
	}

	key, err := generateChannelKey()
	if err != nil {
		return nil, err
	}
	m.setDirectoryKey(key)
	if err := m.persistDirectoryKey(); err != nil {
		return nil, err
	}
	if err := m.shareDirectoryKey(); err != nil {
		return nil, err
	}
	return key, nil
}

func (m *chatModel) setDirectoryKey(key []byte) {
	if len(key) != crypto.KeySize {
		return
	}
	stored := make([]byte, len(key))
	copy(stored, key)
	m.directoryKey = stored
}

func (m *chatModel) persistDirectoryKey() error {
	return saveDirectoryKey(m.directoryKey, m.keystorePassphrase)
}

func (m *chatModel) scheduleDirectoryTick() tea.Cmd {
	return tea.Tick(10*time.Second, func(time.Time) tea.Msg {
		return directoryTick{}
	})
}

func (m *chatModel) deleteChannel(nameOrID string) {
	resolvedID, info, ok := m.resolveChannel(nameOrID, false)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := m.api.DeleteChannel(ctx, m.auth.Token, resolvedID); err != nil {
		m.errMsg = fmt.Sprintf("delete channel: %v", err)
		return
	}
	delete(m.channels, resolvedID)
	delete(m.channelMsgs, resolvedID)
	delete(m.channelHistoryLoaded, resolvedID)
	delete(m.channelUnread, resolvedID)
	if m.activeChannel == resolvedID {
		m.activeChannel = ""
	}
	m.ensureSidebarIndex()
	if info.Name != "" {
		m.appendSystemMessage(fmt.Sprintf("deleted channel '%s'", info.Name))
		return
	}
	m.appendSystemMessage(fmt.Sprintf("deleted channel '%s'", shortID(resolvedID)))
}

func (m *chatModel) renameChannel(nameOrID, newName string) {
	resolvedID, info, ok := m.resolveChannel(nameOrID, false)
	if !ok {
		return
	}
	key, err := m.ensureChannelKey(resolvedID)
	if err != nil {
		m.errMsg = fmt.Sprintf("channel key: %v", err)
		return
	}
	nameEnc, err := encryptChannelField(key, newName)
	if err != nil {
		m.errMsg = fmt.Sprintf("encrypt channel name: %v", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	updated, err := m.api.UpdateChannelName(ctx, m.auth.Token, resolvedID, nameEnc)
	if err != nil {
		m.errMsg = fmt.Sprintf("rename channel: %v", err)
		return
	}
	name := m.decryptChannelName(updated.ID, updated.NameEnc)
	m.channels[resolvedID] = channelInfo{ID: resolvedID, Name: name}
	m.ensureSidebarIndex()
	if info.Name != "" {
		m.appendSystemMessage(fmt.Sprintf("renamed channel '%s' to '%s'", info.Name, name))
		return
	}
	m.appendSystemMessage(fmt.Sprintf("renamed channel '%s'", shortID(resolvedID)))
}
func (m *chatModel) useChannel(channelID string) {
	resolvedID, info, ok := m.resolveChannel(channelID, true)
	if !ok {
		return
	}
	if resolvedID == m.activeChannel {
		m.appendSystemMessage("already viewing that channel")
		return
	}
	m.applyChannelSelection(resolvedID, info)
}

func (m *chatModel) loadChannelHistory(channelID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := m.ensureChannelKey(channelID); err != nil {
		m.errMsg = fmt.Sprintf("channel key: %v", err)
		return
	}
	msgs, err := m.api.ListChannelMessages(ctx, m.auth.Token, channelID, 100)
	if err != nil {
		m.errMsg = fmt.Sprintf("channel history: %v", err)
		return
	}
	if len(msgs) == 0 {
		m.channelHistoryLoaded[channelID] = true
		return
	}

	loaded := make([]chatMessage, 0, len(msgs))
	for _, msg := range msgs {
		senderName := m.decryptChannelField(channelID, msg.SenderNameEnc)
		body := m.decryptChannelField(channelID, msg.Body)
		if senderName != "" {
			m.userNames[msg.SenderID] = senderName
		}
		loaded = append(loaded, chatMessage{
			sender:     msg.SenderID,
			senderName: senderName,
			body:       body,
			sentAt:     msg.SentAt,
			isHistory:  true,
			isMine:     msg.SenderID == m.auth.UserID,
		})
	}

	if existing := m.channelMsgs[channelID]; len(existing) > 0 {
		loaded = append(loaded, existing...)
	}
	m.channelMsgs[channelID] = loaded
	m.channelHistoryLoaded[channelID] = true
	m.channelUnread[channelID] = 0
}

func (m *chatModel) resolveChannel(nameOrID string, allowSelect bool) (string, channelInfo, bool) {
	if nameOrID == "" {
		m.appendSystemMessage("channel id or name is required")
		return "", channelInfo{}, false
	}
	if info, ok := m.channels[nameOrID]; ok {
		return nameOrID, info, true
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	channels, err := m.api.ListChannels(ctx, m.auth.Token)
	if err != nil {
		m.errMsg = fmt.Sprintf("list channels: %v", err)
		return "", channelInfo{}, false
	}
	if len(channels) == 0 {
		m.appendSystemMessage("no channels available")
		return "", channelInfo{}, false
	}
	for _, ch := range channels {
		_, _ = m.ensureChannelKey(ch.ID)
		name := m.decryptChannelName(ch.ID, ch.NameEnc)
		m.channels[ch.ID] = channelInfo{ID: ch.ID, Name: name}
	}

	needle := strings.ToLower(strings.TrimSpace(nameOrID))
	var matches []channelInfo
	for _, ch := range channels {
		name := m.decryptChannelName(ch.ID, ch.NameEnc)
		if strings.ToLower(name) == needle {
			matches = append(matches, channelInfo{ID: ch.ID, Name: name})
		}
	}
	if len(matches) == 0 {
		for _, ch := range channels {
			if strings.HasPrefix(strings.ToLower(ch.ID), needle) {
				name := m.decryptChannelName(ch.ID, ch.NameEnc)
				matches = append(matches, channelInfo{ID: ch.ID, Name: name})
			}
		}
	}
	if len(matches) == 0 {
		m.appendSystemMessage("unknown channel name")
		return "", channelInfo{}, false
	}
	if len(matches) > 1 {
		if allowSelect {
			m.startChannelSelection(matches)
			return "", channelInfo{}, false
		}
		var b strings.Builder
		b.WriteString("multiple channels match; use an id:\n")
		for _, match := range matches {
			b.WriteString("  ")
			b.WriteString(match.Name)
			b.WriteString(" (")
			b.WriteString(match.ID)
			b.WriteString(")\n")
		}
		m.appendSystemMessage(b.String())
		return "", channelInfo{}, false
	}
	return matches[0].ID, matches[0], true
}

func (m *chatModel) startChannelSelection(options []channelInfo) {
	if len(options) == 0 {
		return
	}
	m.selectActive = true
	m.selectOptions = options
	m.selectIndex = 0
	m.updateLayout()
}

func (m *chatModel) handleChannelSelectKey(msg tea.KeyMsg) {
	switch msg.String() {
	case "up", "k":
		if m.selectIndex > 0 {
			m.selectIndex--
		}
	case "down", "j":
		if m.selectIndex < len(m.selectOptions)-1 {
			m.selectIndex++
		}
	case "enter":
		if len(m.selectOptions) == 0 {
			m.selectActive = false
			m.updateLayout()
			return
		}
		selected := m.selectOptions[m.selectIndex]
		m.selectActive = false
		m.updateLayout()
		m.applyChannelSelection(selected.ID, selected)
	case "esc":
		m.selectActive = false
		m.updateLayout()
		m.appendSystemMessage("channel selection canceled")
	}
}

func (m *chatModel) applyChannelSelection(channelID string, info channelInfo) {
	if channelID == m.activeChannel {
		m.appendSystemMessage("already viewing that channel")
		return
	}
	m.activeChannel = channelID
	if !m.channelHistoryLoaded[channelID] {
		m.loadChannelHistory(channelID)
	}
	m.channelUnread[channelID] = 0
	m.ensureSidebarIndex()
	m.updateLayout()
	m.appendSystemMessage(fmt.Sprintf("now chatting in '%s'", info.Name))
	m.refreshViewport()
}

func (m *chatModel) appendSystemMessage(text string) {
	msg := chatMessage{senderName: "system", body: text, sentAt: time.Now().UTC().Format(time.RFC3339Nano), isSystem: true}
	if m.activeChannel != "" {
		m.channelMsgs[m.activeChannel] = append(m.channelMsgs[m.activeChannel], msg)
		m.refreshViewport()
		return
	}
	m.messages = append(m.messages, msg)
	m.refreshViewport()
}

func (m *chatModel) appendHighlightedMessage(text string) {
	msg := chatMessage{senderName: "system", body: text, sentAt: time.Now().UTC().Format(time.RFC3339Nano), isSystem: true, highlight: true}
	if m.activeChannel != "" {
		m.channelMsgs[m.activeChannel] = append(m.channelMsgs[m.activeChannel], msg)
		m.refreshViewport()
		return
	}
	m.messages = append(m.messages, msg)
	m.refreshViewport()
}

func (m *chatModel) handleServerMessage(msg ServerMessage) {
	switch msg.Type {
	case "channel.message.new":
		senderName := m.decryptChannelField(msg.ChannelID, msg.SenderNameEnc)
		body := m.decryptChannelField(msg.ChannelID, msg.Body)
		if senderName != "" {
			m.userNames[msg.Sender] = senderName
		}
		cm := chatMessage{
			sender:     msg.Sender,
			senderName: senderName,
			body:       body,
			sentAt:     msg.SentAt,
			isHistory:  false,
			isMine:     msg.Sender == m.auth.UserID,
		}
		channelID := msg.ChannelID
		m.channelMsgs[channelID] = append(m.channelMsgs[channelID], cm)
		if channelID != m.activeChannel {
			m.channelUnread[channelID] = m.channelUnread[channelID] + 1
		} else {
			m.channelUnread[channelID] = 0
		}
		if m.sidebarVisible {
			m.refreshPresence()
		}

	case "channel.updated":
		if msg.ChannelID == "" {
			return
		}
		prev := m.channels[msg.ChannelID]
		_, _ = m.ensureChannelKey(msg.ChannelID)
		name := m.decryptChannelName(msg.ChannelID, msg.ChannelNameEnc)
		m.channels[msg.ChannelID] = channelInfo{ID: msg.ChannelID, Name: name}
		if m.activeChannel == msg.ChannelID && name != "" && prev.Name != "" && prev.Name != name {
			m.appendSystemMessage(fmt.Sprintf("channel renamed to '%s'", name))
		}
		m.ensureSidebarIndex()
		m.refreshViewport()

	case "channel.deleted":
		if msg.ChannelID == "" {
			return
		}
		info := m.channels[msg.ChannelID]
		delete(m.channels, msg.ChannelID)
		delete(m.channelMsgs, msg.ChannelID)
		delete(m.channelHistoryLoaded, msg.ChannelID)
		delete(m.channelUnread, msg.ChannelID)
		delete(m.channelKeys, msg.ChannelID)
		_ = m.persistChannelKeys()
		if m.activeChannel == msg.ChannelID {
			m.activeChannel = ""
			if info.Name != "" {
				m.appendSystemMessage(fmt.Sprintf("channel '%s' was deleted", info.Name))
			} else {
				m.appendSystemMessage("channel was deleted")
			}
		}
		m.ensureSidebarIndex()
		m.refreshViewport()

	case "error":
		m.errMsg = fmt.Sprintf("[%s] %s", msg.Code, msg.Message)
	}
}

func (m *chatModel) refreshViewport() {
	m.viewport.SetContent(m.renderMessages())
	m.viewport.GotoBottom()
}

func (m *chatModel) updateLayout() {
	width := m.width - 4
	if !m.selectActive && m.sidebarVisible {
		width -= sidebarWidth
	}
	m.viewport.Width = clampMin(width, 10)
	m.viewport.Height = clampMin(m.height-7, 1)
	m.input.Width = clampMin(m.width-8, 20)
}

func (m *chatModel) renderMessages() string {
	msgs := m.messages
	if m.activeChannel != "" {
		msgs = m.channelMsgs[m.activeChannel]
	}
	if len(msgs) == 0 {
		if m.activeChannel == "" {
			return labelStyle.Render("  No channel selected. Use the sidebar or /channel list.")
		}
		return labelStyle.Render("  No messages yet. Send one to start chatting!")
	}

	var b strings.Builder
	for _, msg := range msgs {
		ts := formatTime(msg.sentAt)
		sender := m.auth.Username
		if sender == "" {
			if cached, ok := m.userNames[m.auth.UserID]; ok {
				sender = cached
			}
		}
		if !msg.isMine {
			if msg.senderName != "" {
				sender = msg.senderName
			} else {
				sender = shortID(msg.sender)
			}
		}
		if msg.isSystem {
			sender = "system"
		} else {
			sender = formatUsername(sender)
		}

		var style lipgloss.Style
		switch {
		case msg.highlight:
			style = inviteTokenStyle
		case msg.isSystem:
			style = labelStyle
		case msg.isHistory:
			style = historyMsgStyle
		case msg.isMine:
			style = sentMsgStyle
		default:
			style = recvMsgStyle
		}
		lines := formatMessageLines(ts, sender, msg.body, m.viewport.Width, msg.isSystem)
		for _, line := range lines {
			b.WriteString(style.Render(line))
			b.WriteString("\n")
		}
	}
	return b.String()
}

func (m *chatModel) renderSidebar() string {
	lines := make([]string, 0, 20)
	lines = append(lines, sidebarTitleStyle.Render("Channels"), "")
	channels := m.channelList()
	voiceChannelID := m.voiceChannelIndicatorID()
	if len(channels) == 0 {
		lines = append(lines, labelStyle.Render("(none)"))
	} else {
		for i, ch := range channels {
			prefix := "  "
			if i == m.sidebarIndex {
				prefix = "> "
			}
			name := ch.Name
			if name == "" {
				name = shortID(ch.ID)
			}
			markers := ""
			if ch.ID == m.activeChannel {
				markers += "* "
			}
			if ch.ID == voiceChannelID {
				markers += "♪ "
			}
			if markers != "" {
				name = markers + name
			}
			unread := m.channelUnread[ch.ID]
			if unread > 0 && ch.ID != m.activeChannel {
				name = fmt.Sprintf("%s (%d)", name, unread)
			}
			lines = append(lines, fmt.Sprintf("%s%s", prefix, name))
		}
	}

	lines = append(lines, "", sidebarTitleStyle.Render("In Voice"), "")
	if voiceChannelID == "" {
		lines = append(lines, labelStyle.Render("(not connected)"))
	} else {
		lines = append(lines, subtitleStyle.Render(m.channelDisplayName(voiceChannelID)))
		members := m.voiceMemberEntries()
		if len(members) == 0 {
			lines = append(lines, labelStyle.Render("(none)"))
		} else {
			for _, entry := range members {
				style := sidebarOfflineStyle
				if entry.ID == m.auth.UserID || (entry.Known && entry.Online) {
					style = sidebarOnlineStyle
				}
				name := formatUsername(entry.Name)
				if entry.ID == m.auth.UserID {
					name = fmt.Sprintf("%s (you)", name)
				}
				if entry.Speak {
					name = fmt.Sprintf("+ %s", name)
				}
				if entry.Admin {
					name = fmt.Sprintf("%s (admin)", name)
				}
				lines = append(lines, style.Render(name))
			}
		}
	}

	lines = append(lines, "", sidebarTitleStyle.Render("Users"), "")
	var users []userEntry
	if m.isTrusted() {
		users = m.allUserEntries()
	} else if m.activeChannel != "" {
		users = m.channelUserEntries(m.activeChannel)
	}
	if !m.isTrusted() && m.activeChannel == "" {
		lines = append(lines, labelStyle.Render("(no channel)"))
	} else if len(users) == 0 {
		lines = append(lines, labelStyle.Render("(none)"))
	} else {
		for _, entry := range users {
			style := sidebarOfflineStyle
			if entry.Known && entry.Online {
				style = sidebarOnlineStyle
			}
			name := formatUsername(entry.Name)
			if entry.Speak {
				name = fmt.Sprintf("+ %s", name)
			}
			if entry.Admin {
				name = fmt.Sprintf("%s (admin)", name)
			}
			lines = append(lines, style.Render(name))
		}
	}

	content := strings.Join(lines, "\n")
	return sidebarBoxStyle.Width(sidebarWidth).Render(content)
}

func (m *chatModel) channelList() []channelInfo {
	list := make([]channelInfo, 0, len(m.channels))
	for _, ch := range m.channels {
		list = append(list, ch)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Name == list[j].Name {
			return list[i].ID < list[j].ID
		}
		return list[i].Name < list[j].Name
	})
	return list
}

func (m *chatModel) voiceMemberEntries() []userEntry {
	if len(m.voiceMembers) == 0 {
		return nil
	}
	entries := make([]userEntry, 0, len(m.voiceMembers))
	for id := range m.voiceMembers {
		status, ok := m.userPresence[id]
		if m.auth != nil && id == m.auth.UserID {
			status = true
			ok = true
		}
		entries = append(entries, userEntry{
			ID:     id,
			Name:   m.userDisplayName(id),
			Online: status,
			Known:  ok,
			Admin:  m.userAdmins[id],
			Speak:  m.voiceSpeaking[id],
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Name == entries[j].Name {
			return entries[i].ID < entries[j].ID
		}
		return entries[i].Name < entries[j].Name
	})
	return entries
}

func (m *chatModel) channelUserEntries(channelID string) []userEntry {
	if channelID == "" {
		return nil
	}
	seen := make(map[string]string)
	for _, msg := range m.channelMsgs[channelID] {
		if msg.isSystem || msg.sender == "" {
			continue
		}
		name := msg.senderName
		if name == "" {
			if cached := m.userNames[msg.sender]; cached != "" {
				name = cached
			} else {
				name = shortID(msg.sender)
			}
		}
		seen[msg.sender] = name
	}
	entries := make([]userEntry, 0, len(seen))
	for id, name := range seen {
		status, ok := m.userPresence[id]
		admin := m.userAdmins[id]
		entries = append(entries, userEntry{ID: id, Name: name, Online: status, Known: ok, Admin: admin, Speak: m.voiceSpeaking[id]})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Name == entries[j].Name {
			return entries[i].ID < entries[j].ID
		}
		return entries[i].Name < entries[j].Name
	})
	return entries
}

func (m *chatModel) channelUserIDs(channelID string) []string {
	if channelID == "" {
		return nil
	}
	seen := make(map[string]struct{})
	for _, msg := range m.channelMsgs[channelID] {
		if msg.isSystem || msg.sender == "" {
			continue
		}
		seen[msg.sender] = struct{}{}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (m *chatModel) allUserEntries() []userEntry {
	seen := make(map[string]string)
	addUser := func(id, name string) {
		id = strings.TrimSpace(id)
		if id == "" {
			return
		}
		if name == "" {
			if cached := m.userNames[id]; cached != "" {
				name = cached
			} else {
				name = shortID(id)
			}
		}
		if _, ok := seen[id]; ok {
			return
		}
		seen[id] = name
	}

	if m.auth != nil && m.auth.UserID != "" {
		name := m.auth.Username
		if name == "" {
			name = m.userNames[m.auth.UserID]
		}
		addUser(m.auth.UserID, name)
	}

	for _, msgs := range m.channelMsgs {
		for _, msg := range msgs {
			if msg.isSystem || msg.sender == "" {
				continue
			}
			addUser(msg.sender, msg.senderName)
		}
	}

	for id, name := range m.userNames {
		addUser(id, name)
	}

	entries := make([]userEntry, 0, len(seen))
	for id, name := range seen {
		status, ok := m.userPresence[id]
		admin := m.userAdmins[id]
		entries = append(entries, userEntry{ID: id, Name: name, Online: status, Known: ok, Admin: admin, Speak: m.voiceSpeaking[id]})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Name == entries[j].Name {
			return entries[i].ID < entries[j].ID
		}
		return entries[i].Name < entries[j].Name
	})
	return entries
}

func (m *chatModel) allUserIDs() []string {
	seen := make(map[string]struct{})
	addUser := func(id string) {
		id = strings.TrimSpace(id)
		if id == "" {
			return
		}
		seen[id] = struct{}{}
	}

	if m.auth != nil {
		addUser(m.auth.UserID)
	}
	for id := range m.userNames {
		addUser(id)
	}
	for _, msgs := range m.channelMsgs {
		for _, msg := range msgs {
			if msg.isSystem || msg.sender == "" {
				continue
			}
			addUser(msg.sender)
		}
	}

	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (m *chatModel) refreshPresence() {
	var ids []string
	if m.isTrusted() {
		ids = m.allUserIDs()
	} else {
		if m.activeChannel == "" {
			return
		}
		ids = m.channelUserIDs(m.activeChannel)
	}
	if len(ids) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	statuses, admins, err := m.api.FetchPresence(ctx, m.auth.Token, ids)
	if err != nil {
		m.errMsg = fmt.Sprintf("presence: %v", err)
		return
	}
	for id, status := range statuses {
		m.userPresence[id] = status
	}
	for id, admin := range admins {
		m.userAdmins[id] = admin
	}
}

func (m *chatModel) schedulePresenceTick() tea.Cmd {
	return tea.Tick(5*time.Second, func(time.Time) tea.Msg {
		return presenceTick{}
	})
}

func (m *chatModel) scheduleVoicePing() tea.Cmd {
	return tea.Tick(15*time.Second, func(time.Time) tea.Msg {
		return voicePingTick{}
	})
}

func (m *chatModel) scheduleVoiceReconnect(attempt int) tea.Cmd {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 5 {
		attempt = 5
	}
	delay := time.Duration(1<<attempt) * time.Second
	return tea.Tick(delay, func(time.Time) tea.Msg {
		return voiceReconnectTick{}
	})
}

func (m *chatModel) scheduleShareTick() tea.Cmd {
	return tea.Tick(shareKeysInterval, func(time.Time) tea.Msg {
		return shareTick{}
	})
}

func (m *chatModel) scheduleChannelRefresh() tea.Cmd {
	return tea.Tick(channelRefreshDelay, func(time.Time) tea.Msg {
		return channelRefreshTick{}
	})
}

func (m *chatModel) moveSidebarSelection(delta int) {
	channels := m.channelList()
	if len(channels) == 0 {
		m.sidebarIndex = 0
		return
	}
	idx := m.sidebarIndex + delta
	if idx < 0 {
		idx = 0
	}
	if idx >= len(channels) {
		idx = len(channels) - 1
	}
	m.sidebarIndex = idx
}

func (m *chatModel) selectSidebarChannel() bool {
	channels := m.channelList()
	if len(channels) == 0 {
		return false
	}
	if m.sidebarIndex < 0 || m.sidebarIndex >= len(channels) {
		return false
	}
	selected := channels[m.sidebarIndex]
	if selected.ID == m.activeChannel {
		m.appendSystemMessage("already viewing that channel")
		return true
	}
	m.applyChannelSelection(selected.ID, selected)
	return true
}

func (m *chatModel) ensureSidebarIndex() {
	channels := m.channelList()
	if len(channels) == 0 {
		m.sidebarIndex = 0
		return
	}
	if m.activeChannel == "" {
		if m.sidebarIndex >= len(channels) {
			m.sidebarIndex = 0
		}
		return
	}
	for i, ch := range channels {
		if ch.ID == m.activeChannel {
			m.sidebarIndex = i
			return
		}
	}
}
func (m *chatModel) renderChannelSelectionModal() string {
	if len(m.selectOptions) == 0 {
		return ""
	}

	lines := make([]string, 0, len(m.selectOptions)+3)
	lines = append(lines, "Select a channel", "")
	for i, option := range m.selectOptions {
		prefix := "  "
		if i == m.selectIndex {
			prefix = "> "
		}
		lines = append(lines, fmt.Sprintf("%s%s (%s)", prefix, option.Name, shortID(option.ID)))
	}
	lines = append(lines, "", "enter: select  esc: cancel")

	availableWidth := clampMin(m.width-4, 20)
	maxContentWidth := availableWidth - 4
	if maxContentWidth < 10 {
		maxContentWidth = 10
	}
	maxLen := 0
	for i, line := range lines {
		trimmed := trimLine(line, maxContentWidth)
		lines[i] = trimmed
		if len(trimmed) > maxLen {
			maxLen = len(trimmed)
		}
	}
	boxWidth := maxLen + 4
	if boxWidth > availableWidth {
		boxWidth = availableWidth
		maxContentWidth = boxWidth - 4
		for i, line := range lines {
			lines[i] = trimLine(line, maxContentWidth)
		}
	}

	var b strings.Builder
	border := strings.Repeat("-", boxWidth-2)
	b.WriteString("+")
	b.WriteString(border)
	b.WriteString("+\n")
	for _, line := range lines {
		padding := maxContentWidth - len(line)
		if padding < 0 {
			padding = 0
		}
		b.WriteString("| ")
		b.WriteString(line)
		b.WriteString(strings.Repeat(" ", padding))
		b.WriteString(" |\n")
	}
	b.WriteString("+")
	b.WriteString(border)
	b.WriteString("+")

	return lipgloss.Place(availableWidth, m.viewport.Height, lipgloss.Center, lipgloss.Center, b.String())
}

func (m chatModel) View() string {
	var b strings.Builder

	header := fmt.Sprintf(
		"  %s  %s  %s  %s  %s",
		appNameStyle.Render("* dialtone"),
		headerStyle.Render(formatUsername(m.auth.Username)),
		labelStyle.Render(shortID(m.auth.UserID)),
		labelStyle.Render(m.activeChannelLabel()),
		labelStyle.Render(m.voiceStatusLabel()),
	)
	connStatus := connectedStyle.Render("online")
	if !m.connected {
		connStatus = disconnectedStyle.Render("offline")
	}
	gap := max(1, m.width-lipgloss.Width(header)-lipgloss.Width(connStatus)-2)
	b.WriteString(header + strings.Repeat(" ", gap) + connStatus)
	b.WriteString("\n")

	b.WriteString(separator(m.width))
	b.WriteString("\n")

	chatContent := m.viewport.View()
	if m.selectActive {
		chatContent = m.renderChannelSelectionModal()
	} else if m.sidebarVisible {
		chatContent = lipgloss.JoinHorizontal(lipgloss.Top, m.viewport.View(), m.renderSidebar())
	}
	b.WriteString(chatContent)
	b.WriteString("\n")

	b.WriteString(separator(m.width))
	b.WriteString("\n")

	inputLabel := activeInputStyle.Render("  > ")
	b.WriteString(inputLabel + m.input.View())
	b.WriteString("\n")

	if m.errMsg != "" {
		b.WriteString(errorStyle.Render("  x " + m.errMsg))
	} else {
		b.WriteString(helpStyle.Render("  enter: send - /help for commands - up/down+enter (empty): switch channel - ctrl+u: focus users/channels - pgup/pgdn: scroll - ctrl+h: toggle sidebar - ctrl+q: quit"))
	}

	return b.String()
}

func (m *chatModel) activeChannelLabel() string {
	if m.activeChannel == "" {
		return "no channel"
	}
	return "channel: " + m.channelDisplayName(m.activeChannel)
}

func (m *chatModel) voiceStatusLabel() string {
	if m.voicePendingCmd != nil {
		switch m.voicePendingCmd.Cmd {
		case ipc.CommandVoiceJoin:
			if channelID := m.voiceChannelIndicatorID(); channelID != "" {
				return "voice: connecting " + m.channelDisplayName(channelID)
			}
			return "voice: connecting"
		case ipc.CommandVoiceLeave:
			if m.voiceRoom != "" {
				return "voice: leaving " + m.channelDisplayName(m.voiceRoom)
			}
			return "voice: leaving"
		default:
			if m.voiceRoom != "" {
				return "voice: " + m.channelDisplayName(m.voiceRoom)
			}
			return "voice: updating"
		}
	}
	if m.voiceAutoStarting {
		if channelID := m.voiceChannelIndicatorID(); channelID != "" {
			return "voice: starting " + m.channelDisplayName(channelID)
		}
		return "voice: starting"
	}
	if m.voiceRoom != "" {
		return "voice: " + m.channelDisplayName(m.voiceRoom)
	}
	if m.voiceCh == nil && m.voiceReconnectAttempt > 0 {
		return "voice: reconnecting"
	}
	return "voice: off"
}

func (m *chatModel) voiceChannelIndicatorID() string {
	if m.voiceRoom != "" {
		return m.voiceRoom
	}
	if m.voicePendingCmd != nil && m.voicePendingCmd.Cmd == ipc.CommandVoiceJoin {
		if m.voicePendingRoom != "" {
			return m.voicePendingRoom
		}
		if m.voicePendingCmd.Room != "" {
			return m.voicePendingCmd.Room
		}
	}
	return ""
}

func (m *chatModel) channelDisplayName(channelID string) string {
	if channelID == "" {
		return ""
	}
	if info, ok := m.channels[channelID]; ok {
		name := strings.TrimSpace(info.Name)
		if name != "" {
			return name
		}
	}
	return shortID(channelID)
}

func (m *chatModel) setVoiceMembers(users []string) {
	if m.voiceMembers == nil {
		m.voiceMembers = make(map[string]bool)
	}
	clear(m.voiceMembers)
	for _, userID := range users {
		id := strings.TrimSpace(userID)
		if id == "" {
			continue
		}
		m.voiceMembers[id] = true
	}
	if m.auth != nil && m.auth.UserID != "" && m.voiceRoom != "" {
		m.voiceMembers[m.auth.UserID] = true
	}
}

func (m *chatModel) resetVoiceMembersForRoom(room string) {
	if room == "" {
		m.clearVoiceMembers()
		return
	}
	if m.voiceMembers == nil {
		m.voiceMembers = make(map[string]bool)
	}
	clear(m.voiceMembers)
	if m.auth != nil && m.auth.UserID != "" {
		m.voiceMembers[m.auth.UserID] = true
	}
}

func (m *chatModel) clearVoiceMembers() {
	if m.voiceMembers == nil {
		m.voiceMembers = make(map[string]bool)
		return
	}
	clear(m.voiceMembers)
}

func (m *chatModel) userDisplayName(userID string) string {
	if userID == "" {
		return ""
	}
	if m.auth != nil && userID == m.auth.UserID {
		if name := strings.TrimSpace(m.auth.Username); name != "" {
			return name
		}
	}
	if name := strings.TrimSpace(m.userNames[userID]); name != "" {
		return name
	}
	return shortID(userID)
}

func formatTime(ts string) string {
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return ts
	}
	return t.Local().Format("15:04")
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func formatUsername(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return name
	}
	if strings.HasPrefix(name, "<") && strings.HasSuffix(name, ">") {
		return name
	}
	return "<" + name + ">"
}

func clampMin(v, minimum int) int {
	if v < minimum {
		return minimum
	}
	return v
}

func trimLine(line string, max int) string {
	if max <= 0 || len(line) <= max {
		return line
	}
	if max <= 3 {
		return line[:max]
	}
	return line[:max-3] + "..."
}

func formatMessageLines(ts, sender, body string, width int, isSystem bool) []string {
	prefix := fmt.Sprintf("  [%s] ", ts)
	if !isSystem {
		prefix = fmt.Sprintf("  [%s] %s: ", ts, sender)
	}
	contPrefix := strings.Repeat(" ", len(prefix))
	available := width - len(prefix)
	if available < 10 {
		available = 10
	}

	var out []string
	lines := strings.Split(body, "\n")
	for i, line := range lines {
		wrapped := wrapText(line, available)
		for j, part := range wrapped {
			if i == 0 && j == 0 {
				out = append(out, prefix+part)
				continue
			}
			out = append(out, contPrefix+part)
		}
		if len(wrapped) == 0 {
			if i == 0 {
				out = append(out, prefix)
			} else {
				out = append(out, contPrefix)
			}
		}
	}
	return out
}

func wrapText(text string, width int) []string {
	if width <= 0 {
		return []string{text}
	}
	if text == "" {
		return []string{""}
	}
	words := strings.Fields(text)
	if len(words) == 0 {
		return []string{""}
	}
	var lines []string
	current := words[0]
	if len(current) > width {
		lines = append(lines, chunkText(current, width)...)
		current = ""
	}
	for _, word := range words[1:] {
		if current == "" {
			if len(word) > width {
				lines = append(lines, chunkText(word, width)...)
				continue
			}
			current = word
			continue
		}
		if len(current)+1+len(word) <= width {
			current = current + " " + word
			continue
		}
		lines = append(lines, current)
		if len(word) > width {
			lines = append(lines, chunkText(word, width)...)
			current = ""
			continue
		}
		current = word
	}
	if current != "" {
		lines = append(lines, current)
	}
	return lines
}

func chunkText(text string, width int) []string {
	if width <= 0 {
		return []string{text}
	}
	chunks := make([]string, 0, (len(text)/width)+1)
	for len(text) > width {
		chunks = append(chunks, text[:width])
		text = text[width:]
	}
	if text != "" {
		chunks = append(chunks, text)
	}
	return chunks
}

func generateChannelKey() ([]byte, error) {
	key := make([]byte, crypto.KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

func (m *chatModel) getChannelKey(channelID string) []byte {
	if channelID == "" {
		return nil
	}
	return m.channelKeys[channelID]
}

func (m *chatModel) setChannelKey(channelID string, key []byte) {
	if channelID == "" || len(key) != crypto.KeySize {
		return
	}
	stored := make([]byte, len(key))
	copy(stored, key)
	m.channelKeys[channelID] = stored
}

func (m *chatModel) ensureChannelKey(channelID string) ([]byte, error) {
	if channelID == "" {
		return nil, fmt.Errorf("missing channel id")
	}
	if existing := m.getChannelKey(channelID); len(existing) == crypto.KeySize {
		return existing, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	env, err := m.api.GetChannelKeyEnvelope(ctx, m.auth.Token, channelID)
	if err != nil {
		return nil, err
	}
	senderPub, err := crypto.PublicKeyFromBase64(env.SenderPublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid sender public key: %v", err)
	}
	key, err := crypto.DecryptFromPeer(m.kp.Private, senderPub, env.Envelope)
	if err != nil {
		return nil, fmt.Errorf("decrypt key envelope: %v", err)
	}
	if len(key) != crypto.KeySize {
		return nil, fmt.Errorf("invalid channel key size")
	}
	m.setChannelKey(channelID, key)
	if err := m.persistChannelKeys(); err != nil {
		return nil, err
	}
	return key, nil
}

func (m *chatModel) persistChannelKeys() error {
	return saveChannelKeys(m.channelKeys, m.keystorePassphrase)
}

func buildChannelKeyEnvelopes(kp *crypto.KeyPair, senderDeviceID string, key []byte, devices []DeviceKey) ([]ChannelKeyEnvelopeRequest, error) {
	if kp == nil || kp.Private == nil || kp.Public == nil {
		return nil, fmt.Errorf("missing device key")
	}
	if senderDeviceID == "" {
		return nil, fmt.Errorf("missing sender device id")
	}
	senderPub := crypto.PublicKeyToBase64(kp.Public)
	envelopes := make([]ChannelKeyEnvelopeRequest, 0, len(devices))
	for _, d := range devices {
		if strings.TrimSpace(d.DeviceID) == "" || strings.TrimSpace(d.PublicKey) == "" {
			continue
		}
		pub, err := crypto.PublicKeyFromBase64(d.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("invalid device public key: %v", err)
		}
		ct, err := crypto.EncryptForPeer(kp.Private, pub, key)
		if err != nil {
			return nil, fmt.Errorf("encrypt key for device: %v", err)
		}
		envelopes = append(envelopes, ChannelKeyEnvelopeRequest{
			DeviceID:        d.DeviceID,
			SenderDeviceID:  senderDeviceID,
			SenderPublicKey: senderPub,
			Envelope:        ct,
		})
	}
	return envelopes, nil
}

func buildDirectoryKeyEnvelopes(kp *crypto.KeyPair, senderDeviceID string, key []byte, devices []DeviceKey) ([]DirectoryKeyEnvelopeRequest, error) {
	if kp == nil || kp.Private == nil || kp.Public == nil {
		return nil, fmt.Errorf("missing device key")
	}
	if senderDeviceID == "" {
		return nil, fmt.Errorf("missing sender device id")
	}
	senderPub := crypto.PublicKeyToBase64(kp.Public)
	envelopes := make([]DirectoryKeyEnvelopeRequest, 0, len(devices))
	for _, d := range devices {
		if strings.TrimSpace(d.DeviceID) == "" || strings.TrimSpace(d.PublicKey) == "" {
			continue
		}
		pub, err := crypto.PublicKeyFromBase64(d.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("invalid device public key: %v", err)
		}
		ct, err := crypto.EncryptForPeer(kp.Private, pub, key)
		if err != nil {
			return nil, fmt.Errorf("encrypt key for device: %v", err)
		}
		envelopes = append(envelopes, DirectoryKeyEnvelopeRequest{
			DeviceID:        d.DeviceID,
			SenderDeviceID:  senderDeviceID,
			SenderPublicKey: senderPub,
			Envelope:        ct,
		})
	}
	return envelopes, nil
}

func encryptChannelField(key []byte, plaintext string) (string, error) {
	ct, err := crypto.Encrypt(key, []byte(plaintext))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ct), nil
}

func decryptFieldWithKey(key []byte, encoded string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	pt, err := crypto.Decrypt(key, raw)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

func (m *chatModel) decryptChannelField(channelID, encoded string) string {
	if encoded == "" {
		return ""
	}
	key := m.getChannelKey(channelID)
	if len(key) != crypto.KeySize {
		return "<encrypted>"
	}
	value, err := decryptFieldWithKey(key, encoded)
	if err != nil {
		return "<encrypted>"
	}
	return value
}

func (m *chatModel) decryptDirectoryName(encoded string) string {
	if encoded == "" || len(m.directoryKey) != crypto.KeySize {
		return ""
	}
	value, err := decryptFieldWithKey(m.directoryKey, encoded)
	if err != nil {
		return ""
	}
	return value
}

func isNotFoundErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "404") || strings.Contains(msg, "not found")
}

func (m *chatModel) decryptChannelName(channelID, encoded string) string {
	if encoded == "" {
		return "<encrypted>"
	}
	return m.decryptChannelField(channelID, encoded)
}
