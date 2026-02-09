package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/Avicted/dialtone/internal/crypto"
)

// peerKeyCache is a thread-safe cache of peer public keys, stored behind a
// pointer so chatModel can be copied by Bubble Tea without tripping vet.
type peerKeyCache struct {
	mu   sync.RWMutex
	keys map[string]*ecdh.PublicKey
}

func newPeerKeyCache() *peerKeyCache {
	return &peerKeyCache{keys: make(map[string]*ecdh.PublicKey)}
}

func (c *peerKeyCache) get(id string) (*ecdh.PublicKey, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	pub, ok := c.keys[id]
	return pub, ok
}

func (c *peerKeyCache) set(id string, pub *ecdh.PublicKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keys[id] = pub
}

type chatMessage struct {
	sender     string
	senderName string
	body       string
	sentAt     string
	isHistory  bool
	isMine     bool
	encrypted  bool // true if body arrived as ciphertext
}

type chatModel struct {
	api       *APIClient
	auth      *AuthResponse
	kp        *crypto.KeyPair
	ws        *WSClient
	wsCh      chan ServerMessage
	messages  []chatMessage
	viewport  viewport.Model
	input     textinput.Model
	connected bool
	errMsg    string
	width     int
	height    int

	// peers caches sender_id -> public key for decryption.
	peers *peerKeyCache
}

type wsConnectedMsg struct {
	ws *WSClient
	ch chan ServerMessage
}

type wsMessageMsg ServerMessage

type wsErrorMsg struct{ err error }

func newChatModel(api *APIClient, auth *AuthResponse, kp *crypto.KeyPair, width, height int) chatModel {
	input := textinput.New()
	input.Placeholder = "type a message..."
	input.CharLimit = 4096
	input.Width = clampMin(width-8, 20)
	input.Focus()

	vpHeight := clampMin(height-7, 1)
	vpWidth := clampMin(width-4, 10)
	vp := viewport.New(vpWidth, vpHeight)

	return chatModel{
		api:      api,
		auth:     auth,
		kp:       kp,
		viewport: vp,
		input:    input,
		width:    width,
		height:   height,
		peers:    newPeerKeyCache(),
	}
}

func (m chatModel) Init() tea.Cmd {
	return tea.Batch(
		textinput.Blink,
		m.connectWS(),
	)
}

func (m chatModel) connectWS() tea.Cmd {
	serverURL := m.api.serverURL
	token := m.auth.Token
	return func() tea.Msg {
		ws, err := ConnectWS(serverURL, token)
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

func (m chatModel) Update(msg tea.Msg) (chatModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.viewport.Width = clampMin(m.width-4, 10)
		m.viewport.Height = clampMin(m.height-7, 1)
		m.input.Width = clampMin(m.width-8, 20)
		m.refreshViewport()
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "enter":
			if m.connected {
				m.sendCurrentMessage()
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
		return m, waitForWSMsg(m.wsCh)

	case wsMessageMsg:
		m.handleServerMessage(ServerMessage(msg))
		m.refreshViewport()
		return m, waitForWSMsg(m.wsCh)

	case wsErrorMsg:
		m.connected = false
		m.errMsg = msg.err.Error()
		return m, nil
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m *chatModel) sendCurrentMessage() {
	body := strings.TrimSpace(m.input.Value())
	if body == "" || m.ws == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	keysResp, err := m.api.FetchAllDeviceKeys(ctx)
	if err != nil {
		m.errMsg = fmt.Sprintf("fetch keys: %v", err)
		return
	}

	contentKey := make([]byte, crypto.KeySize)
	if _, err := rand.Read(contentKey); err != nil {
		m.errMsg = fmt.Sprintf("random key: %v", err)
		return
	}

	ct, err := crypto.Encrypt(contentKey, []byte(body))
	if err != nil {
		m.errMsg = fmt.Sprintf("encrypt: %v", err)
		return
	}
	encryptedBody := base64.StdEncoding.EncodeToString(ct)

	envelopes := make(map[string]string, len(keysResp.Keys))
	for _, key := range keysResp.Keys {
		pub, err := crypto.PublicKeyFromBase64(key.PublicKey)
		if err != nil {
			continue
		}
		encKey, err := crypto.EncryptForPeer(m.kp.Private, pub, contentKey)
		if err != nil {
			continue
		}
		envelopes[key.DeviceID] = encKey
	}
	if len(envelopes) == 0 {
		m.errMsg = "no recipient keys available"
		return
	}

	_ = m.ws.Send(SendMessage{
		Type:         "message.broadcast",
		Body:         encryptedBody,
		PublicKey:    crypto.PublicKeyToBase64(m.kp.Public),
		KeyEnvelopes: envelopes,
	})
	m.input.Reset()
}

// tryDecrypt attempts to decrypt a message body from a sender.
// For broadcast messages the sender encrypts with their own key pair, so the
// recipient needs the sender's public key to derive the shared secret.
func (m *chatModel) tryDecrypt(senderID, body, senderPubKey, keyEnvelope string) (string, bool) {
	if m.kp == nil || m.kp.Private == nil {
		return body, false
	}

	if senderPubKey != "" && keyEnvelope != "" {
		pub, err := crypto.PublicKeyFromBase64(senderPubKey)
		if err == nil {
			contentKey, err := crypto.DecryptFromPeer(m.kp.Private, pub, keyEnvelope)
			if err == nil {
				ct, err := base64.StdEncoding.DecodeString(body)
				if err == nil {
					pt, err := crypto.Decrypt(contentKey, ct)
					if err == nil {
						m.peers.set(senderID, pub)
						return string(pt), true
					}
				}
			}
		}
	}

	// First try using the embedded sender public key.
	if senderPubKey != "" {
		pub, err := crypto.PublicKeyFromBase64(senderPubKey)
		if err == nil {
			pt, err := crypto.DecryptFromPeer(m.kp.Private, pub, body)
			if err == nil {
				// Cache the public key for future messages.
				m.peers.set(senderID, pub)
				return string(pt), true
			}
		}
	}

	// Try cached peer key.
	pub, ok := m.peers.get(senderID)
	if ok {
		pt, err := crypto.DecryptFromPeer(m.kp.Private, pub, body)
		if err == nil {
			return string(pt), true
		}
	}

	// If the sender is ourselves, try our own key pair.
	if senderID == m.auth.UserID {
		pt, err := crypto.DecryptFromPeer(m.kp.Private, m.kp.Public, body)
		if err == nil {
			return string(pt), true
		}
	}

	// Try fetching the sender's public key from the server.
	keysResp, err := m.api.FetchDeviceKeys(context.Background(), senderID)
	if err == nil && len(keysResp.Keys) > 0 {
		for _, k := range keysResp.Keys {
			pub, err := crypto.PublicKeyFromBase64(k.PublicKey)
			if err != nil {
				continue
			}
			pt, err := crypto.DecryptFromPeer(m.kp.Private, pub, body)
			if err == nil {
				m.peers.set(senderID, pub)
				return string(pt), true
			}
		}
	}

	// Not encrypted or unable to decrypt – treat as plaintext.
	return body, false
}

func (m *chatModel) handleServerMessage(msg ServerMessage) {
	switch msg.Type {
	case "message.new", "message.history", "message.broadcast":
		body, encrypted := m.tryDecrypt(msg.Sender, msg.Body, msg.SenderPubKey, msg.KeyEnvelope)

		cm := chatMessage{
			sender:     msg.Sender,
			senderName: msg.SenderName,
			body:       body,
			sentAt:     msg.SentAt,
			isHistory:  msg.Type == "message.history",
			isMine:     msg.Sender == m.auth.UserID,
			encrypted:  encrypted,
		}
		m.messages = append(m.messages, cm)

	case "error":
		m.errMsg = fmt.Sprintf("[%s] %s", msg.Code, msg.Message)
	}
}

func (m *chatModel) refreshViewport() {
	m.viewport.SetContent(m.renderMessages())
	m.viewport.GotoBottom()
}

func (m *chatModel) renderMessages() string {
	if len(m.messages) == 0 {
		return labelStyle.Render("  No messages yet. Send one to start chatting!")
	}

	var b strings.Builder
	for _, msg := range m.messages {
		ts := formatTime(msg.sentAt)
		sender := "you"
		if !msg.isMine {
			if msg.senderName != "" {
				sender = msg.senderName
			} else {
				sender = shortID(msg.sender)
			}
		}

		lockIcon := ""
		if msg.encrypted {
			lockIcon = "🔒 "
		}

		var line string
		switch {
		case msg.isHistory:
			line = historyMsgStyle.Render(fmt.Sprintf("  %s[%s] %s: %s", lockIcon, ts, sender, msg.body))
		case msg.isMine:
			line = sentMsgStyle.Render(fmt.Sprintf("  %s[%s] %s: %s", lockIcon, ts, sender, msg.body))
		default:
			line = recvMsgStyle.Render(fmt.Sprintf("  %s[%s] %s: %s", lockIcon, ts, sender, msg.body))
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}

func (m chatModel) View() string {
	var b strings.Builder

	header := fmt.Sprintf(
		"  %s  %s  %s",
		appNameStyle.Render("◆ dialtone"),
		headerStyle.Render(m.auth.Username),
		labelStyle.Render(shortID(m.auth.UserID)),
	)
	connStatus := connectedStyle.Render("● connected")
	if !m.connected {
		connStatus = disconnectedStyle.Render("○ disconnected")
	}
	gap := max(1, m.width-lipgloss.Width(header)-lipgloss.Width(connStatus)-2)
	b.WriteString(header + strings.Repeat(" ", gap) + connStatus)
	b.WriteString("\n")

	b.WriteString(separator(m.width))
	b.WriteString("\n")

	b.WriteString(m.viewport.View())
	b.WriteString("\n")

	b.WriteString(separator(m.width))
	b.WriteString("\n")

	inputLabel := activeInputStyle.Render("  > ")
	b.WriteString(inputLabel + m.input.View())
	b.WriteString("\n")

	if m.errMsg != "" {
		b.WriteString(errorStyle.Render("  ✗ " + m.errMsg))
	} else {
		b.WriteString(helpStyle.Render("  enter: send • pgup/pgdn: scroll • 🔒 e2e encrypted • ctrl+c: quit"))
	}

	return b.String()
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

func clampMin(v, minimum int) int {
	if v < minimum {
		return minimum
	}
	return v
}
