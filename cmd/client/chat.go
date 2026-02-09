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

const sidebarWidth = 26

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
	isSystem   bool
	highlight  bool
}

type roomInfo struct {
	ID   string
	Name string
}

type roomMember struct {
	UserID   string
	Username string
	Online   bool
}

type chatModel struct {
	api               *APIClient
	auth              *AuthResponse
	kp                *crypto.KeyPair
	ws                *WSClient
	wsCh              chan ServerMessage
	messages          []chatMessage
	rooms             map[string]roomInfo
	roomMsgs          map[string][]chatMessage
	roomHistoryLoaded map[string]bool
	roomMembers       map[string][]roomMember
	userNames         map[string]string
	roomKeys          map[string][]byte
	activeRoom        string
	sidebarVisible    bool
	selectActive      bool
	selectOptions     []roomInfo
	selectIndex       int
	viewport          viewport.Model
	input             textinput.Model
	connected         bool
	errMsg            string
	width             int
	height            int

	// peers caches sender_id -> public key for decryption.
	peers *peerKeyCache
}

type wsConnectedMsg struct {
	ws *WSClient
	ch chan ServerMessage
}

type wsMessageMsg ServerMessage

type wsErrorMsg struct{ err error }

type roomMembersTick struct {
	roomID string
}

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
		api:               api,
		auth:              auth,
		kp:                kp,
		viewport:          vp,
		input:             input,
		width:             width,
		height:            height,
		peers:             newPeerKeyCache(),
		rooms:             make(map[string]roomInfo),
		roomMsgs:          make(map[string][]chatMessage),
		roomHistoryLoaded: make(map[string]bool),
		roomMembers:       make(map[string][]roomMember),
		userNames:         make(map[string]string),
		roomKeys:          loadRoomKeys(),
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
		m.updateLayout()
		m.refreshViewport()
		return m, nil

	case tea.KeyMsg:
		if m.selectActive {
			m.handleRoomSelectKey(msg)
			return m, nil
		}
		switch msg.String() {
		case "enter":
			if m.connected {
				m.sendCurrentMessage()
			}
			return m, nil

		case "ctrl+u":
			if m.activeRoom == "" {
				m.appendSystemMessage("sidebar is only available inside a room")
				return m, nil
			}
			m.sidebarVisible = !m.sidebarVisible
			m.updateLayout()
			if m.sidebarVisible {
				m.fetchRoomMembers(m.activeRoom)
				return m, m.scheduleRoomMembersTick(m.activeRoom)
			}
			m.refreshViewport()
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
		if m.activeRoom == "" && len(m.messages) == 0 {
			m.appendSystemMessage("no global chat; create or join a room with /room")
		}
		if m.sidebarVisible && m.activeRoom != "" {
			return m, tea.Batch(waitForWSMsg(m.wsCh), m.scheduleRoomMembersTick(m.activeRoom))
		}
		return m, waitForWSMsg(m.wsCh)

	case wsMessageMsg:
		m.handleServerMessage(ServerMessage(msg))
		m.refreshViewport()
		return m, waitForWSMsg(m.wsCh)

	case wsErrorMsg:
		m.connected = false
		m.errMsg = msg.err.Error()
		return m, nil

	case roomMembersTick:
		if !m.sidebarVisible || m.activeRoom == "" || msg.roomID != m.activeRoom {
			return m, nil
		}
		m.fetchRoomMembers(m.activeRoom)
		return m, m.scheduleRoomMembersTick(m.activeRoom)
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
	if strings.HasPrefix(body, "/") {
		m.handleCommand(body)
		m.input.Reset()
		return
	}

	if m.activeRoom != "" {
		key, ok := m.roomKeys[m.activeRoom]
		if !ok || len(key) == 0 {
			m.errMsg = "missing room key"
			return
		}
		encryptedBody, err := encryptRoomField(key, body)
		if err != nil {
			m.errMsg = fmt.Sprintf("encrypt room message: %v", err)
			return
		}
		_ = m.ws.Send(SendMessage{
			Type:   "room.message.send",
			RoomID: m.activeRoom,
			Body:   encryptedBody,
		})
		m.input.Reset()
		return
	}
	m.appendSystemMessage("no global chat; create or join a room with /room")
}

func (m *chatModel) handleCommand(raw string) {
	parts := strings.Fields(raw)
	if len(parts) == 0 {
		return
	}
	cmd := strings.ToLower(parts[0])
	if cmd != "/room" {
		m.appendSystemMessage("unknown command")
		return
	}
	if len(parts) < 2 {
		m.appendSystemMessage("room commands: /room list | create <name> | invite <room_id|name> | join <token> | use <room_id|name> | leave")
		return
	}
	action := strings.ToLower(parts[1])

	switch action {
	case "help":
		m.appendSystemMessage("/room list | /room create <name> | /room invite <room_id|name> | /room join <token> | /room use <room_id|name> | /room leave")
	case "list":
		m.fetchRooms()
	case "create":
		if len(parts) < 3 {
			m.appendSystemMessage("usage: /room create <name>")
			return
		}
		name := strings.TrimSpace(strings.TrimPrefix(raw, parts[0]+" "+parts[1]))
		m.createRoom(name)
	case "invite":
		if len(parts) < 3 {
			m.appendSystemMessage("usage: /room invite <room_id|name>")
			return
		}
		nameOrID := strings.TrimSpace(strings.TrimPrefix(raw, parts[0]+" "+parts[1]))
		m.createInvite(nameOrID)
	case "join":
		if len(parts) < 3 {
			m.appendSystemMessage("usage: /room join <token>")
			return
		}
		m.joinRoom(parts[2])
	case "use":
		if len(parts) < 3 {
			m.appendSystemMessage("usage: /room use <room_id|name>")
			return
		}
		nameOrID := strings.TrimSpace(strings.TrimPrefix(raw, parts[0]+" "+parts[1]))
		m.useRoom(nameOrID)
	case "leave", "global":
		m.leaveRoom()
	default:
		m.appendSystemMessage("unknown room command")
	}
}

func (m *chatModel) fetchRooms() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rooms, err := m.api.ListRooms(ctx, m.auth.Token)
	if err != nil {
		m.errMsg = fmt.Sprintf("list rooms: %v", err)
		return
	}
	if len(rooms) == 0 {
		m.appendSystemMessage("no rooms yet")
		return
	}
	for _, rm := range rooms {
		name := m.decryptRoomName(rm.ID, rm.NameEnc)
		m.rooms[rm.ID] = roomInfo{ID: rm.ID, Name: name}
	}
	var b strings.Builder
	b.WriteString("rooms:")
	for _, rm := range rooms {
		name := m.decryptRoomName(rm.ID, rm.NameEnc)
		b.WriteString("\n  ")
		b.WriteString(name)
		b.WriteString(" (")
		b.WriteString(shortID(rm.ID))
		b.WriteString(")")
	}
	m.appendSystemMessage(b.String())
}

func (m *chatModel) createRoom(name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	key := make([]byte, crypto.KeySize)
	if _, err := rand.Read(key); err != nil {
		m.errMsg = fmt.Sprintf("room key: %v", err)
		return
	}
	nameEnc, err := encryptRoomField(key, name)
	if err != nil {
		m.errMsg = fmt.Sprintf("encrypt room name: %v", err)
		return
	}
	displayNameEnc, err := encryptRoomField(key, m.auth.Username)
	if err != nil {
		m.errMsg = fmt.Sprintf("encrypt display name: %v", err)
		return
	}
	created, err := m.api.CreateRoom(ctx, m.auth.Token, nameEnc, displayNameEnc)
	if err != nil {
		m.errMsg = fmt.Sprintf("create room: %v", err)
		return
	}
	m.setRoomKey(created.ID, key)
	info := roomInfo{ID: created.ID, Name: name}
	m.rooms[created.ID] = info
	m.activeRoom = created.ID
	m.appendSystemMessage(fmt.Sprintf("created room '%s' (%s)", name, shortID(created.ID)))
	m.refreshViewport()
}

func (m *chatModel) createInvite(nameOrID string) {
	resolvedID, info, ok := m.resolveRoom(nameOrID, false)
	if !ok {
		return
	}
	key, ok := m.roomKeys[resolvedID]
	if !ok || len(key) == 0 {
		m.errMsg = "missing room key"
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	invite, err := m.api.CreateRoomInvite(ctx, m.auth.Token, resolvedID)
	if err != nil {
		m.errMsg = fmt.Sprintf("create invite: %v", err)
		return
	}
	fullToken := formatInviteToken(invite.Token, key)
	m.appendSystemMessage(fmt.Sprintf("invite token (room '%s', expires %s):", info.Name, formatTime(invite.ExpiresAt)))
	m.appendHighlightedMessage(fullToken)
}

func (m *chatModel) joinRoom(token string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	inviteToken, key, err := parseInviteToken(token)
	if err != nil {
		m.errMsg = fmt.Sprintf("invite token: %v", err)
		return
	}
	displayNameEnc, err := encryptRoomField(key, m.auth.Username)
	if err != nil {
		m.errMsg = fmt.Sprintf("encrypt display name: %v", err)
		return
	}
	joined, err := m.api.JoinRoom(ctx, m.auth.Token, inviteToken, displayNameEnc)
	if err != nil {
		m.errMsg = fmt.Sprintf("join room: %v", err)
		return
	}
	m.setRoomKey(joined.Room.ID, key)
	name := m.decryptRoomName(joined.Room.ID, joined.Room.NameEnc)
	info := roomInfo{ID: joined.Room.ID, Name: name}
	m.rooms[joined.Room.ID] = info
	m.activeRoom = joined.Room.ID
	m.appendSystemMessage(fmt.Sprintf("joined room '%s'", name))

	for _, msg := range joined.Messages {
		senderName := m.decryptRoomField(joined.Room.ID, msg.SenderNameEnc)
		body := m.decryptRoomField(joined.Room.ID, msg.Body)
		cm := chatMessage{
			sender:     msg.SenderID,
			senderName: senderName,
			body:       body,
			sentAt:     msg.SentAt,
			isHistory:  true,
			isMine:     msg.SenderID == m.auth.UserID,
		}
		m.roomMsgs[msg.RoomID] = append(m.roomMsgs[msg.RoomID], cm)
	}
	m.roomHistoryLoaded[joined.Room.ID] = true
	if m.sidebarVisible {
		m.fetchRoomMembers(joined.Room.ID)
		m.scheduleRoomMembersTick(joined.Room.ID)
	}
	m.updateLayout()
	m.refreshViewport()
}

func (m *chatModel) useRoom(roomID string) {
	if strings.EqualFold(roomID, "global") {
		m.leaveRoom()
		return
	}
	resolvedID, info, ok := m.resolveRoom(roomID, true)
	if !ok {
		return
	}
	m.applyRoomSelection(resolvedID, info)
}

func (m *chatModel) leaveRoom() {
	m.activeRoom = ""
	m.sidebarVisible = false
	m.updateLayout()
	m.appendSystemMessage("left room; use /room create, /room join, or /room use")
	m.refreshViewport()
}

func (m *chatModel) loadRoomHistory(roomID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	msgs, err := m.api.ListRoomMessages(ctx, m.auth.Token, roomID, 100)
	if err != nil {
		m.errMsg = fmt.Sprintf("room history: %v", err)
		return
	}
	if len(msgs) == 0 {
		m.roomHistoryLoaded[roomID] = true
		return
	}

	loaded := make([]chatMessage, 0, len(msgs))
	for _, msg := range msgs {
		senderName := m.decryptRoomField(roomID, msg.SenderNameEnc)
		body := m.decryptRoomField(roomID, msg.Body)
		loaded = append(loaded, chatMessage{
			sender:     msg.SenderID,
			senderName: senderName,
			body:       body,
			sentAt:     msg.SentAt,
			isHistory:  true,
			isMine:     msg.SenderID == m.auth.UserID,
		})
	}

	if existing := m.roomMsgs[roomID]; len(existing) > 0 {
		loaded = append(loaded, existing...)
	}
	m.roomMsgs[roomID] = loaded
	m.roomHistoryLoaded[roomID] = true
}

func (m *chatModel) resolveRoom(nameOrID string, allowSelect bool) (string, roomInfo, bool) {
	if nameOrID == "" {
		m.appendSystemMessage("room id or name is required")
		return "", roomInfo{}, false
	}
	if info, ok := m.rooms[nameOrID]; ok {
		return nameOrID, info, true
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rooms, err := m.api.ListRooms(ctx, m.auth.Token)
	if err != nil {
		m.errMsg = fmt.Sprintf("list rooms: %v", err)
		return "", roomInfo{}, false
	}
	if len(rooms) == 0 {
		m.appendSystemMessage("no rooms available")
		return "", roomInfo{}, false
	}
	for _, rm := range rooms {
		name := m.decryptRoomName(rm.ID, rm.NameEnc)
		m.rooms[rm.ID] = roomInfo{ID: rm.ID, Name: name}
	}

	needle := strings.ToLower(strings.TrimSpace(nameOrID))
	var matches []roomInfo
	for _, rm := range rooms {
		name := m.decryptRoomName(rm.ID, rm.NameEnc)
		if strings.ToLower(name) == needle {
			matches = append(matches, roomInfo{ID: rm.ID, Name: name})
		}
	}
	if len(matches) == 0 {
		for _, rm := range rooms {
			if strings.HasPrefix(strings.ToLower(rm.ID), needle) {
				name := m.decryptRoomName(rm.ID, rm.NameEnc)
				matches = append(matches, roomInfo{ID: rm.ID, Name: name})
			}
		}
	}
	if len(matches) == 0 {
		m.appendSystemMessage("unknown room name")
		return "", roomInfo{}, false
	}
	if len(matches) > 1 {
		if allowSelect {
			m.startRoomSelection(matches)
			return "", roomInfo{}, false
		}
		var b strings.Builder
		b.WriteString("multiple rooms match; use an id:\n")
		for _, match := range matches {
			b.WriteString("  ")
			b.WriteString(match.Name)
			b.WriteString(" (")
			b.WriteString(match.ID)
			b.WriteString(")\n")
		}
		m.appendSystemMessage(b.String())
		return "", roomInfo{}, false
	}
	return matches[0].ID, matches[0], true
}

func (m *chatModel) startRoomSelection(options []roomInfo) {
	if len(options) == 0 {
		return
	}
	m.selectActive = true
	m.selectOptions = options
	m.selectIndex = 0
	m.updateLayout()
}

func (m *chatModel) handleRoomSelectKey(msg tea.KeyMsg) {
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
		m.applyRoomSelection(selected.ID, selected)
	case "esc":
		m.selectActive = false
		m.updateLayout()
		m.appendSystemMessage("room selection canceled")
	}
}

func (m *chatModel) applyRoomSelection(roomID string, info roomInfo) {
	m.activeRoom = roomID
	if !m.roomHistoryLoaded[roomID] {
		m.loadRoomHistory(roomID)
	}
	if m.sidebarVisible {
		m.fetchRoomMembers(roomID)
		m.scheduleRoomMembersTick(roomID)
	}
	m.updateLayout()
	m.appendSystemMessage(fmt.Sprintf("now chatting in '%s'", info.Name))
	m.refreshViewport()
}

func (m *chatModel) fetchRoomMembers(roomID string) {
	if roomID == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	members, err := m.api.ListRoomMembers(ctx, m.auth.Token, roomID)
	if err != nil {
		m.errMsg = fmt.Sprintf("room members: %v", err)
		return
	}
	roomMembers := make([]roomMember, 0, len(members))
	for _, member := range members {
		displayName := m.decryptRoomField(roomID, member.DisplayNameEnc)
		roomMembers = append(roomMembers, roomMember{
			UserID:   member.UserID,
			Username: displayName,
			Online:   member.Online,
		})
	}
	m.roomMembers[roomID] = roomMembers
}

func (m *chatModel) appendSystemMessage(text string) {
	msg := chatMessage{senderName: "system", body: text, sentAt: time.Now().UTC().Format(time.RFC3339Nano), isSystem: true}
	if m.activeRoom != "" {
		m.roomMsgs[m.activeRoom] = append(m.roomMsgs[m.activeRoom], msg)
		m.refreshViewport()
		return
	}
	m.messages = append(m.messages, msg)
	m.refreshViewport()
}

func (m *chatModel) appendHighlightedMessage(text string) {
	msg := chatMessage{senderName: "system", body: text, sentAt: time.Now().UTC().Format(time.RFC3339Nano), isSystem: true, highlight: true}
	if m.activeRoom != "" {
		m.roomMsgs[m.activeRoom] = append(m.roomMsgs[m.activeRoom], msg)
		m.refreshViewport()
		return
	}
	m.messages = append(m.messages, msg)
	m.refreshViewport()
}

func (m *chatModel) scheduleRoomMembersTick(roomID string) tea.Cmd {
	if roomID == "" {
		return nil
	}
	return tea.Tick(4*time.Second, func(time.Time) tea.Msg {
		return roomMembersTick{roomID: roomID}
	})
}

// tryDecrypt attempts to decrypt a message body from a sender.
// For broadcast messages the sender encrypts with their own key pair, so the
// recipient needs the sender's public key to derive the shared secret.
func (m *chatModel) tryDecrypt(senderID, body, senderPubKey, keyEnvelope string) (string, bool, []byte) {
	if m.kp == nil || m.kp.Private == nil {
		return body, false, nil
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
						return string(pt), true, contentKey
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
				return string(pt), true, nil
			}
		}
	}

	// Try cached peer key.
	pub, ok := m.peers.get(senderID)
	if ok {
		pt, err := crypto.DecryptFromPeer(m.kp.Private, pub, body)
		if err == nil {
			return string(pt), true, nil
		}
	}

	// If the sender is ourselves, try our own key pair.
	if senderID == m.auth.UserID {
		pt, err := crypto.DecryptFromPeer(m.kp.Private, m.kp.Public, body)
		if err == nil {
			return string(pt), true, nil
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
				return string(pt), true, nil
			}
		}
	}

	// Not encrypted or unable to decrypt – treat as plaintext.
	return body, false, nil
}

func (m *chatModel) handleServerMessage(msg ServerMessage) {
	switch msg.Type {
	case "message.new", "message.history", "message.broadcast":
		body, encrypted, contentKey := m.tryDecrypt(msg.Sender, msg.Body, msg.SenderPubKey, msg.KeyEnvelope)
		senderName := msg.SenderName
		if msg.SenderNameEnc != "" && len(contentKey) > 0 {
			if name, err := decryptRoomFieldWithKey(contentKey, msg.SenderNameEnc); err == nil {
				senderName = name
			}
		}

		cm := chatMessage{
			sender:     msg.Sender,
			senderName: senderName,
			body:       body,
			sentAt:     msg.SentAt,
			isHistory:  msg.Type == "message.history",
			isMine:     msg.Sender == m.auth.UserID,
			encrypted:  encrypted,
		}
		m.messages = append(m.messages, cm)

	case "room.message.new":
		senderName := m.decryptRoomField(msg.RoomID, msg.SenderNameEnc)
		body := m.decryptRoomField(msg.RoomID, msg.Body)
		cm := chatMessage{
			sender:     msg.Sender,
			senderName: senderName,
			body:       body,
			sentAt:     msg.SentAt,
			isHistory:  false,
			isMine:     msg.Sender == m.auth.UserID,
		}
		roomID := msg.RoomID
		m.roomMsgs[roomID] = append(m.roomMsgs[roomID], cm)

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
	if !m.selectActive && m.sidebarVisible && m.activeRoom != "" {
		width -= sidebarWidth
	}
	m.viewport.Width = clampMin(width, 10)
	m.viewport.Height = clampMin(m.height-7, 1)
	m.input.Width = clampMin(m.width-8, 20)
}

func (m *chatModel) renderMessages() string {
	msgs := m.messages
	if m.activeRoom != "" {
		msgs = m.roomMsgs[m.activeRoom]
	}
	if len(msgs) == 0 {
		if m.activeRoom == "" {
			return labelStyle.Render("  No room selected. Use /room create, /room join, or /room use.")
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
	members := m.roomMembers[m.activeRoom]
	lines := make([]string, 0, len(members)+6)
	lines = append(lines, sidebarTitleStyle.Render("Members"), "")
	if len(members) == 0 {
		lines = append(lines, labelStyle.Render("(none)"))
	} else {
		var online []roomMember
		var offline []roomMember
		for _, member := range members {
			if member.Online {
				online = append(online, member)
			} else {
				offline = append(offline, member)
			}
		}
		lines = append(lines, sidebarSectionStyle.Render("Online"))
		if len(online) == 0 {
			lines = append(lines, labelStyle.Render("(none)"))
		} else {
			for _, member := range online {
				display := member.Username
				if display == "" {
					display = shortID(member.UserID)
				}
				lines = append(lines, fmt.Sprintf("%s %s", sidebarOnlineStyle.Render("*"), display))
			}
		}
		lines = append(lines, "", sidebarSectionStyle.Render("Offline"))
		if len(offline) == 0 {
			lines = append(lines, labelStyle.Render("(none)"))
		} else {
			for _, member := range offline {
				display := member.Username
				if display == "" {
					display = shortID(member.UserID)
				}
				lines = append(lines, fmt.Sprintf("%s %s", sidebarOfflineStyle.Render("o"), display))
			}
		}
	}
	content := strings.Join(lines, "\n")
	return sidebarBoxStyle.Width(sidebarWidth).Render(content)
}

func (m *chatModel) renderRoomSelectionModal() string {
	if len(m.selectOptions) == 0 {
		return ""
	}

	lines := make([]string, 0, len(m.selectOptions)+3)
	lines = append(lines, "Select a room", "")
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
		"  %s  %s  %s  %s",
		appNameStyle.Render("* dialtone"),
		headerStyle.Render(m.auth.Username),
		labelStyle.Render(shortID(m.auth.UserID)),
		labelStyle.Render(m.activeRoomLabel()),
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
		chatContent = m.renderRoomSelectionModal()
	} else if m.sidebarVisible && m.activeRoom != "" {
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
		b.WriteString(helpStyle.Render("  enter: send - /room help in chat - ctrl+u: members - pgup/pgdn: scroll - ctrl+q: quit"))
	}

	return b.String()
}

func (m *chatModel) activeRoomLabel() string {
	if m.activeRoom == "" {
		return "no room"
	}
	if info, ok := m.rooms[m.activeRoom]; ok && info.Name != "" {
		return "room: " + info.Name
	}
	return "room: " + shortID(m.activeRoom)
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
	for _, word := range words[1:] {
		if len(current)+1+len(word) <= width {
			current = current + " " + word
			continue
		}
		lines = append(lines, current)
		current = word
	}
	lines = append(lines, current)
	return lines
}

func encryptRoomField(key []byte, plaintext string) (string, error) {
	ct, err := crypto.Encrypt(key, []byte(plaintext))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ct), nil
}

func decryptRoomFieldWithKey(key []byte, encoded string) (string, error) {
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

func formatInviteToken(token string, key []byte) string {
	if token == "" || len(key) == 0 {
		return token
	}
	return token + "." + base64.StdEncoding.EncodeToString(key)
}

func parseInviteToken(value string) (string, []byte, error) {
	parts := strings.SplitN(strings.TrimSpace(value), ".", 2)
	if len(parts) != 2 {
		return "", nil, fmt.Errorf("token must include room key")
	}
	key, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", nil, fmt.Errorf("invalid room key")
	}
	return parts[0], key, nil
}

func (m *chatModel) setRoomKey(roomID string, key []byte) {
	if roomID == "" || len(key) == 0 {
		return
	}
	m.roomKeys[roomID] = key
	_ = saveRoomKeys(m.roomKeys)
}

func (m *chatModel) decryptRoomField(roomID, encoded string) string {
	if encoded == "" {
		return ""
	}
	key, ok := m.roomKeys[roomID]
	if !ok || len(key) == 0 {
		return "<encrypted>"
	}
	value, err := decryptRoomFieldWithKey(key, encoded)
	if err != nil {
		return "<encrypted>"
	}
	return value
}

func (m *chatModel) decryptRoomName(roomID, encoded string) string {
	if encoded == "" {
		return "<encrypted>"
	}
	return m.decryptRoomField(roomID, encoded)
}
