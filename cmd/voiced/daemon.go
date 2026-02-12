package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/Avicted/dialtone/internal/audio"
	"github.com/Avicted/dialtone/internal/ipc"
	voicewebrtc "github.com/Avicted/dialtone/internal/webrtc"
	"github.com/pion/webrtc/v4"
)

var errWebsocketUnavailable = errors.New("websocket unavailable")

type voiceDaemon struct {
	serverURL    string
	token        string
	pttBind      string
	pttBackend   string
	iceConfig    webrtc.Configuration
	vadThreshold int64
	meter        bool
	meterNext    time.Time

	mu    sync.Mutex
	room  string
	muted bool
	local string
	speak bool
	memb  map[string]struct{}

	ws       *WSClient
	pc       *voicewebrtc.Manager
	ipc      *ipcServer
	rem      map[string]bool
	sts      *voiceStats
	playback *audio.Playback
}

func newVoiceDaemon(serverURL, token, pttBind, pttBackend string, iceConfig webrtc.Configuration, vadThreshold int64, meter bool) *voiceDaemon {
	if vadThreshold <= 0 {
		vadThreshold = defaultVADThreshold
	}
	return &voiceDaemon{
		serverURL:    serverURL,
		token:        token,
		pttBind:      pttBind,
		pttBackend:   pttBackend,
		iceConfig:    iceConfig,
		vadThreshold: vadThreshold,
		meter:        meter,
		meterNext:    time.Time{},
	}
}

func (d *voiceDaemon) Run(ctx context.Context, ipcAddr string) error {
	d.sts = newVoiceStats()
	go d.sts.LogLoop(ctx)
	d.startPlayback(ctx)

	manager, err := voicewebrtc.NewManager(d.iceConfig, d.handleICECandidate, d.handlePeerState, d.handleRemoteTrack)
	if err != nil {
		return err
	}
	d.pc = manager

	go logCPUUsage(ctx)

	wsCh := make(chan VoiceSignal, 64)
	wsErrCh := make(chan error, 1)
	go func() {
		wsErrCh <- d.runWSLoop(ctx, wsCh)
	}()

	server := newIPCServer(ipcAddr, d.handleIPCCommand)
	d.ipc = server
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Run(ctx)
	}()

	audioErrCh := make(chan error, 1)
	go func() {
		audioErrCh <- d.runAudio(ctx)
	}()

	pttErrCh := make(chan error, 1)
	if d.hasPTTBinding() {
		go func() {
			pttErrCh <- d.runPTT(ctx)
		}()
	}

	for {
		select {
		case <-ctx.Done():
			d.closeWS()
			d.closePlayback()
			_ = server.Close()
			return nil
		case msg, ok := <-wsCh:
			if !ok {
				if ctx.Err() != nil {
					return nil
				}
				return errors.New("websocket loop closed")
			}
			d.handleWSMessage(msg)
		case err := <-wsErrCh:
			if err != nil {
				return fmt.Errorf("websocket loop failed: %w", err)
			}
			return nil
		case err := <-errCh:
			if err != nil {
				return fmt.Errorf("ipc server failed: %w", err)
			}
			return nil
		case err := <-pttErrCh:
			if err != nil {
				log.Printf("ptt unavailable; falling back to VAD: %v", err)
				if d.ipc != nil {
					d.ipc.Broadcast(ipc.Message{Event: ipc.EventError, Error: fmt.Sprintf("ptt unavailable; falling back to VAD: %v", err)})
				}
				d.disablePTT()
				continue
			}
			if ctx.Err() != nil {
				return nil
			}
			log.Printf("ptt stopped; falling back to VAD")
			d.disablePTT()
			continue
		case err := <-audioErrCh:
			if err != nil {
				return fmt.Errorf("audio pipeline failed: %w", err)
			}
			return nil
		}
	}
}

func (d *voiceDaemon) handleIPCCommand(ctx context.Context, msg ipc.Message) (ipc.Message, error) {
	switch msg.Cmd {
	case ipc.CommandVoiceJoin:
		room := strings.TrimSpace(msg.Room)
		if room == "" {
			return ipc.Message{}, fmt.Errorf("room is required")
		}
		d.mu.Lock()
		d.room = room
		d.mu.Unlock()
		d.resetVoiceMembersForCurrentRoom()
		if err := d.sendSignal(VoiceSignal{Type: "voice_join", ChannelID: room}); err != nil {
			if errors.Is(err, errWebsocketUnavailable) {
				log.Printf("voice join deferred until websocket connected: room=%s", room)
				return ipc.Message{Event: ipc.EventVoiceConnected, Room: room}, nil
			}
			d.mu.Lock()
			if d.room == room {
				d.room = ""
			}
			d.mu.Unlock()
			d.clearVoiceMembers()
			return ipc.Message{}, err
		}
		return ipc.Message{Event: ipc.EventVoiceConnected, Room: room}, nil
	case ipc.CommandVoiceLeave:
		room := strings.TrimSpace(msg.Room)
		if room == "" {
			room = d.currentRoom()
		}
		if room == "" {
			return ipc.Message{}, fmt.Errorf("room is required")
		}
		if err := d.sendSignal(VoiceSignal{Type: "voice_leave", ChannelID: room}); err != nil {
			return ipc.Message{}, err
		}
		d.mu.Lock()
		if d.room == room {
			d.room = ""
		}
		d.mu.Unlock()
		d.clearVoiceMembers()
		if d.pc != nil {
			d.pc.CloseAll()
		}
		d.clearRemoteSpeaking()
		return ipc.Message{Event: ipc.EventVoiceReady, Room: room}, nil
	case ipc.CommandMute:
		d.mu.Lock()
		d.muted = true
		d.mu.Unlock()
		d.setSpeaking(false)
		return ipc.Message{}, nil
	case ipc.CommandUnmute:
		d.mu.Lock()
		d.muted = false
		d.mu.Unlock()
		return ipc.Message{}, nil
	case ipc.CommandIdentify:
		user := strings.TrimSpace(msg.User)
		if user == "" {
			return ipc.Message{}, fmt.Errorf("user is required")
		}
		d.mu.Lock()
		d.local = user
		d.mu.Unlock()
		d.resetVoiceMembersForCurrentRoom()
		return ipc.Message{}, nil
	case ipc.CommandPing:
		return ipc.Message{Event: ipc.EventPong}, nil
	default:
		return ipc.Message{}, fmt.Errorf("unknown command")
	}
}

func (d *voiceDaemon) handleWSMessage(msg VoiceSignal) {
	if msg.Sender != "" && msg.Sender == d.localUser() {
		return
	}
	switch msg.Type {
	case "voice_join":
		if msg.ChannelID == "" || msg.Sender == "" || d.pc == nil {
			return
		}
		if msg.ChannelID != d.currentRoom() {
			return
		}
		d.addVoiceMember(msg.Sender)
		d.pc.ClosePeer(msg.Sender)
		offer, err := d.pc.CreateOffer(msg.Sender)
		if err != nil {
			log.Printf("webrtc offer failed: %v", err)
			return
		}
		_ = d.sendSignal(VoiceSignal{Type: "webrtc_offer", ChannelID: msg.ChannelID, Recipient: msg.Sender, SDP: offer})
	case "voice_leave":
		if msg.Sender == "" || d.pc == nil {
			return
		}
		if msg.ChannelID != "" && msg.ChannelID != d.currentRoom() {
			return
		}
		d.pc.ClosePeer(msg.Sender)
		d.removeVoiceMember(msg.Sender)
		d.setRemoteSpeaking(msg.Sender, false)
	case "voice_roster":
		if msg.ChannelID == "" {
			return
		}
		d.setVoiceMembersForRoom(msg.ChannelID, msg.Users)
	case "voice.presence", "voice.presence.snapshot":
		return
	case "webrtc_offer":
		if msg.Sender == "" || msg.SDP == "" || d.pc == nil {
			return
		}
		if msg.ChannelID != d.currentRoom() {
			return
		}
		answer, err := d.pc.HandleOffer(msg.Sender, msg.SDP)
		if err != nil {
			log.Printf("webrtc answer failed: %v", err)
			return
		}
		_ = d.sendSignal(VoiceSignal{Type: "webrtc_answer", ChannelID: msg.ChannelID, Recipient: msg.Sender, SDP: answer})
	case "webrtc_answer":
		if msg.Sender == "" || msg.SDP == "" || d.pc == nil {
			return
		}
		if msg.ChannelID != d.currentRoom() {
			return
		}
		if err := d.pc.HandleAnswer(msg.Sender, msg.SDP); err != nil {
			log.Printf("webrtc handle answer failed: %v", err)
		}
	case "ice_candidate":
		if msg.Sender == "" || msg.Candidate == "" || d.pc == nil {
			return
		}
		if msg.ChannelID != d.currentRoom() {
			return
		}
		if err := d.pc.AddICECandidate(msg.Sender, msg.Candidate); err != nil {
			log.Printf("webrtc add candidate failed: %v", err)
		}
	default:
		log.Printf("ws signal type=%s channel=%s sender=%s", msg.Type, msg.ChannelID, msg.Sender)
	}
}

func (d *voiceDaemon) sendSignal(msg VoiceSignal) error {
	ws := d.currentWS()
	if ws == nil {
		return errWebsocketUnavailable
	}
	return ws.Send(msg)
}

func (d *voiceDaemon) currentRoom() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.room
}

func (d *voiceDaemon) localUser() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.local
}

func (d *voiceDaemon) handleICECandidate(peerID, candidate string) {
	room := d.currentRoom()
	if room == "" || candidate == "" {
		return
	}
	_ = d.sendSignal(VoiceSignal{Type: "ice_candidate", ChannelID: room, Recipient: peerID, Candidate: candidate})
}

func (d *voiceDaemon) handlePeerState(peerID string, state webrtc.PeerConnectionState) {
	log.Printf("webrtc peer=%s state=%s", peerID, state.String())
	switch state {
	case webrtc.PeerConnectionStateFailed, webrtc.PeerConnectionStateClosed:
		if d.pc != nil {
			d.pc.ClosePeer(peerID)
		}
		d.setRemoteSpeaking(peerID, false)
	}
}

func (d *voiceDaemon) runWSLoop(ctx context.Context, out chan<- VoiceSignal) error {
	defer close(out)
	attempt := 0
	for {
		if ctx.Err() != nil {
			return nil
		}
		ws, err := d.connectWSWithRetry(ctx, attempt)
		if err != nil {
			return err
		}
		attempt = 0
		d.setWS(ws)
		ch := make(chan VoiceSignal, 64)
		go ws.ReadLoop(ch)

		if room := d.currentRoom(); room != "" {
			_ = d.sendSignal(VoiceSignal{Type: "voice_join", ChannelID: room})
		}

		for {
			select {
			case <-ctx.Done():
				ws.Close()
				return nil
			case msg, ok := <-ch:
				if !ok {
					ws.Close()
					d.onWSDisconnect()
					attempt++
					delay := wsBackoff(attempt)
					select {
					case <-ctx.Done():
						return nil
					case <-time.After(delay):
					}
					goto Reconnect
				}
				select {
				case out <- msg:
				case <-ctx.Done():
					ws.Close()
					return nil
				}
			}
		}
	Reconnect:
		continue
	}
}

func (d *voiceDaemon) connectWSWithRetry(ctx context.Context, attempt int) (*WSClient, error) {
	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		ws, err := ConnectWS(d.serverURL, d.token)
		if err == nil {
			return ws, nil
		}
		attempt++
		delay := wsBackoff(attempt)
		log.Printf("ws connect failed: %v", err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(delay):
		}
	}
}

func wsBackoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 5 {
		attempt = 5
	}
	return time.Duration(1<<attempt) * time.Second
}

func (d *voiceDaemon) onWSDisconnect() {
	d.closeWS()
	if d.pc != nil {
		d.pc.CloseAll()
	}
	d.clearRemoteSpeaking()
	d.resetVoiceMembersForCurrentRoom()
}

func (d *voiceDaemon) setWS(ws *WSClient) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.ws = ws
}

func (d *voiceDaemon) currentWS() *WSClient {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.ws
}

func (d *voiceDaemon) closeWS() {
	d.mu.Lock()
	ws := d.ws
	d.ws = nil
	d.mu.Unlock()
	if ws != nil {
		ws.Close()
	}
}

func (d *voiceDaemon) startPlayback(ctx context.Context) {
	playback, err := audio.StartPlayback(ctx)
	if err != nil {
		log.Printf("audio playback failed: %v", err)
		return
	}
	d.mu.Lock()
	d.playback = playback
	d.mu.Unlock()
}

func (d *voiceDaemon) closePlayback() {
	d.mu.Lock()
	playback := d.playback
	d.playback = nil
	d.mu.Unlock()
	if playback != nil {
		_ = playback.Close()
	}
}

func (d *voiceDaemon) writePlayback(samples []int16) {
	d.mu.Lock()
	playback := d.playback
	d.mu.Unlock()
	if playback == nil || len(samples) == 0 {
		return
	}
	playback.Write(samples)
}

func (d *voiceDaemon) runPTT(ctx context.Context) error {
	controller, err := newPTTController(d.pttBind, d.pttBackend)
	if err != nil {
		return err
	}
	if strings.TrimSpace(controller.startupInfo) != "" && d.ipc != nil {
		d.ipc.Broadcast(ipc.Message{Event: ipc.EventInfo, Error: controller.startupInfo})
	}
	return controller.Run(ctx, func() {
		d.setSpeaking(true)
	}, func() {
		d.setSpeaking(false)
	})
}

func (d *voiceDaemon) updateVAD(active bool) {
	if d.hasPTTBinding() {
		return
	}
	d.setSpeaking(active)
}

func (d *voiceDaemon) hasPTTBinding() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return strings.TrimSpace(d.pttBind) != ""
}

func (d *voiceDaemon) disablePTT() {
	d.mu.Lock()
	alreadyDisabled := strings.TrimSpace(d.pttBind) == ""
	d.pttBind = ""
	d.mu.Unlock()
	if alreadyDisabled {
		return
	}
	d.setSpeaking(false)
}

func (d *voiceDaemon) setSpeaking(active bool) {
	d.mu.Lock()
	muted := d.muted
	user := d.local
	if muted && active {
		d.mu.Unlock()
		return
	}
	if d.speak == active {
		d.mu.Unlock()
		return
	}
	d.speak = active
	ipcServer := d.ipc
	d.mu.Unlock()

	if ipcServer == nil || user == "" {
		return
	}
	ipcServer.Broadcast(ipc.Message{Event: ipc.EventUserSpeaking, User: user, Active: active})
}

func (d *voiceDaemon) isSpeaking() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.muted {
		return false
	}
	return d.speak
}
