package main

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/Avicted/dialtone/internal/ipc"
	"github.com/pion/webrtc/v4"
)

func TestNewVoiceDaemonDefaultsVADThreshold(t *testing.T) {
	d := newVoiceDaemon("http://server", "token", "", pttBackendAuto, webrtc.Configuration{}, 0, false)
	if d.vadThreshold != defaultVADThreshold {
		t.Fatalf("expected default VAD threshold %d, got %d", defaultVADThreshold, d.vadThreshold)
	}

	d = newVoiceDaemon("http://server", "token", "", pttBackendAuto, webrtc.Configuration{}, 1234, false)
	if d.vadThreshold != 1234 {
		t.Fatalf("expected explicit VAD threshold to be preserved, got %d", d.vadThreshold)
	}
}

func TestWSBackoffClamp(t *testing.T) {
	tests := []struct {
		attempt int
		want    time.Duration
	}{
		{attempt: 0, want: 2 * time.Second},
		{attempt: 1, want: 2 * time.Second},
		{attempt: 2, want: 4 * time.Second},
		{attempt: 5, want: 32 * time.Second},
		{attempt: 99, want: 32 * time.Second},
	}

	for _, tt := range tests {
		if got := wsBackoff(tt.attempt); got != tt.want {
			t.Fatalf("wsBackoff(%d) = %v, want %v", tt.attempt, got, tt.want)
		}
	}
}

func TestHandleIPCCommandVoiceJoinDeferredWithoutWebsocket(t *testing.T) {
	d := newVoiceDaemon("http://server", "token", "", pttBackendAuto, webrtc.Configuration{}, defaultVADThreshold, false)
	d.local = "alice"

	resp, err := d.handleIPCCommand(context.Background(), ipc.Message{Cmd: ipc.CommandVoiceJoin, Room: "  room-1  "})
	if err != nil {
		t.Fatalf("handleIPCCommand voice join: %v", err)
	}
	if resp.Event != ipc.EventVoiceConnected {
		t.Fatalf("expected %q event, got %q", ipc.EventVoiceConnected, resp.Event)
	}
	if resp.Room != "room-1" {
		t.Fatalf("expected joined room room-1, got %q", resp.Room)
	}
	if got := d.currentRoom(); got != "room-1" {
		t.Fatalf("expected daemon room to be set, got %q", got)
	}

	d.mu.Lock()
	_, hasLocal := d.memb["alice"]
	d.mu.Unlock()
	if !hasLocal {
		t.Fatalf("expected local user to be included in voice members after join")
	}
}

func TestHandleIPCCommandVoiceJoinClearsRoomOnSendError(t *testing.T) {
	d := newVoiceDaemon("http://server", "token", "", pttBackendAuto, webrtc.Configuration{}, defaultVADThreshold, false)
	d.setWS(&WSClient{closed: true})

	resp, err := d.handleIPCCommand(context.Background(), ipc.Message{Cmd: ipc.CommandVoiceJoin, Room: "room-1"})
	if err == nil {
		t.Fatalf("expected voice join send failure")
	}
	if resp.Event != "" {
		t.Fatalf("expected empty response event on join failure, got %q", resp.Event)
	}
	if got := d.currentRoom(); got != "" {
		t.Fatalf("expected room to be cleared on join failure, got %q", got)
	}

	d.mu.Lock()
	membersLen := len(d.memb)
	d.mu.Unlock()
	if membersLen != 0 {
		t.Fatalf("expected voice members cleared on join failure, got %d members", membersLen)
	}
}

func TestHandleIPCCommandValidationAndBasics(t *testing.T) {
	d := newVoiceDaemon("http://server", "token", "", pttBackendAuto, webrtc.Configuration{}, defaultVADThreshold, false)

	if _, err := d.handleIPCCommand(context.Background(), ipc.Message{Cmd: ipc.CommandVoiceJoin, Room: "   "}); err == nil {
		t.Fatalf("expected join with blank room to fail")
	}
	if _, err := d.handleIPCCommand(context.Background(), ipc.Message{Cmd: ipc.CommandVoiceLeave}); err == nil {
		t.Fatalf("expected leave without room to fail")
	}
	if _, err := d.handleIPCCommand(context.Background(), ipc.Message{Cmd: ipc.CommandIdentify, User: ""}); err == nil {
		t.Fatalf("expected identify without user to fail")
	}

	if _, err := d.handleIPCCommand(context.Background(), ipc.Message{Cmd: ipc.CommandIdentify, User: "alice"}); err != nil {
		t.Fatalf("identify failed: %v", err)
	}
	if got := d.localUser(); got != "alice" {
		t.Fatalf("expected local user alice, got %q", got)
	}

	resp, err := d.handleIPCCommand(context.Background(), ipc.Message{Cmd: ipc.CommandPing})
	if err != nil {
		t.Fatalf("ping failed: %v", err)
	}
	if resp.Event != ipc.EventPong {
		t.Fatalf("expected pong event, got %q", resp.Event)
	}

	if _, err := d.handleIPCCommand(context.Background(), ipc.Message{Cmd: "unknown"}); err == nil {
		t.Fatalf("expected unknown command to fail")
	}
}

func TestMuteUnmuteAndSpeakingState(t *testing.T) {
	d := newVoiceDaemon("http://server", "token", "", pttBackendAuto, webrtc.Configuration{}, defaultVADThreshold, false)
	d.local = "alice"
	d.setSpeaking(true)
	if !d.isSpeaking() {
		t.Fatalf("expected speaking=true after setSpeaking(true)")
	}

	if _, err := d.handleIPCCommand(context.Background(), ipc.Message{Cmd: ipc.CommandMute}); err != nil {
		t.Fatalf("mute failed: %v", err)
	}
	if d.isSpeaking() {
		t.Fatalf("expected muted daemon to report not speaking")
	}

	if _, err := d.handleIPCCommand(context.Background(), ipc.Message{Cmd: ipc.CommandUnmute}); err != nil {
		t.Fatalf("unmute failed: %v", err)
	}
	if d.isSpeaking() {
		t.Fatalf("expected speaking to remain false after unmute")
	}
}

func TestUpdateVADAndDisablePTT(t *testing.T) {
	d := newVoiceDaemon("http://server", "token", "ctrl+v", pttBackendAuto, webrtc.Configuration{}, defaultVADThreshold, false)
	d.local = "alice"

	d.updateVAD(true)
	if d.isSpeaking() {
		t.Fatalf("expected VAD to be ignored while PTT binding is active")
	}

	d.disablePTT()
	if d.hasPTTBinding() {
		t.Fatalf("expected PTT binding to be cleared")
	}

	d.updateVAD(true)
	if !d.isSpeaking() {
		t.Fatalf("expected VAD to control speaking after PTT is disabled")
	}
}

func TestSendSignalWithoutWebsocket(t *testing.T) {
	d := newVoiceDaemon("http://server", "token", "", pttBackendAuto, webrtc.Configuration{}, defaultVADThreshold, false)
	err := d.sendSignal(VoiceSignal{Type: "voice_join", ChannelID: "room-1"})
	if !errors.Is(err, errWebsocketUnavailable) {
		t.Fatalf("expected errWebsocketUnavailable, got %v", err)
	}
}

func TestOnWSDisconnectResetsVoiceState(t *testing.T) {
	d := newVoiceDaemon("http://server", "token", "", pttBackendAuto, webrtc.Configuration{}, defaultVADThreshold, false)
	d.local = "alice"
	d.room = "room-1"
	d.ws = &WSClient{closed: true}
	d.rem = map[string]bool{"bob": true}
	d.memb = map[string]struct{}{"alice": {}, "bob": {}}

	d.onWSDisconnect()

	if d.currentWS() != nil {
		t.Fatalf("expected websocket reference to be cleared")
	}

	d.mu.Lock()
	remLen := len(d.rem)
	_, hasAlice := d.memb["alice"]
	_, hasBob := d.memb["bob"]
	membersLen := len(d.memb)
	d.mu.Unlock()

	if remLen != 0 {
		t.Fatalf("expected remote speaking state cleared, got %d entries", remLen)
	}
	if !hasAlice || hasBob || membersLen != 1 {
		t.Fatalf("expected members reset to only local user, got alice=%v bob=%v len=%d", hasAlice, hasBob, membersLen)
	}
}

func TestHandleWSMessageVoiceRosterUpdatesMembersForCurrentRoom(t *testing.T) {
	d := newVoiceDaemon("http://server", "token", "", pttBackendAuto, webrtc.Configuration{}, defaultVADThreshold, false)
	d.local = "alice"
	d.room = "room-1"

	d.handleWSMessage(VoiceSignal{Type: "voice_roster", ChannelID: "room-1", Users: []string{"bob", "", "bob"}})

	d.mu.Lock()
	_, hasAlice := d.memb["alice"]
	_, hasBob := d.memb["bob"]
	membersLen := len(d.memb)
	d.mu.Unlock()

	if !hasAlice || !hasBob || membersLen != 2 {
		t.Fatalf("expected roster to include local+remote members once, got alice=%v bob=%v len=%d", hasAlice, hasBob, membersLen)
	}
}

func TestHandleICECandidateAndPeerStateFailure(t *testing.T) {
	d := newVoiceDaemon("http://server", "token", "", pttBackendAuto, webrtc.Configuration{}, defaultVADThreshold, false)

	d.setRemoteSpeaking("peer-1", true)
	d.handleICECandidate("peer-1", "candidate")
	d.room = "room-1"
	d.handleICECandidate("peer-1", "candidate")
	d.handlePeerState("peer-1", webrtc.PeerConnectionStateFailed)

	d.mu.Lock()
	active := d.rem["peer-1"]
	d.mu.Unlock()
	if active {
		t.Fatalf("expected failed peer state to clear remote speaking")
	}
}

func TestRunWSLoopAndConnectWSHonorCanceledContext(t *testing.T) {
	d := newVoiceDaemon("http://server", "token", "", pttBackendAuto, webrtc.Configuration{}, defaultVADThreshold, false)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	out := make(chan VoiceSignal)
	if err := d.runWSLoop(ctx, out); err != nil {
		t.Fatalf("runWSLoop canceled context: %v", err)
	}
	if _, ok := <-out; ok {
		t.Fatalf("expected runWSLoop output channel to be closed")
	}

	if _, err := d.connectWSWithRetry(ctx, 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled context from connectWSWithRetry, got %v", err)
	}
}

func TestRunPTTInvalidBackendReturnsError(t *testing.T) {
	d := newVoiceDaemon("http://server", "token", "ctrl+v", "invalid-backend", webrtc.Configuration{}, defaultVADThreshold, false)
	if err := d.runPTT(context.Background()); err == nil {
		t.Fatalf("expected runPTT to fail for unsupported backend")
	}
}

func TestPlaybackHelpersNoopWithoutPlayback(t *testing.T) {
	d := newVoiceDaemon("http://server", "token", "", pttBackendAuto, webrtc.Configuration{}, defaultVADThreshold, false)
	d.writePlayback(nil)
	d.writePlayback([]int16{1, 2, 3})
	d.closePlayback()
}

func TestStartPlaybackReturnsPromptly(t *testing.T) {
	d := newVoiceDaemon("http://server", "token", "", pttBackendAuto, webrtc.Configuration{}, defaultVADThreshold, false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan struct{})
	go func() {
		d.startPlayback(ctx)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatalf("startPlayback did not return promptly")
	}
}

func TestRunReturnsNilWhenContextCanceled(t *testing.T) {
	d := newVoiceDaemon("http://server", "token", "", pttBackendAuto, webrtc.Configuration{}, defaultVADThreshold, false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ipcAddr := filepath.Join(t.TempDir(), "voice.sock")
	if err := d.Run(ctx, ipcAddr); err != nil {
		t.Fatalf("Run canceled context: %v", err)
	}
}

func TestAddAndRemoveVoiceMember(t *testing.T) {
	d := newVoiceDaemon("http://server", "token", "", pttBackendAuto, webrtc.Configuration{}, defaultVADThreshold, false)
	d.room = "room-1"
	d.local = "alice"
	d.memb = map[string]struct{}{"alice": {}}

	d.addVoiceMember("")
	d.addVoiceMember("bob")
	d.addVoiceMember("bob")

	d.mu.Lock()
	_, hasAlice := d.memb["alice"]
	_, hasBob := d.memb["bob"]
	membersLen := len(d.memb)
	d.mu.Unlock()
	if !hasAlice || !hasBob || membersLen != 2 {
		t.Fatalf("expected alice and bob members only, got alice=%v bob=%v len=%d", hasAlice, hasBob, membersLen)
	}

	d.removeVoiceMember("charlie")
	d.removeVoiceMember("")
	d.removeVoiceMember("bob")

	d.mu.Lock()
	_, hasAlice = d.memb["alice"]
	_, hasBob = d.memb["bob"]
	membersLen = len(d.memb)
	d.mu.Unlock()
	if !hasAlice || hasBob || membersLen != 1 {
		t.Fatalf("expected only local member to remain, got alice=%v bob=%v len=%d", hasAlice, hasBob, membersLen)
	}
}
