package main

import (
	"reflect"
	"testing"

	"github.com/Avicted/dialtone/internal/ipc"
	"github.com/pion/webrtc/v4"
)

func TestVoiceMembersPayloadLocked(t *testing.T) {
	d := newVoiceDaemon("http://server", "token", "", pttBackendAuto, webrtc.Configuration{}, defaultVADThreshold, false)
	d.memb = map[string]struct{}{"bob": {}, "alice": {}}

	if _, _, ok := d.voiceMembersPayloadLocked(); ok {
		t.Fatalf("expected no payload when ipc server is unavailable")
	}

	d.ipc = &ipcServer{}
	if _, _, ok := d.voiceMembersPayloadLocked(); ok {
		t.Fatalf("expected no payload when room is empty")
	}

	d.room = "room-1"
	server, payload, ok := d.voiceMembersPayloadLocked()
	if !ok {
		t.Fatalf("expected payload to be produced")
	}
	if server != d.ipc {
		t.Fatalf("expected payload server to match daemon ipc server")
	}
	if payload.Event != ipc.EventVoiceMembers || payload.Room != "room-1" {
		t.Fatalf("unexpected payload metadata: %+v", payload)
	}
	if want := []string{"alice", "bob"}; !reflect.DeepEqual(payload.Users, want) {
		t.Fatalf("unexpected sorted users: got=%v want=%v", payload.Users, want)
	}
}

func TestResetVoiceMembersForCurrentRoom(t *testing.T) {
	d := newVoiceDaemon("http://server", "token", "", pttBackendAuto, webrtc.Configuration{}, defaultVADThreshold, false)
	d.local = " alice "
	d.memb = map[string]struct{}{"bob": {}}

	d.resetVoiceMembersForCurrentRoom()
	d.mu.Lock()
	emptyRoomMembers := len(d.memb)
	d.mu.Unlock()
	if emptyRoomMembers != 0 {
		t.Fatalf("expected no members when room is empty, got %d", emptyRoomMembers)
	}

	d.room = "room-1"
	d.memb["bob"] = struct{}{}
	d.resetVoiceMembersForCurrentRoom()

	d.mu.Lock()
	_, hasAlice := d.memb["alice"]
	_, hasBob := d.memb["bob"]
	membersLen := len(d.memb)
	d.mu.Unlock()

	if !hasAlice || hasBob || membersLen != 1 {
		t.Fatalf("expected only local member after reset, got alice=%v bob=%v len=%d", hasAlice, hasBob, membersLen)
	}
}

func TestSetVoiceMembersForRoomGuardsAndPopulate(t *testing.T) {
	d := newVoiceDaemon("http://server", "token", "", pttBackendAuto, webrtc.Configuration{}, defaultVADThreshold, false)
	d.room = "room-1"
	d.local = "alice"
	d.memb = map[string]struct{}{"stale": {}}

	d.setVoiceMembersForRoom("   ", []string{"bob"})
	d.setVoiceMembersForRoom("other-room", []string{"bob"})

	d.mu.Lock()
	_, stillStale := d.memb["stale"]
	d.mu.Unlock()
	if !stillStale {
		t.Fatalf("expected stale members unchanged for ignored rooms")
	}

	d.setVoiceMembersForRoom("room-1", []string{" bob ", "", "bob", "carol"})
	d.mu.Lock()
	_, hasAlice := d.memb["alice"]
	_, hasBob := d.memb["bob"]
	_, hasCarol := d.memb["carol"]
	_, hasStale := d.memb["stale"]
	membersLen := len(d.memb)
	d.mu.Unlock()

	if !hasAlice || !hasBob || !hasCarol || hasStale || membersLen != 3 {
		t.Fatalf("unexpected members after roster apply: alice=%v bob=%v carol=%v stale=%v len=%d", hasAlice, hasBob, hasCarol, hasStale, membersLen)
	}
}

func TestBroadcastVoiceMembersGuards(t *testing.T) {
	d := newVoiceDaemon("http://server", "token", "", pttBackendAuto, webrtc.Configuration{}, defaultVADThreshold, false)
	payload := ipc.Message{Event: ipc.EventVoiceMembers, Room: "room-1", Users: []string{"alice"}}

	d.broadcastVoiceMembers(nil, payload, true)
	d.broadcastVoiceMembers(&ipcServer{}, ipc.Message{}, true)
	d.broadcastVoiceMembers(&ipcServer{}, payload, false)
	d.broadcastVoiceMembers(&ipcServer{}, payload, true)
}

func TestAddRemoveVoiceMemberGuardPaths(t *testing.T) {
	d := newVoiceDaemon("http://server", "token", "", pttBackendAuto, webrtc.Configuration{}, defaultVADThreshold, false)

	d.addVoiceMember("bob")
	d.removeVoiceMember("bob")

	d.room = "room-1"
	d.removeVoiceMember("bob")

	d.mu.Lock()
	membersLen := len(d.memb)
	d.mu.Unlock()

	if membersLen != 0 {
		t.Fatalf("expected no members after guard-path operations, got %d", membersLen)
	}
}
