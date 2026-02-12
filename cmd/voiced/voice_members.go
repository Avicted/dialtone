package main

import (
	"sort"
	"strings"

	"github.com/Avicted/dialtone/internal/ipc"
)

func (d *voiceDaemon) resetVoiceMembersForCurrentRoom() {
	d.mu.Lock()
	if d.memb == nil {
		d.memb = make(map[string]struct{})
	} else {
		clear(d.memb)
	}
	if d.room != "" {
		if local := strings.TrimSpace(d.local); local != "" {
			d.memb[local] = struct{}{}
		}
	}
	ipcServer, payload, ok := d.voiceMembersPayloadLocked()
	d.mu.Unlock()
	d.broadcastVoiceMembers(ipcServer, payload, ok)
}

func (d *voiceDaemon) clearVoiceMembers() {
	d.mu.Lock()
	if d.memb == nil {
		d.memb = make(map[string]struct{})
	} else {
		clear(d.memb)
	}
	d.mu.Unlock()
}

func (d *voiceDaemon) setVoiceMembersForRoom(room string, users []string) {
	room = strings.TrimSpace(room)
	if room == "" {
		return
	}
	d.mu.Lock()
	if d.room == "" || d.room != room {
		d.mu.Unlock()
		return
	}
	if d.memb == nil {
		d.memb = make(map[string]struct{})
	} else {
		clear(d.memb)
	}
	for _, userID := range users {
		id := strings.TrimSpace(userID)
		if id == "" {
			continue
		}
		d.memb[id] = struct{}{}
	}
	if local := strings.TrimSpace(d.local); local != "" {
		d.memb[local] = struct{}{}
	}
	ipcServer, payload, ok := d.voiceMembersPayloadLocked()
	d.mu.Unlock()
	d.broadcastVoiceMembers(ipcServer, payload, ok)
}

func (d *voiceDaemon) addVoiceMember(userID string) {
	id := strings.TrimSpace(userID)
	if id == "" {
		return
	}
	d.mu.Lock()
	if d.room == "" {
		d.mu.Unlock()
		return
	}
	if d.memb == nil {
		d.memb = make(map[string]struct{})
	}
	if _, exists := d.memb[id]; exists {
		d.mu.Unlock()
		return
	}
	d.memb[id] = struct{}{}
	ipcServer, payload, ok := d.voiceMembersPayloadLocked()
	d.mu.Unlock()
	d.broadcastVoiceMembers(ipcServer, payload, ok)
}

func (d *voiceDaemon) removeVoiceMember(userID string) {
	id := strings.TrimSpace(userID)
	if id == "" {
		return
	}
	d.mu.Lock()
	if len(d.memb) == 0 {
		d.mu.Unlock()
		return
	}
	if _, exists := d.memb[id]; !exists {
		d.mu.Unlock()
		return
	}
	delete(d.memb, id)
	if local := strings.TrimSpace(d.local); local != "" && d.room != "" {
		d.memb[local] = struct{}{}
	}
	ipcServer, payload, ok := d.voiceMembersPayloadLocked()
	d.mu.Unlock()
	d.broadcastVoiceMembers(ipcServer, payload, ok)
}

func (d *voiceDaemon) voiceMembersPayloadLocked() (*ipcServer, ipc.Message, bool) {
	if d.ipc == nil || d.room == "" {
		return nil, ipc.Message{}, false
	}
	users := make([]string, 0, len(d.memb))
	for id := range d.memb {
		users = append(users, id)
	}
	sort.Strings(users)
	payload := ipc.Message{Event: ipc.EventVoiceMembers, Room: d.room, Users: users}
	return d.ipc, payload, true
}

func (d *voiceDaemon) broadcastVoiceMembers(ipcServer *ipcServer, payload ipc.Message, ok bool) {
	if !ok || ipcServer == nil || payload.Event == "" {
		return
	}
	ipcServer.Broadcast(payload)
}
