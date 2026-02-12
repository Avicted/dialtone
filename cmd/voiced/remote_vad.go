package main

import (
	"github.com/Avicted/dialtone/internal/ipc"
)

func (d *voiceDaemon) setRemoteSpeaking(peerID string, active bool) {
	if peerID == "" {
		return
	}
	d.mu.Lock()
	if d.rem == nil {
		d.rem = make(map[string]bool)
	}
	prev := d.rem[peerID]
	if prev == active {
		d.mu.Unlock()
		return
	}
	d.rem[peerID] = active
	ipcServer := d.ipc
	d.mu.Unlock()

	if ipcServer == nil {
		return
	}
	ipcServer.Broadcast(ipc.Message{Event: ipc.EventUserSpeaking, User: peerID, Active: active})
}

func (d *voiceDaemon) clearRemoteSpeaking() {
	d.mu.Lock()
	ids := make([]string, 0, len(d.rem))
	for id, active := range d.rem {
		if active {
			ids = append(ids, id)
		}
	}
	d.rem = make(map[string]bool)
	ipcServer := d.ipc
	d.mu.Unlock()

	if ipcServer == nil {
		return
	}
	for _, id := range ids {
		ipcServer.Broadcast(ipc.Message{Event: ipc.EventUserSpeaking, User: id, Active: false})
	}
}
