package main

import (
	"log"

	"github.com/Avicted/dialtone/internal/audio"
	"github.com/Avicted/dialtone/internal/ipc"
	"github.com/hraban/opus"
	"github.com/pion/webrtc/v4"
)

const maxRemoteFrameSize = opusFrameSize * 6

func (d *voiceDaemon) handleRemoteTrack(peerID string, track *webrtc.TrackRemote) {
	if track == nil || track.Kind() != webrtc.RTPCodecTypeAudio {
		return
	}
	decoder, err := opus.NewDecoder(audio.SampleRate, audio.Channels)
	if err != nil {
		log.Printf("opus decoder init failed: %v", err)
		return
	}

	go func() {
		pcm := make([]int16, maxRemoteFrameSize)
		for {
			pkt, _, err := track.ReadRTP()
			if err != nil {
				d.setRemoteSpeaking(peerID, false)
				return
			}
			if len(pkt.Payload) == 0 {
				continue
			}
			n, err := decoder.Decode(pkt.Payload, pcm)
			if err != nil {
				log.Printf("opus decode failed: %v", err)
				continue
			}
			if n <= 0 {
				continue
			}
			d.writePlayback(pcm[:n])
			level := voiceLevel(pcm[:n])
			active := isVoiceActive(level, d.vadThreshold)
			d.setRemoteSpeaking(peerID, active)
		}
	}()
}

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
