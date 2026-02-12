//go:build linux

package main

import (
	"log"

	"github.com/Avicted/dialtone/internal/audio"
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
