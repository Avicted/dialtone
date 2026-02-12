//go:build linux

package main

import (
	"log"
	"time"

	"github.com/Avicted/dialtone/internal/audio"
	"github.com/hraban/opus"
	"github.com/pion/webrtc/v4"
)

const maxRemoteFrameSize = opusFrameSize * 6
const remoteSpeakingTimeout = 600 * time.Millisecond

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
		done := make(chan struct{})
		pulse := make(chan struct{}, 1)
		go d.trackRemoteSpeaking(peerID, pulse, done)

		pcm := make([]int16, maxRemoteFrameSize)
		for {
			pkt, _, err := track.ReadRTP()
			if err != nil {
				close(done)
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
			select {
			case pulse <- struct{}{}:
			default:
			}
		}
	}()
}

func (d *voiceDaemon) trackRemoteSpeaking(peerID string, pulse <-chan struct{}, done <-chan struct{}) {
	timer := time.NewTimer(remoteSpeakingTimeout)
	defer timer.Stop()

	active := false
	for {
		select {
		case <-done:
			return
		case <-pulse:
			if !active {
				d.setRemoteSpeaking(peerID, true)
				active = true
			}
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(remoteSpeakingTimeout)
		case <-timer.C:
			if active {
				d.setRemoteSpeaking(peerID, false)
				active = false
			}
			timer.Reset(remoteSpeakingTimeout)
		}
	}
}
