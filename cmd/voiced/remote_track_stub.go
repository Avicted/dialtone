//go:build !linux

package main

import "github.com/pion/webrtc/v4"

func (d *voiceDaemon) handleRemoteTrack(peerID string, track *webrtc.TrackRemote) {
	if peerID != "" {
		d.setRemoteSpeaking(peerID, false)
	}
}
