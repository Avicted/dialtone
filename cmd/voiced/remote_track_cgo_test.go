//go:build linux

package main

import (
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
)

func TestHandleRemoteTrackNilAndNonAudioNoPanic(t *testing.T) {
	d := newVoiceDaemon("http://server", "token", "", pttBackendAuto, webrtc.Configuration{}, 20, false)

	d.handleRemoteTrack("peer-1", nil)
}

func TestTrackRemoteSpeakingPulseAndTimeout(t *testing.T) {
	d := newVoiceDaemon("http://server", "token", "", pttBackendAuto, webrtc.Configuration{}, 20, false)
	pulse := make(chan struct{}, 1)
	done := make(chan struct{})

	finished := make(chan struct{})
	go func() {
		d.trackRemoteSpeaking("peer-1", pulse, done)
		close(finished)
	}()

	pulse <- struct{}{}
	time.Sleep(50 * time.Millisecond)

	d.mu.Lock()
	active := d.rem["peer-1"]
	d.mu.Unlock()
	if !active {
		t.Fatalf("expected peer to become active after pulse")
	}

	time.Sleep(remoteSpeakingTimeout + 150*time.Millisecond)

	d.mu.Lock()
	active = d.rem["peer-1"]
	d.mu.Unlock()
	if active {
		t.Fatalf("expected peer to become inactive after timeout")
	}

	close(done)
	select {
	case <-time.After(2 * time.Second):
		t.Fatal("trackRemoteSpeaking did not stop after done")
	case <-finished:
	}
}
