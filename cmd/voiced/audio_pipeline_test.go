//go:build linux

package main

import (
	"context"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
)

func TestAudioBackoffClamp(t *testing.T) {
	tests := []struct {
		attempt int
		want    time.Duration
	}{
		{attempt: 0, want: 2 * time.Second},
		{attempt: 1, want: 2 * time.Second},
		{attempt: 3, want: 8 * time.Second},
		{attempt: 5, want: 32 * time.Second},
		{attempt: 100, want: 32 * time.Second},
	}

	for _, tt := range tests {
		if got := audioBackoff(tt.attempt); got != tt.want {
			t.Fatalf("audioBackoff(%d) = %v, want %v", tt.attempt, got, tt.want)
		}
	}
}

func TestVoiceLevelAndIsVoiceActive(t *testing.T) {
	if got := voiceLevel(nil); got != 0 {
		t.Fatalf("voiceLevel(nil) = %d, want 0", got)
	}
	if got := voiceLevel([]int16{-10, 20, -30, 40}); got != 25 {
		t.Fatalf("voiceLevel abs average mismatch: got %d, want 25", got)
	}

	if !isVoiceActive(25, 25) {
		t.Fatalf("expected voice active at threshold")
	}
	if isVoiceActive(24, 25) {
		t.Fatalf("expected voice inactive below threshold")
	}
}

func TestUpdateVADFromFrameAndMeterBehavior(t *testing.T) {
	d := newVoiceDaemon("http://server", "token", "", pttBackendAuto, webrtc.Configuration{}, 20, true)
	d.local = "alice"

	active := d.updateVADFromFrame([]int16{30, -30, 30, -30})
	if !active {
		t.Fatalf("expected frame to be active")
	}
	if !d.isSpeaking() {
		t.Fatalf("expected speaking after active VAD frame")
	}

	d.muted = true
	inactive := d.updateVADFromFrame([]int16{5, -5, 5, -5})
	if inactive {
		t.Fatalf("expected low-level frame to be inactive")
	}
	if d.isSpeaking() {
		t.Fatalf("expected muted daemon to report not speaking")
	}

	d.muted = false
	d.meter = true
	d.vadThreshold = 15
	d.meterNext = time.Time{}
	d.maybeLogMeter(16)
	firstNext := d.meterNext
	if firstNext.IsZero() {
		t.Fatalf("expected meterNext to be scheduled when meter is enabled")
	}
	d.maybeLogMeter(16)
	if !d.meterNext.Equal(firstNext) {
		t.Fatalf("expected meterNext unchanged inside interval")
	}

	d.pttBind = "ctrl+v"
	d.setSpeaking(false)
	d.updateVADFromFrame([]int16{100, 100, 100, 100})
	if d.isSpeaking() {
		t.Fatalf("expected VAD updates ignored while PTT binding is active")
	}
}

func TestRunAudioSessionCanceledContextReturns(t *testing.T) {
	d := newVoiceDaemon("http://server", "token", "", pttBackendAuto, webrtc.Configuration{}, 20, false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan error, 1)
	go func() {
		done <- d.runAudioSession(ctx)
	}()

	select {
	case <-time.After(3 * time.Second):
		t.Fatal("runAudioSession did not return promptly for canceled context")
	case <-done:
	}
}
