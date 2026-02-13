package main

import (
	"context"
	"testing"
	"time"
)

func TestVoiceStatsRecordSentAndDrop(t *testing.T) {
	var nilStats *voiceStats
	nilStats.RecordSent(100)
	nilStats.RecordDrop()

	s := newVoiceStats()
	s.RecordSent(0)
	s.RecordSent(-1)
	s.RecordSent(120)
	s.RecordDrop()
	s.RecordDrop()

	if got := s.bytesSent.Load(); got != 120 {
		t.Fatalf("bytesSent = %d, want 120", got)
	}
	if got := s.framesSent.Load(); got != 1 {
		t.Fatalf("framesSent = %d, want 1", got)
	}
	if got := s.framesDropped.Load(); got != 2 {
		t.Fatalf("framesDropped = %d, want 2", got)
	}
}

func TestVoiceStatsLogLoopStopsOnContextCancel(t *testing.T) {
	var nilStats *voiceStats
	nilStats.LogLoop(context.Background())

	s := newVoiceStats()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.LogLoop(ctx)
		close(done)
	}()

	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("LogLoop did not stop after cancel")
	}
}

func TestVoiceStatsLogLoopFlushesCountersOnTick(t *testing.T) {
	s := newVoiceStats()
	s.RecordSent(1600)
	s.RecordDrop()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.LogLoop(ctx)
		close(done)
	}()

	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		if s.bytesSent.Load() == 0 && s.framesSent.Load() == 0 && s.framesDropped.Load() == 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if s.bytesSent.Load() != 0 || s.framesSent.Load() != 0 || s.framesDropped.Load() != 0 {
		cancel()
		<-done
		t.Fatalf("expected counters to be reset after log loop tick")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("LogLoop did not stop after cancel")
	}
}
