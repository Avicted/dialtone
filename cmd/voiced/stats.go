package main

import (
	"context"
	"log"
	"sync/atomic"
	"time"
)

type voiceStats struct {
	bytesSent     atomic.Int64
	framesSent    atomic.Int64
	framesDropped atomic.Int64
}

func newVoiceStats() *voiceStats {
	return &voiceStats{}
}

func (s *voiceStats) RecordSent(bytes int) {
	if s == nil || bytes <= 0 {
		return
	}
	s.bytesSent.Add(int64(bytes))
	s.framesSent.Add(1)
}

func (s *voiceStats) RecordDrop() {
	if s == nil {
		return
	}
	s.framesDropped.Add(1)
}

func (s *voiceStats) LogLoop(ctx context.Context) {
	if s == nil {
		return
	}
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			bytes := s.bytesSent.Swap(0)
			frames := s.framesSent.Swap(0)
			dropped := s.framesDropped.Swap(0)
			bitrate := float64(bytes*8) / 10.0 / 1000.0
			log.Printf("voice stats: kbps=%.1f frames=%d dropped=%d", bitrate, frames, dropped)
		}
	}
}
