//go:build linux

package audio

import (
	"context"
	"encoding/binary"
	"testing"
	"time"
)

func decodeSample(t *testing.T, out []byte, idx int) int16 {
	t.Helper()
	return int16(binary.LittleEndian.Uint16(out[idx*2:]))
}

func TestPlaybackWriteAndFillOutput(t *testing.T) {
	p := &Playback{maxBuf: 4}
	p.Write([]int16{1, 2, 3})
	p.Write([]int16{4, 5})

	if len(p.buf) != 4 {
		t.Fatalf("expected bounded playback buffer length 4, got %d", len(p.buf))
	}
	if p.buf[0] != 2 || p.buf[3] != 5 {
		t.Fatalf("unexpected buffer contents after overflow write: %#v", p.buf)
	}

	out := make([]byte, 6)
	p.fillOutput(out)
	if got := decodeSample(t, out, 0); got != 2 {
		t.Fatalf("sample0 = %d, want 2", got)
	}
	if got := decodeSample(t, out, 1); got != 3 {
		t.Fatalf("sample1 = %d, want 3", got)
	}
	if got := decodeSample(t, out, 2); got != 4 {
		t.Fatalf("sample2 = %d, want 4", got)
	}

	out = make([]byte, 4)
	p.fillOutput(out)
	if got := decodeSample(t, out, 0); got != 5 {
		t.Fatalf("sample0 = %d, want 5", got)
	}
	if got := decodeSample(t, out, 1); got != 0 {
		t.Fatalf("sample1 = %d, want zero padding", got)
	}

	if len(p.buf) != 0 {
		t.Fatalf("expected buffer fully drained, got %d", len(p.buf))
	}
}

func TestPlaybackNilAndCloseSafety(t *testing.T) {
	var p *Playback
	p.Write([]int16{1, 2, 3})
	p.fillOutput(make([]byte, 4))
	if err := p.Close(); err != nil {
		t.Fatalf("nil playback close: %v", err)
	}

	instance := &Playback{}
	instance.Write(nil)
	instance.fillOutput(nil)
	if err := instance.Close(); err != nil {
		t.Fatalf("zero playback close: %v", err)
	}
}

func TestStartPlaybackSmoke(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	playback, err := StartPlayback(ctx)
	if err != nil {
		return
	}
	if playback == nil {
		t.Fatal("StartPlayback() returned nil playback without error")
	}

	playback.Write([]int16{1, 2, 3})
	cancel()
	time.Sleep(20 * time.Millisecond)

	if err := playback.Close(); err != nil {
		t.Fatalf("playback.Close() error: %v", err)
	}
}
