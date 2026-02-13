//go:build linux

package audio

import (
	"context"
	"testing"
	"time"
)

func TestStartCaptureSmokeAndCloseSafety(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	capture, samples, err := StartCapture(ctx)
	if err != nil {
		return
	}
	if capture == nil || samples == nil {
		t.Fatalf("StartCapture() returned capture=%v samples=%v", capture, samples)
	}

	cancel()
	time.Sleep(20 * time.Millisecond)

	if err := capture.Close(); err != nil {
		t.Fatalf("capture.Close() error: %v", err)
	}
}

func TestCaptureCloseNilAndZeroSafety(t *testing.T) {
	var capture *Capture
	if err := capture.Close(); err != nil {
		t.Fatalf("nil capture close: %v", err)
	}

	empty := &Capture{}
	if err := empty.Close(); err != nil {
		t.Fatalf("empty capture close: %v", err)
	}
}
