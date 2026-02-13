package main

import (
	"context"
	"testing"
	"time"
)

func TestLogCPUUsageStopsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		logCPUUsage(ctx)
		close(done)
	}()

	cancel()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatalf("logCPUUsage did not return after context cancellation")
	}
}
