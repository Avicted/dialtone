//go:build !linux

package audio

import (
	"context"
	"fmt"
)

const (
	SampleRate = 48000
	Channels   = 1
)

type Capture struct{}

type Playback struct{}

func StartCapture(context.Context) (*Capture, <-chan []int16, error) {
	return nil, nil, fmt.Errorf("audio capture is supported on linux only")
}

func (c *Capture) Close() error {
	return nil
}

func StartPlayback(context.Context) (*Playback, error) {
	return nil, fmt.Errorf("audio playback is supported on linux only")
}

func (p *Playback) Write([]int16) {}

func (p *Playback) Close() error {
	return nil
}
