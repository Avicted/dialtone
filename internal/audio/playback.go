//go:build linux

package audio

import (
	"context"
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/gen2brain/malgo"
)

const maxPlaybackBufferSeconds = 2

type Playback struct {
	ctx    *malgo.AllocatedContext
	device *malgo.Device

	mu        sync.Mutex
	buf       []int16
	maxBuf    int
	closeOnce sync.Once
}

func StartPlayback(ctx context.Context) (*Playback, error) {
	config := malgo.ContextConfig{}
	malgoCtx, err := malgoInitContext(nil, config, nil)
	if err != nil {
		return nil, fmt.Errorf("init malgo context: %w", err)
	}

	deviceConfig := malgoDefaultDeviceConfig(malgo.Playback)
	deviceConfig.Playback.Format = malgo.FormatS16
	deviceConfig.Playback.Channels = Channels
	deviceConfig.SampleRate = SampleRate

	player := &Playback{
		ctx:    malgoCtx,
		maxBuf: SampleRate * maxPlaybackBufferSeconds,
	}

	callback := malgo.DeviceCallbacks{
		Data: func(output, _ []byte, _ uint32) {
			player.fillOutput(output)
		},
	}

	device, err := malgoInitDevice(malgoCtx.Context, deviceConfig, callback)
	if err != nil {
		malgoContextUninit(malgoCtx)
		return nil, fmt.Errorf("init playback device: %w", err)
	}
	if err := malgoDeviceStart(device); err != nil {
		malgoDeviceUninit(device)
		malgoContextUninit(malgoCtx)
		return nil, fmt.Errorf("start playback: %w", err)
	}

	player.device = device
	go func() {
		<-ctx.Done()
		_ = player.Close()
	}()

	return player, nil
}

func (p *Playback) Write(samples []int16) {
	if p == nil || len(samples) == 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.maxBuf <= 0 {
		p.maxBuf = SampleRate * maxPlaybackBufferSeconds
	}
	if len(p.buf)+len(samples) > p.maxBuf {
		drop := len(p.buf) + len(samples) - p.maxBuf
		if drop >= len(p.buf) {
			p.buf = p.buf[:0]
		} else {
			p.buf = p.buf[drop:]
		}
	}
	p.buf = append(p.buf, samples...)
}

func (p *Playback) fillOutput(output []byte) {
	if p == nil || len(output) == 0 {
		return
	}
	sampleCount := len(output) / 2
	p.mu.Lock()
	available := len(p.buf)
	use := sampleCount
	if available < use {
		use = available
	}
	for i := 0; i < use; i++ {
		binary.LittleEndian.PutUint16(output[i*2:], uint16(p.buf[i]))
	}
	if use < sampleCount {
		for i := use; i < sampleCount; i++ {
			binary.LittleEndian.PutUint16(output[i*2:], 0)
		}
	}
	if use > 0 {
		copy(p.buf, p.buf[use:])
		p.buf = p.buf[:available-use]
	}
	p.mu.Unlock()
}

func (p *Playback) Close() error {
	if p == nil {
		return nil
	}
	p.closeOnce.Do(func() {
		if p.device != nil {
			malgoDeviceUninit(p.device)
			p.device = nil
		}
		if p.ctx != nil {
			malgoContextUninit(p.ctx)
			p.ctx = nil
		}
	})
	return nil
}
