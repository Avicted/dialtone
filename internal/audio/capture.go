//go:build linux

package audio

import (
	"context"
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/gen2brain/malgo"
)

const (
	SampleRate = 48000
	Channels   = 1
)

type Capture struct {
	ctx    *malgo.AllocatedContext
	device *malgo.Device

	closeOnce sync.Once
}

func StartCapture(ctx context.Context) (*Capture, <-chan []int16, error) {
	config := malgo.ContextConfig{}
	malgoCtx, err := malgoInitContext(nil, config, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("init malgo context: %w", err)
	}

	deviceConfig := malgoDefaultDeviceConfig(malgo.Capture)
	deviceConfig.Capture.Format = malgo.FormatS16
	deviceConfig.Capture.Channels = Channels
	deviceConfig.SampleRate = SampleRate

	ch := make(chan []int16, 8)
	callback := malgo.DeviceCallbacks{
		Data: func(_, input []byte, _ uint32) {
			if len(input) == 0 {
				return
			}
			samples := make([]int16, len(input)/2)
			for i := 0; i < len(samples); i++ {
				samples[i] = int16(binary.LittleEndian.Uint16(input[i*2:]))
			}
			select {
			case ch <- samples:
			default:
			}
		},
	}

	device, err := malgoInitDevice(malgoCtx.Context, deviceConfig, callback)
	if err != nil {
		malgoContextUninit(malgoCtx)
		return nil, nil, fmt.Errorf("init capture device: %w", err)
	}
	if err := malgoDeviceStart(device); err != nil {
		malgoDeviceUninit(device)
		malgoContextUninit(malgoCtx)
		return nil, nil, fmt.Errorf("start capture: %w", err)
	}

	cap := &Capture{ctx: malgoCtx, device: device}
	go func() {
		<-ctx.Done()
		_ = cap.Close()
	}()

	return cap, ch, nil
}

func (c *Capture) Close() error {
	if c == nil {
		return nil
	}
	c.closeOnce.Do(func() {
		if c.device != nil {
			malgoDeviceUninit(c.device)
			c.device = nil
		}
		if c.ctx != nil {
			malgoContextUninit(c.ctx)
			c.ctx = nil
		}
	})
	return nil
}
