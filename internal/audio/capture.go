//go:build linux

package audio

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/gen2brain/malgo"
)

const (
	SampleRate = 48000
	Channels   = 1
)

type Capture struct {
	ctx    *malgo.AllocatedContext
	device *malgo.Device
}

func StartCapture(ctx context.Context) (*Capture, <-chan []int16, error) {
	config := malgo.ContextConfig{}
	malgoCtx, err := malgo.InitContext(nil, config, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("init malgo context: %w", err)
	}

	deviceConfig := malgo.DefaultDeviceConfig(malgo.Capture)
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

	device, err := malgo.InitDevice(malgoCtx.Context, deviceConfig, callback)
	if err != nil {
		malgoCtx.Uninit()
		return nil, nil, fmt.Errorf("init capture device: %w", err)
	}
	if err := device.Start(); err != nil {
		device.Uninit()
		malgoCtx.Uninit()
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
	if c.device != nil {
		c.device.Uninit()
		c.device = nil
	}
	if c.ctx != nil {
		c.ctx.Uninit()
		c.ctx = nil
	}
	return nil
}
