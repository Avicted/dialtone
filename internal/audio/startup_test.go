//go:build linux

package audio

import (
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gen2brain/malgo"
)

func saveAndRestoreMalgoHooks(t *testing.T) {
	t.Helper()
	origInitContext := malgoInitContext
	origDefaultDeviceConfig := malgoDefaultDeviceConfig
	origInitDevice := malgoInitDevice
	origContextUninit := malgoContextUninit
	origDeviceStart := malgoDeviceStart
	origDeviceUninit := malgoDeviceUninit

	t.Cleanup(func() {
		malgoInitContext = origInitContext
		malgoDefaultDeviceConfig = origDefaultDeviceConfig
		malgoInitDevice = origInitDevice
		malgoContextUninit = origContextUninit
		malgoDeviceStart = origDeviceStart
		malgoDeviceUninit = origDeviceUninit
	})
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("condition not met before timeout")
}

func decodeInt16LE(buf []byte, idx int) int16 {
	return int16(binary.LittleEndian.Uint16(buf[idx*2:]))
}

func TestStartCaptureInitContextError(t *testing.T) {
	saveAndRestoreMalgoHooks(t)

	malgoInitContext = func([]malgo.Backend, malgo.ContextConfig, malgo.LogProc) (*malgo.AllocatedContext, error) {
		return nil, errors.New("boom")
	}

	capture, ch, err := StartCapture(context.Background())
	if err == nil || !strings.Contains(err.Error(), "init malgo context") {
		t.Fatalf("error = %v, want init malgo context failure", err)
	}
	if capture != nil || ch != nil {
		t.Fatalf("expected nil capture/channel on init context error, got capture=%v channel=%v", capture, ch)
	}
}

func TestStartCaptureInitDeviceErrorUninitsContext(t *testing.T) {
	saveAndRestoreMalgoHooks(t)

	ctxUninitCalls := 0
	malgoInitContext = func([]malgo.Backend, malgo.ContextConfig, malgo.LogProc) (*malgo.AllocatedContext, error) {
		return &malgo.AllocatedContext{}, nil
	}
	malgoDefaultDeviceConfig = func(malgo.DeviceType) malgo.DeviceConfig {
		return malgo.DeviceConfig{}
	}
	malgoInitDevice = func(malgo.Context, malgo.DeviceConfig, malgo.DeviceCallbacks) (*malgo.Device, error) {
		return nil, errors.New("no device")
	}
	malgoContextUninit = func(*malgo.AllocatedContext) error {
		ctxUninitCalls++
		return nil
	}

	capture, ch, err := StartCapture(context.Background())
	if err == nil || !strings.Contains(err.Error(), "init capture device") {
		t.Fatalf("error = %v, want init capture device failure", err)
	}
	if capture != nil || ch != nil {
		t.Fatalf("expected nil capture/channel on init device error, got capture=%v channel=%v", capture, ch)
	}
	if ctxUninitCalls != 1 {
		t.Fatalf("context uninit calls = %d, want 1", ctxUninitCalls)
	}
}

func TestStartCaptureStartErrorUninitsDeviceAndContext(t *testing.T) {
	saveAndRestoreMalgoHooks(t)

	ctxUninitCalls := 0
	deviceUninitCalls := 0
	malgoInitContext = func([]malgo.Backend, malgo.ContextConfig, malgo.LogProc) (*malgo.AllocatedContext, error) {
		return &malgo.AllocatedContext{}, nil
	}
	malgoDefaultDeviceConfig = func(malgo.DeviceType) malgo.DeviceConfig {
		return malgo.DeviceConfig{}
	}
	malgoInitDevice = func(malgo.Context, malgo.DeviceConfig, malgo.DeviceCallbacks) (*malgo.Device, error) {
		return &malgo.Device{}, nil
	}
	malgoDeviceStart = func(*malgo.Device) error {
		return errors.New("start failed")
	}
	malgoDeviceUninit = func(*malgo.Device) {
		deviceUninitCalls++
	}
	malgoContextUninit = func(*malgo.AllocatedContext) error {
		ctxUninitCalls++
		return nil
	}

	capture, ch, err := StartCapture(context.Background())
	if err == nil || !strings.Contains(err.Error(), "start capture") {
		t.Fatalf("error = %v, want start capture failure", err)
	}
	if capture != nil || ch != nil {
		t.Fatalf("expected nil capture/channel on start error, got capture=%v channel=%v", capture, ch)
	}
	if deviceUninitCalls != 1 || ctxUninitCalls != 1 {
		t.Fatalf("uninit calls device=%d ctx=%d, want 1 each", deviceUninitCalls, ctxUninitCalls)
	}
}

func TestStartCaptureSuccessConvertsSamplesDropsOverflowAndClosesOnCancel(t *testing.T) {
	saveAndRestoreMalgoHooks(t)

	ctxUninitCalls := 0
	deviceUninitCalls := 0
	var callbacks malgo.DeviceCallbacks

	malgoInitContext = func([]malgo.Backend, malgo.ContextConfig, malgo.LogProc) (*malgo.AllocatedContext, error) {
		return &malgo.AllocatedContext{}, nil
	}
	malgoDefaultDeviceConfig = func(malgo.DeviceType) malgo.DeviceConfig {
		return malgo.DeviceConfig{}
	}
	malgoInitDevice = func(_ malgo.Context, cfg malgo.DeviceConfig, cb malgo.DeviceCallbacks) (*malgo.Device, error) {
		if cfg.Capture.Channels != Channels {
			t.Fatalf("capture channels = %d, want %d", cfg.Capture.Channels, Channels)
		}
		if cfg.SampleRate != SampleRate {
			t.Fatalf("sample rate = %d, want %d", cfg.SampleRate, SampleRate)
		}
		if cfg.Capture.Format != malgo.FormatS16 {
			t.Fatalf("capture format = %v, want %v", cfg.Capture.Format, malgo.FormatS16)
		}
		callbacks = cb
		return &malgo.Device{}, nil
	}
	malgoDeviceStart = func(*malgo.Device) error { return nil }
	malgoDeviceUninit = func(*malgo.Device) { deviceUninitCalls++ }
	malgoContextUninit = func(*malgo.AllocatedContext) error {
		ctxUninitCalls++
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	capture, ch, err := StartCapture(ctx)
	if err != nil {
		t.Fatalf("StartCapture() error: %v", err)
	}
	if capture == nil || ch == nil {
		t.Fatalf("StartCapture() returned capture=%v channel=%v", capture, ch)
	}
	if callbacks.Data == nil {
		t.Fatal("expected data callback to be set")
	}

	callbacks.Data(nil, []byte{1, 0, 255, 127}, 0)
	got := <-ch
	if len(got) != 2 || got[0] != 1 || got[1] != 32767 {
		t.Fatalf("decoded samples = %#v, want [1 32767]", got)
	}

	callbacks.Data(nil, nil, 0)
	select {
	case extra := <-ch:
		t.Fatalf("unexpected extra samples for empty input: %#v", extra)
	default:
	}

	for i := 0; i < 9; i++ {
		callbacks.Data(nil, []byte{9, 0}, 0)
	}
	if len(ch) != 8 {
		t.Fatalf("channel length = %d, want bounded length 8", len(ch))
	}

	cancel()
	waitFor(t, 200*time.Millisecond, func() bool {
		return deviceUninitCalls == 1 && ctxUninitCalls == 1
	})

	if err := capture.Close(); err != nil {
		t.Fatalf("capture.Close() error: %v", err)
	}
	if deviceUninitCalls != 1 || ctxUninitCalls != 1 {
		t.Fatalf("close should be idempotent; got device=%d ctx=%d", deviceUninitCalls, ctxUninitCalls)
	}
}

func TestStartPlaybackInitContextError(t *testing.T) {
	saveAndRestoreMalgoHooks(t)

	malgoInitContext = func([]malgo.Backend, malgo.ContextConfig, malgo.LogProc) (*malgo.AllocatedContext, error) {
		return nil, errors.New("boom")
	}

	p, err := StartPlayback(context.Background())
	if err == nil || !strings.Contains(err.Error(), "init malgo context") {
		t.Fatalf("error = %v, want init malgo context failure", err)
	}
	if p != nil {
		t.Fatalf("expected nil playback on init context error, got %v", p)
	}
}

func TestStartPlaybackInitDeviceErrorUninitsContext(t *testing.T) {
	saveAndRestoreMalgoHooks(t)

	ctxUninitCalls := 0
	malgoInitContext = func([]malgo.Backend, malgo.ContextConfig, malgo.LogProc) (*malgo.AllocatedContext, error) {
		return &malgo.AllocatedContext{}, nil
	}
	malgoDefaultDeviceConfig = func(malgo.DeviceType) malgo.DeviceConfig {
		return malgo.DeviceConfig{}
	}
	malgoInitDevice = func(malgo.Context, malgo.DeviceConfig, malgo.DeviceCallbacks) (*malgo.Device, error) {
		return nil, errors.New("no output")
	}
	malgoContextUninit = func(*malgo.AllocatedContext) error {
		ctxUninitCalls++
		return nil
	}

	p, err := StartPlayback(context.Background())
	if err == nil || !strings.Contains(err.Error(), "init playback device") {
		t.Fatalf("error = %v, want init playback device failure", err)
	}
	if p != nil {
		t.Fatalf("expected nil playback on init device error, got %v", p)
	}
	if ctxUninitCalls != 1 {
		t.Fatalf("context uninit calls = %d, want 1", ctxUninitCalls)
	}
}

func TestStartPlaybackStartErrorUninitsDeviceAndContext(t *testing.T) {
	saveAndRestoreMalgoHooks(t)

	ctxUninitCalls := 0
	deviceUninitCalls := 0
	malgoInitContext = func([]malgo.Backend, malgo.ContextConfig, malgo.LogProc) (*malgo.AllocatedContext, error) {
		return &malgo.AllocatedContext{}, nil
	}
	malgoDefaultDeviceConfig = func(malgo.DeviceType) malgo.DeviceConfig {
		return malgo.DeviceConfig{}
	}
	malgoInitDevice = func(malgo.Context, malgo.DeviceConfig, malgo.DeviceCallbacks) (*malgo.Device, error) {
		return &malgo.Device{}, nil
	}
	malgoDeviceStart = func(*malgo.Device) error {
		return errors.New("start failed")
	}
	malgoDeviceUninit = func(*malgo.Device) {
		deviceUninitCalls++
	}
	malgoContextUninit = func(*malgo.AllocatedContext) error {
		ctxUninitCalls++
		return nil
	}

	p, err := StartPlayback(context.Background())
	if err == nil || !strings.Contains(err.Error(), "start playback") {
		t.Fatalf("error = %v, want start playback failure", err)
	}
	if p != nil {
		t.Fatalf("expected nil playback on start error, got %v", p)
	}
	if deviceUninitCalls != 1 || ctxUninitCalls != 1 {
		t.Fatalf("uninit calls device=%d ctx=%d, want 1 each", deviceUninitCalls, ctxUninitCalls)
	}
}

func TestStartPlaybackSuccessFillsOutputAndClosesOnCancel(t *testing.T) {
	saveAndRestoreMalgoHooks(t)

	ctxUninitCalls := 0
	deviceUninitCalls := 0
	var callbacks malgo.DeviceCallbacks

	malgoInitContext = func([]malgo.Backend, malgo.ContextConfig, malgo.LogProc) (*malgo.AllocatedContext, error) {
		return &malgo.AllocatedContext{}, nil
	}
	malgoDefaultDeviceConfig = func(malgo.DeviceType) malgo.DeviceConfig {
		return malgo.DeviceConfig{}
	}
	malgoInitDevice = func(_ malgo.Context, cfg malgo.DeviceConfig, cb malgo.DeviceCallbacks) (*malgo.Device, error) {
		if cfg.Playback.Channels != Channels {
			t.Fatalf("playback channels = %d, want %d", cfg.Playback.Channels, Channels)
		}
		if cfg.SampleRate != SampleRate {
			t.Fatalf("sample rate = %d, want %d", cfg.SampleRate, SampleRate)
		}
		if cfg.Playback.Format != malgo.FormatS16 {
			t.Fatalf("playback format = %v, want %v", cfg.Playback.Format, malgo.FormatS16)
		}
		callbacks = cb
		return &malgo.Device{}, nil
	}
	malgoDeviceStart = func(*malgo.Device) error { return nil }
	malgoDeviceUninit = func(*malgo.Device) { deviceUninitCalls++ }
	malgoContextUninit = func(*malgo.AllocatedContext) error {
		ctxUninitCalls++
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p, err := StartPlayback(ctx)
	if err != nil {
		t.Fatalf("StartPlayback() error: %v", err)
	}
	if p == nil {
		t.Fatal("StartPlayback() returned nil playback")
	}
	if p.maxBuf != SampleRate*maxPlaybackBufferSeconds {
		t.Fatalf("maxBuf = %d, want %d", p.maxBuf, SampleRate*maxPlaybackBufferSeconds)
	}
	if callbacks.Data == nil {
		t.Fatal("expected playback callback to be set")
	}

	p.Write([]int16{7, 8})
	out := make([]byte, 6)
	callbacks.Data(out, nil, 0)
	if got := decodeInt16LE(out, 0); got != 7 {
		t.Fatalf("sample0 = %d, want 7", got)
	}
	if got := decodeInt16LE(out, 1); got != 8 {
		t.Fatalf("sample1 = %d, want 8", got)
	}
	if got := decodeInt16LE(out, 2); got != 0 {
		t.Fatalf("sample2 = %d, want 0", got)
	}

	cancel()
	waitFor(t, 200*time.Millisecond, func() bool {
		return deviceUninitCalls == 1 && ctxUninitCalls == 1
	})

	if err := p.Close(); err != nil {
		t.Fatalf("playback.Close() error: %v", err)
	}
	if deviceUninitCalls != 1 || ctxUninitCalls != 1 {
		t.Fatalf("close should be idempotent; got device=%d ctx=%d", deviceUninitCalls, ctxUninitCalls)
	}
}
