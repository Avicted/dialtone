package main

import (
	"context"
	"log"
	"time"

	"github.com/Avicted/dialtone/internal/audio"
	"github.com/hraban/opus"
)

const (
	opusFrameSize = 960
	opusMaxBytes  = 4000
	vadThreshold  = 500
)

func (d *voiceDaemon) runAudio(ctx context.Context) error {
	attempt := 0
	for {
		if ctx.Err() != nil {
			return nil
		}
		if err := d.runAudioSession(ctx); err != nil {
			attempt++
			log.Printf("audio capture failed: %v", err)
			delay := audioBackoff(attempt)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(delay):
			}
			continue
		}
		return nil
	}
}

func (d *voiceDaemon) runAudioSession(ctx context.Context) error {
	capture, audioCh, err := audio.StartCapture(ctx)
	if err != nil {
		return err
	}
	defer capture.Close()

	encoder, err := opus.NewEncoder(audio.SampleRate, audio.Channels, opus.AppVoIP)
	if err != nil {
		return err
	}

	buf := make([]int16, 0, opusFrameSize*4)
	frameDuration := 20 * time.Millisecond

	for {
		select {
		case <-ctx.Done():
			return nil
		case samples := <-audioCh:
			if len(samples) == 0 {
				continue
			}
			buf = append(buf, samples...)
			for len(buf) >= opusFrameSize {
				frame := buf[:opusFrameSize]
				buf = buf[opusFrameSize:]
				if d.updateVADFromFrame(frame) && !d.isSpeaking() {
					if d.sts != nil {
						d.sts.RecordDrop()
					}
					continue
				}
				if !d.isSpeaking() {
					if d.sts != nil {
						d.sts.RecordDrop()
					}
					continue
				}
				packet := make([]byte, opusMaxBytes)
				n, err := encoder.Encode(frame, packet)
				if err != nil {
					log.Printf("opus encode failed: %v", err)
					continue
				}
				if d.pc != nil {
					if err := d.pc.WriteSample(packet[:n], frameDuration); err != nil {
						log.Printf("webrtc write sample failed: %v", err)
					}
				}
				if d.sts != nil {
					d.sts.RecordSent(n)
				}
			}
		}
	}
}

func audioBackoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 5 {
		attempt = 5
	}
	return time.Duration(1<<attempt) * time.Second
}

func (d *voiceDaemon) updateVADFromFrame(frame []int16) bool {
	active := isVoiceActive(frame)
	d.updateVAD(active)
	return active
}

func isVoiceActive(frame []int16) bool {
	if len(frame) == 0 {
		return false
	}
	var sum int64
	for _, sample := range frame {
		if sample < 0 {
			sum -= int64(sample)
		} else {
			sum += int64(sample)
		}
	}
	avg := sum / int64(len(frame))
	return avg >= vadThreshold
}
