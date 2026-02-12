//go:build !linux

package main

import (
	"context"
	"fmt"
)

func (d *voiceDaemon) runAudio(context.Context) error {
	return fmt.Errorf("audio pipeline is supported on linux only")
}
