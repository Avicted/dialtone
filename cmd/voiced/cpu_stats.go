package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/shirou/gopsutil/v3/process"
)

func logCPUUsage(ctx context.Context) {
	proc, err := process.NewProcess(int32(os.Getpid()))
	if err != nil {
		log.Printf("cpu stats unavailable: %v", err)
		return
	}
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			percent, err := proc.CPUPercent()
			if err != nil {
				log.Printf("cpu stats failed: %v", err)
				continue
			}
			log.Printf("voice cpu: %.1f%%", percent)
		}
	}
}
