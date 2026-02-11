package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.com/pion/webrtc/v4"
)

func main() {
	if err := run(); err != nil {
		log.Printf("fatal: %v", err)
		os.Exit(1)
	}
}

func run() error {
	fs := flag.NewFlagSet("dialtone-voiced", flag.ContinueOnError)
	serverAddr := fs.String("server", "", "dialtone server address")
	token := fs.String("token", "", "dialtone auth token")
	ipcAddr := fs.String("ipc", defaultIPCAddr(), "ipc socket/pipe address")
	pttBind := fs.String("ptt", "ctrl+v", "push-to-talk hotkey")
	stunServers := fs.String("stun", "", "comma-separated STUN servers")
	turnServers := fs.String("turn", "", "comma-separated TURN servers")
	turnUser := fs.String("turn-user", "", "TURN username")
	turnPass := fs.String("turn-pass", "", "TURN password")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}

	if *serverAddr == "" {
		return fmt.Errorf("server address is required")
	}
	if *token == "" {
		return fmt.Errorf("auth token is required")
	}
	if *ipcAddr == "" {
		return fmt.Errorf("ipc address is required")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Printf("starting voice daemon server=%s ipc=%s", *serverAddr, *ipcAddr)
	iceConfig := buildICEConfig(*stunServers, *turnServers, *turnUser, *turnPass)
	daemon := newVoiceDaemon(*serverAddr, *token, *pttBind, iceConfig)
	if err := daemon.Run(ctx, *ipcAddr); err != nil {
		return err
	}
	log.Printf("shutting down")
	return nil
}

func defaultIPCAddr() string {
	if runtime.GOOS == "windows" {
		return `\\.\pipe\dialtone-voice`
	}
	return "/tmp/dialtone-voice.sock"
}

func buildICEConfig(stunList, turnList, turnUser, turnPass string) webrtc.Configuration {
	stunURLs := normalizeICEURLs(splitCSV(stunList), "stun:")
	turnURLs := normalizeICEURLs(splitCSV(turnList), "turn:")
	servers := make([]webrtc.ICEServer, 0, 2)
	if len(stunURLs) > 0 {
		servers = append(servers, webrtc.ICEServer{URLs: stunURLs})
	}
	if len(turnURLs) > 0 {
		servers = append(servers, webrtc.ICEServer{URLs: turnURLs, Username: turnUser, Credential: turnPass})
	}
	return webrtc.Configuration{ICEServers: servers}
}

func splitCSV(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	filtered := make([]string, 0, len(parts))
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item == "" {
			continue
		}
		filtered = append(filtered, item)
	}
	return filtered
}

func normalizeICEURLs(values []string, prefix string) []string {
	urls := make([]string, 0, len(values))
	for _, value := range values {
		if strings.HasPrefix(value, "stun:") || strings.HasPrefix(value, "turn:") || strings.HasPrefix(value, "turns:") {
			urls = append(urls, value)
			continue
		}
		urls = append(urls, prefix+value)
	}
	return urls
}
