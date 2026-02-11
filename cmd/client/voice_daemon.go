package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

type voiceAutoProcess struct {
	cmd    *exec.Cmd
	cancel context.CancelFunc
}

func (m *chatModel) startVoiceDaemon() error {
	if !m.voiceAutoStart {
		return fmt.Errorf("voice auto-start disabled")
	}
	if m.voiceProc != nil {
		return nil
	}
	if m.api == nil || m.auth == nil {
		return fmt.Errorf("missing auth")
	}
	if m.voiceIPCAddr == "" {
		return fmt.Errorf("voice ipc address is required")
	}
	path, err := resolveVoicedPath(m.voicedPath)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	args := []string{"-server", m.api.serverURL, "-token", m.auth.Token, "-ipc", m.voiceIPCAddr}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		cancel()
		return err
	}

	m.voiceProc = &voiceAutoProcess{cmd: cmd, cancel: cancel}
	m.voiceAutoStarting = true
	return nil
}

func (m *chatModel) stopVoiceDaemon() {
	if m.voiceProc == nil {
		return
	}
	if m.voiceProc.cancel != nil {
		m.voiceProc.cancel()
	}
	if m.voiceProc.cmd != nil && m.voiceProc.cmd.Process != nil {
		_ = m.voiceProc.cmd.Process.Kill()
		_, _ = m.voiceProc.cmd.Process.Wait()
	}
	m.voiceProc = nil
}

func resolveVoicedPath(hint string) (string, error) {
	candidates := make([]string, 0, 6)
	if strings.TrimSpace(hint) != "" {
		candidates = append(candidates, hint)
	}
	if env := strings.TrimSpace(os.Getenv("DIALTONE_VOICED")); env != "" {
		candidates = append(candidates, env)
	}
	if exe, err := os.Executable(); err == nil && exe != "" {
		dir := filepath.Dir(exe)
		candidates = append(candidates, filepath.Join(dir, "voiced"))
	}
	candidates = append(candidates, filepath.Join(".", "bin", "voiced"), filepath.Join(".", "voiced"))

	for _, candidate := range candidates {
		if path := resolveExecutableCandidate(candidate); path != "" {
			return path, nil
		}
	}
	if path, err := exec.LookPath("voiced"); err == nil {
		return path, nil
	}
	return "", fmt.Errorf("voiced binary not found; set --voiced or DIALTONE_VOICED")
}

func resolveExecutableCandidate(path string) string {
	if path == "" {
		return ""
	}
	if fileIsExecutable(path) {
		return path
	}
	if runtime.GOOS == "windows" && !strings.HasSuffix(strings.ToLower(path), ".exe") {
		withExe := path + ".exe"
		if fileIsExecutable(withExe) {
			return withExe
		}
	}
	return ""
}

func fileIsExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	if runtime.GOOS == "windows" {
		return true
	}
	return info.Mode()&0o111 != 0
}

func isVoiceIPCNotRunning(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no such file") || strings.Contains(msg, "connection refused")
}
