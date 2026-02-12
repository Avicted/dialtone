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
	"time"
)

type voiceAutoProcess struct {
	cmd     *exec.Cmd
	cancel  context.CancelFunc
	logFile *os.File
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
	if len(m.voiceArgs) > 0 {
		args = append(args, m.voiceArgs...)
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = voiceDaemonEnv()
	logFile, err := m.openVoiceLogFile()
	if err != nil {
		cancel()
		return err
	}
	if logFile != nil {
		cmd.Stdout = logFile
		cmd.Stderr = logFile
	} else {
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
	}
	if err := cmd.Start(); err != nil {
		if logFile != nil {
			_ = logFile.Close()
		}
		cancel()
		return err
	}

	m.voiceProc = &voiceAutoProcess{cmd: cmd, cancel: cancel, logFile: logFile}
	m.voiceAutoStarting = true
	return nil
}

func voiceDaemonEnv() []string {
	env := os.Environ()
	filtered := make([]string, 0, len(env))
	for _, entry := range env {
		if strings.HasPrefix(entry, "XDG_ACTIVATION_TOKEN=") {
			continue
		}
		if strings.HasPrefix(entry, "DESKTOP_STARTUP_ID=") {
			continue
		}
		if strings.HasPrefix(entry, "GIO_LAUNCHED_DESKTOP_FILE=") {
			continue
		}
		if strings.HasPrefix(entry, "GIO_LAUNCHED_DESKTOP_FILE_PID=") {
			continue
		}
		if strings.HasPrefix(entry, "BAMF_DESKTOP_FILE_HINT=") {
			continue
		}
		if strings.HasPrefix(entry, "BAMF_DESKTOP_FILE=") {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
}

func (m *chatModel) stopVoiceDaemon() {
	if m.voiceProc == nil {
		return
	}
	if m.voiceProc.cmd != nil {
		stopCommandGracefully(m.voiceProc.cmd, 2*time.Second)
	}
	if m.voiceProc.cancel != nil {
		m.voiceProc.cancel()
	}
	if m.voiceProc.logFile != nil {
		_ = m.voiceProc.logFile.Close()
	}
	m.voiceAutoStarting = false
	m.voiceProc = nil
}

func stopCommandGracefully(cmd *exec.Cmd, timeout time.Duration) {
	if cmd == nil {
		return
	}

	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()

	if !signalCommandShutdown(cmd) {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		<-done
		return
	}

	select {
	case <-done:
		return
	case <-time.After(timeout):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		<-done
	}
}

func signalCommandShutdown(cmd *exec.Cmd) bool {
	if cmd == nil || cmd.Process == nil {
		return false
	}
	if err := cmd.Process.Signal(os.Interrupt); err == nil {
		return true
	}
	if runtime.GOOS == "windows" {
		return false
	}
	return cmd.Process.Signal(syscall.SIGTERM) == nil
}

func (m *chatModel) openVoiceLogFile() (*os.File, error) {
	if !m.voiceDebug && strings.TrimSpace(m.voiceLogPath) == "" {
		return nil, nil
	}
	logPath, err := resolveVoiceLogPath(m.voiceLogPath)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	m.voiceLogPath = logPath
	return file, nil
}

func resolveVoiceLogPath(explicit string) (string, error) {
	if strings.TrimSpace(explicit) != "" {
		return explicit, nil
	}
	dir, err := os.UserCacheDir()
	if err != nil || dir == "" {
		dir = os.TempDir()
	}
	return filepath.Join(dir, "dialtone", "voiced.log"), nil
}

func resolveVoicedPath(hint string) (string, error) {
	candidates := make([]string, 0, 10)
	if strings.TrimSpace(hint) != "" {
		candidates = append(candidates, hint)
	}
	if env := strings.TrimSpace(os.Getenv("DIALTONE_VOICE_DAEMON")); env != "" {
		candidates = append(candidates, env)
	}
	if env := strings.TrimSpace(os.Getenv("DIALTONE_VOICED")); env != "" {
		candidates = append(candidates, env)
	}
	if exe, err := os.Executable(); err == nil && exe != "" {
		dir := filepath.Dir(exe)
		candidates = append(candidates, filepath.Join(dir, "dialtone-voiced"), filepath.Join(dir, "voiced"))
	}
	candidates = append(
		candidates,
		filepath.Join(".", "bin", "dialtone-voiced"),
		filepath.Join(".", "dialtone-voiced"),
		filepath.Join(".", "bin", "voiced"),
		filepath.Join(".", "voiced"),
	)

	for _, candidate := range candidates {
		if path := resolveExecutableCandidate(candidate); path != "" {
			return path, nil
		}
	}
	if path, err := exec.LookPath("dialtone-voiced"); err == nil {
		return path, nil
	}
	if path, err := exec.LookPath("voiced"); err == nil {
		return path, nil
	}
	return "", fmt.Errorf("dialtone-voiced binary not found; set --voiced, DIALTONE_VOICE_DAEMON, or DIALTONE_VOICED")
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
