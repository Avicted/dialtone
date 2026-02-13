package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func makeExecutableFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o700); err != nil {
		t.Fatalf("write executable %s: %v", path, err)
	}
}

func waitForFile(t *testing.T, path string, timeout time.Duration, wantLine string) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		data, err := os.ReadFile(path)
		if err == nil {
			content := string(data)
			if wantLine == "" || hasLine(content, wantLine) {
				return content
			}
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("read %s: %v", path, err)
		}
		if time.Now().After(deadline) {
			if wantLine == "" {
				t.Fatalf("timed out waiting for %s", path)
			}
			t.Fatalf("timed out waiting for %s to contain line %q", path, wantLine)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func hasLine(content, want string) bool {
	normalized := strings.ReplaceAll(content, "\r\n", "\n")
	for _, line := range strings.Split(normalized, "\n") {
		if line == want {
			return true
		}
	}
	return false
}

func TestStartVoiceDaemonValidation(t *testing.T) {
	tests := []struct {
		name string
		m    *chatModel
		want string
	}{
		{
			name: "autostart disabled",
			m:    &chatModel{},
			want: "voice auto-start disabled",
		},
		{
			name: "missing auth context",
			m: &chatModel{
				voiceAutoStart: true,
			},
			want: "missing auth",
		},
		{
			name: "missing ipc address",
			m: &chatModel{
				voiceAutoStart: true,
				api:            &APIClient{serverURL: "http://server"},
				auth:           newTestAuth(),
			},
			want: "voice ipc address is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.m.startVoiceDaemon()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("startVoiceDaemon() error = %v, want contains %q", err, tt.want)
			}
		})
	}
}

func TestStartVoiceDaemonAlreadyRunningNoop(t *testing.T) {
	m := &chatModel{
		voiceAutoStart: true,
		voiceProc:      &voiceAutoProcess{},
		api:            &APIClient{serverURL: "http://server"},
		auth:           newTestAuth(),
		voiceIPCAddr:   "/tmp/dialtone-voice.sock",
	}
	if err := m.startVoiceDaemon(); err != nil {
		t.Fatalf("startVoiceDaemon should no-op when already running: %v", err)
	}
}

func TestStartVoiceDaemonLaunchesProcessAndStops(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script process test is unix-only")
	}

	tmp := t.TempDir()
	argsPath := filepath.Join(tmp, "args.txt")
	envPath := filepath.Join(tmp, "env.txt")
	logPath := filepath.Join(tmp, "voiced.log")
	binPath := filepath.Join(tmp, "dialtone-voiced")

	script := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' \"$@\" > %q\nenv > %q\nsleep 60\n", argsPath, envPath)
	makeExecutableFile(t, binPath, script)

	t.Setenv("XDG_ACTIVATION_TOKEN", "launcher-token")
	t.Setenv("DESKTOP_STARTUP_ID", "launcher-id")
	t.Setenv("DIALTONE_KEEP_ME", "ok")

	m := &chatModel{
		voiceAutoStart: true,
		api:            &APIClient{serverURL: "http://dialtone.test"},
		auth:           &AuthResponse{Token: "secret-token"},
		voiceIPCAddr:   "/tmp/dialtone-test.sock",
		voicedPath:     binPath,
		voiceArgs:      []string{"--meter"},
		voiceLogPath:   logPath,
	}

	if err := m.startVoiceDaemon(); err != nil {
		t.Fatalf("startVoiceDaemon: %v", err)
	}
	t.Cleanup(func() {
		m.stopVoiceDaemon()
	})

	if m.voiceProc == nil {
		t.Fatalf("expected voice process state after start")
	}
	if !m.voiceAutoStarting {
		t.Fatalf("expected voiceAutoStarting=true after start")
	}

	argsOut := waitForFile(t, argsPath, 2*time.Second, "--meter")
	for _, arg := range []string{"-server", "http://dialtone.test", "-token", "secret-token", "-ipc", "/tmp/dialtone-test.sock", "--meter"} {
		if !hasLine(argsOut, arg) {
			t.Fatalf("expected daemon arg %q in:\n%s", arg, argsOut)
		}
	}

	envOut := waitForFile(t, envPath, 2*time.Second, "DIALTONE_KEEP_ME=ok")
	if strings.Contains(envOut, "XDG_ACTIVATION_TOKEN=") {
		t.Fatalf("expected launcher token removed from daemon environment")
	}
	if strings.Contains(envOut, "DESKTOP_STARTUP_ID=") {
		t.Fatalf("expected desktop startup id removed from daemon environment")
	}
	if !strings.Contains(envOut, "DIALTONE_KEEP_ME=ok") {
		t.Fatalf("expected unrelated env var to be preserved")
	}

	m.stopVoiceDaemon()
	if m.voiceProc != nil {
		t.Fatalf("expected voice process cleared after stop")
	}
	if m.voiceAutoStarting {
		t.Fatalf("expected voiceAutoStarting=false after stop")
	}
}

func TestResolveVoicedPathCandidateOrder(t *testing.T) {
	tmp := t.TempDir()
	hintPath := filepath.Join(tmp, "hint-voiced")
	envPrimary := filepath.Join(tmp, "env-primary-voiced")
	envSecondary := filepath.Join(tmp, "env-secondary-voiced")

	makeExecutableFile(t, hintPath, "#!/bin/sh\nexit 0\n")
	makeExecutableFile(t, envPrimary, "#!/bin/sh\nexit 0\n")
	makeExecutableFile(t, envSecondary, "#!/bin/sh\nexit 0\n")

	t.Setenv("DIALTONE_VOICE_DAEMON", envPrimary)
	t.Setenv("DIALTONE_VOICED", envSecondary)

	path, err := resolveVoicedPath(hintPath)
	if err != nil {
		t.Fatalf("resolveVoicedPath hint: %v", err)
	}
	if path != hintPath {
		t.Fatalf("expected hint path %q, got %q", hintPath, path)
	}

	path, err = resolveVoicedPath("")
	if err != nil {
		t.Fatalf("resolveVoicedPath env primary: %v", err)
	}
	if path != envPrimary {
		t.Fatalf("expected primary env path %q, got %q", envPrimary, path)
	}

	if err := os.Remove(envPrimary); err != nil {
		t.Fatalf("remove env primary: %v", err)
	}
	path, err = resolveVoicedPath("")
	if err != nil {
		t.Fatalf("resolveVoicedPath env secondary: %v", err)
	}
	if path != envSecondary {
		t.Fatalf("expected secondary env path %q, got %q", envSecondary, path)
	}
}

func TestResolveVoicedPathNotFound(t *testing.T) {
	tmp := t.TempDir()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(oldWD)
	})

	t.Setenv("DIALTONE_VOICE_DAEMON", "")
	t.Setenv("DIALTONE_VOICED", "")
	t.Setenv("PATH", tmp)

	path, err := resolveVoicedPath("")
	if err == nil {
		t.Fatalf("expected not found error, got path %q", path)
	}
	if path != "" {
		t.Fatalf("expected empty path on error, got %q", path)
	}
}

func TestOpenVoiceLogFileBehavior(t *testing.T) {
	m := &chatModel{}
	file, err := m.openVoiceLogFile()
	if err != nil {
		t.Fatalf("openVoiceLogFile: %v", err)
	}
	if file != nil {
		t.Fatalf("expected no log file when debug disabled and path unset")
	}

	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	m.voiceDebug = true
	file, err = m.openVoiceLogFile()
	if err != nil {
		t.Fatalf("openVoiceLogFile debug: %v", err)
	}
	if file == nil {
		t.Fatalf("expected log file when debug is enabled")
	}
	_ = file.Close()
	if !strings.HasSuffix(filepath.ToSlash(m.voiceLogPath), "dialtone/voiced.log") {
		t.Fatalf("unexpected default log path: %q", m.voiceLogPath)
	}
	if _, err := os.Stat(m.voiceLogPath); err != nil {
		t.Fatalf("stat default log path: %v", err)
	}

	explicit := filepath.Join(t.TempDir(), "logs", "voice.log")
	m2 := &chatModel{voiceLogPath: explicit}
	file, err = m2.openVoiceLogFile()
	if err != nil {
		t.Fatalf("openVoiceLogFile explicit: %v", err)
	}
	if file == nil {
		t.Fatalf("expected explicit log file to open")
	}
	_ = file.Close()
	if m2.voiceLogPath != explicit {
		t.Fatalf("expected explicit log path preserved, got %q", m2.voiceLogPath)
	}
}

func TestResolveExecutableCandidate(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "voiced")
	makeExecutableFile(t, path, "#!/bin/sh\nexit 0\n")

	if got := resolveExecutableCandidate(path); got != path {
		t.Fatalf("expected executable candidate %q, got %q", path, got)
	}
	if got := resolveExecutableCandidate(filepath.Join(tmp, "missing")); got != "" {
		t.Fatalf("expected missing candidate to resolve empty string, got %q", got)
	}
}

func TestFileIsExecutable(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "plain-file")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	if runtime.GOOS == "windows" {
		if !fileIsExecutable(path) {
			t.Fatalf("expected windows file to be treated as executable")
		}
		return
	}

	if fileIsExecutable(path) {
		t.Fatalf("expected non-executable mode to be false")
	}
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatalf("chmod executable: %v", err)
	}
	if !fileIsExecutable(path) {
		t.Fatalf("expected executable mode to be true")
	}
}

func TestIsVoiceIPCNotRunning(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "os err not exist", err: os.ErrNotExist, want: true},
		{name: "enoent", err: syscall.ENOENT, want: true},
		{name: "conn refused", err: syscall.ECONNREFUSED, want: true},
		{name: "string no such file", err: errors.New("No such file or directory"), want: true},
		{name: "string conn refused", err: errors.New("connection refused by peer"), want: true},
		{name: "other", err: errors.New("permission denied"), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isVoiceIPCNotRunning(tt.err)
			if got != tt.want {
				t.Fatalf("isVoiceIPCNotRunning(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestSignalCommandShutdownNilAndNoProcess(t *testing.T) {
	if signalCommandShutdown(nil) {
		t.Fatalf("expected nil command to return false")
	}
	cmd := exec.Command(os.Args[0])
	if signalCommandShutdown(cmd) {
		t.Fatalf("expected command without process to return false")
	}
}

func TestStopCommandGracefullyKillsUnresponsiveProcess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("signal behavior test is unix-only")
	}

	tmp := t.TempDir()
	binPath := filepath.Join(tmp, "ignore-int")
	makeExecutableFile(t, binPath, "#!/bin/sh\ntrap '' INT\nwhile true; do sleep 1; done\n")

	cmd := exec.Command(binPath)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper process: %v", err)
	}

	start := time.Now()
	stopCommandGracefully(cmd, 150*time.Millisecond)
	if cmd.ProcessState == nil {
		t.Fatalf("expected process state after graceful stop")
	}
	status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !ok {
		t.Fatalf("expected unix wait status, got %T", cmd.ProcessState.Sys())
	}
	if !status.Exited() && !status.Signaled() {
		t.Fatalf("expected process to terminate (exit or signal), status=%v", status)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("expected forced shutdown quickly, took %v", elapsed)
	}
}

func TestVoiceDaemonEnvFiltersLauncherActivationVars(t *testing.T) {
	t.Setenv("XDG_ACTIVATION_TOKEN", "token-from-launcher")
	t.Setenv("DESKTOP_STARTUP_ID", "launcher-startup-id")
	t.Setenv("GIO_LAUNCHED_DESKTOP_FILE", "rofi.desktop")
	t.Setenv("GIO_LAUNCHED_DESKTOP_FILE_PID", "1234")
	t.Setenv("BAMF_DESKTOP_FILE_HINT", "rofi.desktop")
	t.Setenv("BAMF_DESKTOP_FILE", "rofi.desktop")
	t.Setenv("DIALTONE_KEEP_ME", "ok")

	env := voiceDaemonEnv()
	joined := strings.Join(env, "\n")
	if strings.Contains(joined, "XDG_ACTIVATION_TOKEN=") {
		t.Fatalf("expected XDG_ACTIVATION_TOKEN removed from daemon env")
	}
	if strings.Contains(joined, "DESKTOP_STARTUP_ID=") {
		t.Fatalf("expected DESKTOP_STARTUP_ID removed from daemon env")
	}
	if strings.Contains(joined, "GIO_LAUNCHED_DESKTOP_FILE=") {
		t.Fatalf("expected GIO_LAUNCHED_DESKTOP_FILE removed from daemon env")
	}
	if strings.Contains(joined, "GIO_LAUNCHED_DESKTOP_FILE_PID=") {
		t.Fatalf("expected GIO_LAUNCHED_DESKTOP_FILE_PID removed from daemon env")
	}
	if strings.Contains(joined, "BAMF_DESKTOP_FILE_HINT=") {
		t.Fatalf("expected BAMF_DESKTOP_FILE_HINT removed from daemon env")
	}
	if strings.Contains(joined, "BAMF_DESKTOP_FILE=") {
		t.Fatalf("expected BAMF_DESKTOP_FILE removed from daemon env")
	}
	if !strings.Contains(joined, "DIALTONE_KEEP_ME=ok") {
		t.Fatalf("expected unrelated env vars to remain")
	}
}
