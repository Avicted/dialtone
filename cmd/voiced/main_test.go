package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func TestDefaultIPCAddr(t *testing.T) {
	addr := defaultIPCAddr()
	if runtime.GOOS == "windows" {
		if addr != `\\.\pipe\dialtone-voice` {
			t.Fatalf("unexpected windows IPC addr: %q", addr)
		}
		return
	}
	if addr != "/tmp/dialtone-voice.sock" {
		t.Fatalf("unexpected unix IPC addr: %q", addr)
	}
}

func TestSplitCSV(t *testing.T) {
	if got := splitCSV(""); got != nil {
		t.Fatalf("expected nil for empty CSV, got %#v", got)
	}
	got := splitCSV(" stun1.example, ,stun2.example ,, turn.example ")
	if len(got) != 3 || got[0] != "stun1.example" || got[1] != "stun2.example" || got[2] != "turn.example" {
		t.Fatalf("unexpected splitCSV result: %#v", got)
	}
}

func TestNormalizeICEURLs(t *testing.T) {
	urls := normalizeICEURLs([]string{"stun:one", "two", "turn:three", "turns:four"}, "stun:")
	if len(urls) != 4 {
		t.Fatalf("unexpected normalized URL count: %d", len(urls))
	}
	if urls[0] != "stun:one" || urls[1] != "stun:two" || urls[2] != "turn:three" || urls[3] != "turns:four" {
		t.Fatalf("unexpected normalized URLs: %#v", urls)
	}
}

func TestBuildICEConfig(t *testing.T) {
	config := buildICEConfig("stun1.example,stun:stun2.example", "turn.example", "user", "pass")
	if len(config.ICEServers) != 2 {
		t.Fatalf("expected 2 ICE server entries, got %d", len(config.ICEServers))
	}
	stun := config.ICEServers[0]
	if len(stun.URLs) != 2 || stun.URLs[0] != "stun:stun1.example" || stun.URLs[1] != "stun:stun2.example" {
		t.Fatalf("unexpected STUN config: %#v", stun)
	}
	turn := config.ICEServers[1]
	if len(turn.URLs) != 1 || turn.URLs[0] != "turn:turn.example" || turn.Username != "user" || turn.Credential != "pass" {
		t.Fatalf("unexpected TURN config: %#v", turn)
	}

	empty := buildICEConfig("", "", "", "")
	if len(empty.ICEServers) != 0 {
		t.Fatalf("expected empty ICE config, got %#v", empty)
	}
}

func TestRunValidationErrors(t *testing.T) {
	originalArgs := os.Args
	t.Cleanup(func() {
		os.Args = originalArgs
	})

	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{name: "missing server", args: []string{"dialtone-voiced", "-token", "t"}, wantErr: "server address is required"},
		{name: "missing token", args: []string{"dialtone-voiced", "-server", "http://s"}, wantErr: "auth token is required"},
		{name: "empty ipc", args: []string{"dialtone-voiced", "-server", "http://s", "-token", "t", "-ipc", ""}, wantErr: "ipc address is required"},
		{name: "invalid vad", args: []string{"dialtone-voiced", "-server", "http://s", "-token", "t", "-vad-threshold", "0"}, wantErr: "vad-threshold must be > 0"},
		{name: "invalid backend", args: []string{"dialtone-voiced", "-server", "http://s", "-token", "t", "-ptt-backend", "bad"}, wantErr: "invalid ptt-backend"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Args = append([]string(nil), tt.args...)
			err := run()
			if err == nil || err.Error() == "" {
				t.Fatalf("expected validation error containing %q", tt.wantErr)
			}
			if tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("run() error = %q, want contains %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestVoicedMainExitsOnRunError(t *testing.T) {
	if os.Getenv("DIALTONE_TEST_VOICED_MAIN_HELPER") == "1" {
		os.Args = []string{"dialtone-voiced"}
		main()
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestVoicedMainExitsOnRunError")
	cmd.Env = append(os.Environ(), "DIALTONE_TEST_VOICED_MAIN_HELPER=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected subprocess exit error, got %v", err)
	}
	if exitErr.ExitCode() != 1 {
		t.Fatalf("expected exit code 1, got %d", exitErr.ExitCode())
	}
	if !strings.Contains(stderr.String(), "fatal: server address is required") {
		t.Fatalf("expected fatal server-address error in stderr, got %q", stderr.String())
	}
}
