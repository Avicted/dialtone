package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestClientMainExitsOnRunError(t *testing.T) {
	if os.Getenv("DIALTONE_TEST_CLIENT_MAIN_HELPER") == "1" {
		os.Args = []string{"dialtone", "-voice-vad", "0"}
		main()
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestClientMainExitsOnRunError")
	cmd.Env = append(os.Environ(), "DIALTONE_TEST_CLIENT_MAIN_HELPER=1")
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
	if !strings.Contains(stderr.String(), "error: voice-vad must be > 0") {
		t.Fatalf("expected main stderr to include run error, got %q", stderr.String())
	}
}
