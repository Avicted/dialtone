package main

import (
	"strings"
	"testing"
)

func TestVoiceDaemonEnvFiltersLauncherActivationVars(t *testing.T) {
	t.Setenv("XDG_ACTIVATION_TOKEN", "token-from-launcher")
	t.Setenv("DESKTOP_STARTUP_ID", "launcher-startup-id")
	t.Setenv("DIALTONE_KEEP_ME", "ok")

	env := voiceDaemonEnv()
	joined := strings.Join(env, "\n")
	if strings.Contains(joined, "XDG_ACTIVATION_TOKEN=") {
		t.Fatalf("expected XDG_ACTIVATION_TOKEN removed from daemon env")
	}
	if strings.Contains(joined, "DESKTOP_STARTUP_ID=") {
		t.Fatalf("expected DESKTOP_STARTUP_ID removed from daemon env")
	}
	if !strings.Contains(joined, "DIALTONE_KEEP_ME=ok") {
		t.Fatalf("expected unrelated env vars to remain")
	}
}
