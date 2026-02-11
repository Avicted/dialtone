package main

import (
	"strings"
	"testing"
)

func TestCenterText(t *testing.T) {
	out := centerText("hello", 10)
	if !strings.HasPrefix(out, " ") || !strings.Contains(out, "hello") {
		t.Fatalf("expected padding")
	}
}

func TestSeparator(t *testing.T) {
	out := separator(5)
	if out == "" {
		t.Fatalf("expected separator")
	}
}
