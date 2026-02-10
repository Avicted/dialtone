package securelog

import (
	"bytes"
	"fmt"
	"log"
	"strings"
	"testing"
)

type testErr struct{ msg string }

func (e testErr) Error() string { return e.msg }

func TestError_LogsContextAndTypes(t *testing.T) {
	var buf bytes.Buffer
	prevOutput := log.Default().Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prevOutput) })

	wrapped := fmt.Errorf("outer: %w", testErr{msg: "inner"})
	Error("context", wrapped)

	out := buf.String()
	if !strings.Contains(out, "context=context") {
		t.Fatalf("expected context in log output, got %q", out)
	}
	if !strings.Contains(out, "types=") {
		t.Fatalf("expected types in log output, got %q", out)
	}
}

func TestError_IgnoresNil(t *testing.T) {
	var buf bytes.Buffer
	prevOutput := log.Default().Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prevOutput) })

	Error("context", nil)
	if buf.Len() != 0 {
		t.Fatalf("expected no output for nil error, got %q", buf.String())
	}
}

func TestErrorTypes_UniqueChain(t *testing.T) {
	inner := testErr{msg: "inner"}
	wrapped := fmt.Errorf("wrap: %w", inner)
	types := errorTypes(wrapped)
	if len(types) < 2 {
		t.Fatalf("expected at least two error types, got %v", types)
	}
}

func TestError_EmptyContext(t *testing.T) {
	var buf bytes.Buffer
	prevOutput := log.Default().Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prevOutput) })

	Error("", testErr{msg: "test"})
	out := buf.String()
	if !strings.Contains(out, "error at") {
		t.Fatalf("expected 'error at' in log output, got %q", out)
	}
	if strings.Contains(out, "context=") {
		t.Fatalf("expected no context field, got %q", out)
	}
}

func TestCallerLocation(t *testing.T) {
	loc := callerLocation(1)
	if loc == "unknown" {
		t.Fatal("expected a known location")
	}
	if !strings.Contains(loc, "securelog_test.go") {
		t.Fatalf("expected test file in location, got %q", loc)
	}
}

func TestCallerLocation_DeepSkip(t *testing.T) {
	loc := callerLocation(999)
	if loc != "unknown" {
		t.Fatalf("expected 'unknown' for deep skip, got %q", loc)
	}
}

func TestErrorTypes_SingleError(t *testing.T) {
	err := testErr{msg: "single"}
	types := errorTypes(err)
	if len(types) != 1 {
		t.Fatalf("expected 1 type, got %v", types)
	}
}

func TestError_WithWrappedError(t *testing.T) {
	var buf bytes.Buffer
	prevOutput := log.Default().Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prevOutput) })

	inner := testErr{msg: "inner"}
	outer := fmt.Errorf("outer: %w", inner)
	doubleWrap := fmt.Errorf("top: %w", outer)
	Error("deep_chain", doubleWrap)

	out := buf.String()
	if !strings.Contains(out, "context=deep_chain") {
		t.Fatalf("expected context in output, got %q", out)
	}
	if !strings.Contains(out, "types=") {
		t.Fatalf("expected types in output, got %q", out)
	}
}

func TestErrorTypes_NilError(t *testing.T) {
	types := errorTypes(nil)
	if len(types) != 0 {
		t.Fatalf("expected empty types for nil error, got %v", types)
	}
}
