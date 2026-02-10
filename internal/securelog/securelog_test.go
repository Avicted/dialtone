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
