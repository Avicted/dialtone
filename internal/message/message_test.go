package message

import (
	"testing"
)

func TestID_Type(t *testing.T) {
	var id ID = "test-id"
	if id != "test-id" {
		t.Fatalf("ID = %q, want %q", id, "test-id")
	}
}

func TestID_Empty(t *testing.T) {
	var id ID
	if id != "" {
		t.Fatalf("zero ID = %q, want empty", id)
	}
}
