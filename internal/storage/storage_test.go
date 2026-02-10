package storage

import (
	"context"
	"testing"
)

func TestNopStore(t *testing.T) {
	store := NewNopStore()
	if store == nil {
		t.Fatal("expected non-nil store")
	}
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	if err := store.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if store.Users() != nil {
		t.Fatal("expected Users() to return nil")
	}
	if store.Devices() != nil {
		t.Fatal("expected Devices() to return nil")
	}
	if store.Broadcasts() != nil {
		t.Fatal("expected Broadcasts() to return nil")
	}
	if store.Channels() != nil {
		t.Fatal("expected Channels() to return nil")
	}
	if store.ServerInvites() != nil {
		t.Fatal("expected ServerInvites() to return nil")
	}
}
