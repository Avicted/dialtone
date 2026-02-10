package serverinvite

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Avicted/dialtone/internal/user"
)

type fakeRepo struct {
	invites map[string]Invite
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{invites: make(map[string]Invite)}
}

func (r *fakeRepo) Create(_ context.Context, invite Invite) error {
	r.invites[invite.Token] = invite
	return nil
}

func (r *fakeRepo) Consume(_ context.Context, token string, userID user.ID, now time.Time) (Invite, error) {
	invite, ok := r.invites[token]
	if !ok {
		return Invite{}, ErrNotFound
	}
	if invite.ConsumedAt != nil {
		return Invite{}, ErrConsumed
	}
	if !invite.ExpiresAt.IsZero() && !invite.ExpiresAt.After(now) {
		return Invite{}, ErrExpired
	}
	invite.ConsumedAt = &now
	invite.ConsumedBy = &userID
	r.invites[token] = invite
	return invite, nil
}

func TestCreateInvite(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)
	svc.now = func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }

	invite, err := svc.Create(context.Background())
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if invite.Token == "" {
		t.Fatal("invite token empty")
	}
	if invite.ExpiresAt.IsZero() {
		t.Fatal("invite expiration not set")
	}
}

func TestConsumeInvite(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)
	svc.now = func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }

	invite, _ := svc.Create(context.Background())
	_, err := svc.Consume(context.Background(), invite.Token, "user-1")
	if err != nil {
		t.Fatalf("Consume() error = %v", err)
	}

	_, err = svc.Consume(context.Background(), invite.Token, "user-1")
	if !errors.Is(err, ErrConsumed) {
		t.Fatalf("expected ErrConsumed, got %v", err)
	}
}
