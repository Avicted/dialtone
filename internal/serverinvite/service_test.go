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

func TestCreate_NilRepo(t *testing.T) {
	svc := &Service{}
	_, err := svc.Create(context.Background())
	if err == nil {
		t.Fatal("expected error for nil repo")
	}
}

func TestConsume_NilRepo(t *testing.T) {
	svc := &Service{}
	_, err := svc.Consume(context.Background(), "token", "user-1")
	if err == nil {
		t.Fatal("expected error for nil repo")
	}
}

func TestConsume_EmptyToken(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)
	_, err := svc.Consume(context.Background(), "", "user-1")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestConsume_WhitespaceToken(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)
	_, err := svc.Consume(context.Background(), "   ", "user-1")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestConsume_EmptyUserID(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)
	_, err := svc.Consume(context.Background(), "token", "")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestConsume_NotFound(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)
	svc.now = func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	_, err := svc.Consume(context.Background(), "nonexistent", "user-1")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestConsume_Expired(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)
	svc.now = func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }

	invite, _ := svc.Create(context.Background())
	// Move time forward past expiration
	svc.now = func() time.Time { return time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC) }
	_, err := svc.Consume(context.Background(), invite.Token, "user-1")
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("expected ErrExpired, got %v", err)
	}
}

func TestNewService(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)
	if svc == nil {
		t.Fatal("NewService() returned nil")
	}
}

func TestCreateInvite_Props(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)
	svc.now = func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }

	invite, err := svc.Create(context.Background())
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if invite.CreatedAt.IsZero() {
		t.Fatal("CreatedAt should not be zero")
	}
	expectedExpiry := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	if !invite.ExpiresAt.Equal(expectedExpiry) {
		t.Fatalf("ExpiresAt = %v, want %v", invite.ExpiresAt, expectedExpiry)
	}
}

func TestCreate_RepoError(t *testing.T) {
	svc := NewService(&errInviteRepo{})
	svc.now = func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	_, err := svc.Create(context.Background())
	if err == nil {
		t.Fatal("expected error from repo")
	}
}

type errInviteRepo struct{}

func (r *errInviteRepo) Create(_ context.Context, _ Invite) error {
	return errors.New("db error")
}

func (r *errInviteRepo) Consume(_ context.Context, _ string, _ user.ID, _ time.Time) (Invite, error) {
	return Invite{}, errors.New("db error")
}
