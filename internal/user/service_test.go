package user

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeRepo struct {
	users map[string]User
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{users: make(map[string]User)}
}

func (r *fakeRepo) Create(_ context.Context, u User) error {
	if _, exists := r.users[u.Username]; exists {
		return errors.New("duplicate username")
	}
	r.users[u.Username] = u
	return nil
}

func (r *fakeRepo) GetByID(_ context.Context, id ID) (User, error) {
	for _, u := range r.users {
		if u.ID == id {
			return u, nil
		}
	}
	return User{}, errors.New("not found")
}

func (r *fakeRepo) GetByUsername(_ context.Context, username string) (User, error) {
	u, ok := r.users[username]
	if !ok {
		return User{}, errors.New("not found")
	}
	return u, nil
}

func newTestService() (*Service, *fakeRepo) {
	repo := newFakeRepo()
	svc := NewService(repo)
	svc.idGen = func() ID { return "test-id-1" }
	svc.now = func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	return svc, repo
}

func TestCreate_Success(t *testing.T) {
	svc, _ := newTestService()

	u, err := svc.Create(context.Background(), "alice")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if u.Username != "alice" {
		t.Errorf("username = %q, want %q", u.Username, "alice")
	}
	if u.ID == "" {
		t.Error("ID should not be empty")
	}
	if u.CreatedAt.IsZero() {
		t.Error("CreatedAt should not be zero")
	}
}

func TestCreate_EmptyUsername(t *testing.T) {
	svc, _ := newTestService()

	_, err := svc.Create(context.Background(), "")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestCreate_WhitespaceUsername(t *testing.T) {
	svc, _ := newTestService()

	_, err := svc.Create(context.Background(), "   ")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestCreate_TrimsWhitespace(t *testing.T) {
	svc, _ := newTestService()

	u, err := svc.Create(context.Background(), "  bob  ")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if u.Username != "bob" {
		t.Errorf("username = %q, want %q", u.Username, "bob")
	}
}

func TestCreate_NilRepo(t *testing.T) {
	svc := &Service{}

	_, err := svc.Create(context.Background(), "alice")
	if err == nil {
		t.Fatal("expected error for nil repo")
	}
}

func TestCreateWithPassword_Success(t *testing.T) {
	svc, _ := newTestService()

	u, err := svc.CreateWithPassword(context.Background(), "alice", "$2a$10$hash")
	if err != nil {
		t.Fatalf("CreateWithPassword() error = %v", err)
	}
	if u.PasswordHash == "" {
		t.Error("PasswordHash should not be empty")
	}
}

func TestCreateWithPassword_EmptyHash(t *testing.T) {
	svc, _ := newTestService()

	_, err := svc.CreateWithPassword(context.Background(), "alice", "")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestGetByID_Success(t *testing.T) {
	svc, _ := newTestService()

	created, _ := svc.Create(context.Background(), "alice")
	got, err := svc.GetByID(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}
	if got.Username != "alice" {
		t.Errorf("username = %q, want %q", got.Username, "alice")
	}
}

func TestGetByID_Empty(t *testing.T) {
	svc, _ := newTestService()

	_, err := svc.GetByID(context.Background(), "")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestGetByUsername_Success(t *testing.T) {
	svc, _ := newTestService()

	_, _ = svc.Create(context.Background(), "carol")
	got, err := svc.GetByUsername(context.Background(), "carol")
	if err != nil {
		t.Fatalf("GetByUsername() error = %v", err)
	}
	if got.Username != "carol" {
		t.Errorf("username = %q, want %q", got.Username, "carol")
	}
}

func TestGetByUsername_Empty(t *testing.T) {
	svc, _ := newTestService()

	_, err := svc.GetByUsername(context.Background(), "")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestGetByUsername_NotFound(t *testing.T) {
	svc, _ := newTestService()

	_, err := svc.GetByUsername(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown username")
	}
}
