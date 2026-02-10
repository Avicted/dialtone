package device

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Avicted/dialtone/internal/user"
)

type fakeRepo struct {
	devices []Device
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{}
}

func (r *fakeRepo) Create(_ context.Context, d Device) error {
	r.devices = append(r.devices, d)
	return nil
}

func (r *fakeRepo) GetByID(_ context.Context, id ID) (Device, error) {
	for _, d := range r.devices {
		if d.ID == id {
			return d, nil
		}
	}
	return Device{}, ErrNotFound
}

func (r *fakeRepo) GetByUserAndPublicKey(_ context.Context, userID user.ID, publicKey string) (Device, error) {
	for _, d := range r.devices {
		if d.UserID == userID && d.PublicKey == publicKey {
			return d, nil
		}
	}
	return Device{}, ErrNotFound
}

func (r *fakeRepo) ListByUser(_ context.Context, userID user.ID) ([]Device, error) {
	var result []Device
	for _, d := range r.devices {
		if d.UserID == userID {
			result = append(result, d)
		}
	}
	return result, nil
}

func (r *fakeRepo) ListAll(_ context.Context) ([]Device, error) {
	return append([]Device(nil), r.devices...), nil
}

func (r *fakeRepo) UpdateLastSeen(_ context.Context, id ID, t time.Time) error {
	for i := range r.devices {
		if r.devices[i].ID == id {
			r.devices[i].LastSeenAt = &t
			return nil
		}
	}
	return errors.New("not found")
}

func newTestService() (*Service, *fakeRepo) {
	repo := newFakeRepo()
	svc := NewService(repo)
	svc.now = func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	return svc, repo
}

func TestCreate_Success(t *testing.T) {
	svc, repo := newTestService()
	svc.idGen = func() ID { return "dev-1" }

	d, err := svc.Create(context.Background(), "user-1", "pubkey123")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if d.ID == "" {
		t.Error("ID should not be empty")
	}
	if d.ID != "dev-1" {
		t.Errorf("ID = %q, want %q", d.ID, "dev-1")
	}
	if d.UserID != "user-1" {
		t.Errorf("UserID = %q, want %q", d.UserID, "user-1")
	}
	if d.PublicKey != "pubkey123" {
		t.Errorf("PublicKey = %q, want %q", d.PublicKey, "pubkey123")
	}
	if d.CreatedAt.IsZero() {
		t.Error("CreatedAt should not be zero")
	}
	if len(repo.devices) != 1 {
		t.Fatalf("repo contains %d devices, want 1", len(repo.devices))
	}
}

func TestCreate_EmptyUserID(t *testing.T) {
	svc, _ := newTestService()

	_, err := svc.Create(context.Background(), "", "pubkey123")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestCreate_EmptyPublicKey(t *testing.T) {
	svc, _ := newTestService()

	_, err := svc.Create(context.Background(), "user-1", "")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestCreate_WhitespacePublicKey(t *testing.T) {
	svc, _ := newTestService()

	_, err := svc.Create(context.Background(), "user-1", "   ")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestCreate_TrimsPublicKey(t *testing.T) {
	svc, _ := newTestService()

	d, err := svc.Create(context.Background(), "user-1", "  key  ")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if d.PublicKey != "key" {
		t.Errorf("PublicKey = %q, want %q", d.PublicKey, "key")
	}
}

func TestCreate_NilRepo(t *testing.T) {
	svc := &Service{}

	_, err := svc.Create(context.Background(), "user-1", "key")
	if err == nil {
		t.Fatal("expected error for nil repo")
	}
}

func TestListByUser_Success(t *testing.T) {
	svc, _ := newTestService()
	counter := 0
	svc.idGen = func() ID {
		counter++
		return ID("dev-" + string(rune('0'+counter)))
	}

	_, _ = svc.Create(context.Background(), "user-1", "key1")
	_, _ = svc.Create(context.Background(), "user-1", "key2")
	_, _ = svc.Create(context.Background(), "user-2", "key3")

	devices, err := svc.ListByUser(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("ListByUser() error = %v", err)
	}
	if len(devices) != 2 {
		t.Fatalf("ListByUser() returned %d devices, want 2", len(devices))
	}
}

func TestListByUser_EmptyUserID(t *testing.T) {
	svc, _ := newTestService()

	_, err := svc.ListByUser(context.Background(), "")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestListByUser_NilRepo(t *testing.T) {
	svc := &Service{}

	_, err := svc.ListByUser(context.Background(), "user-1")
	if err == nil {
		t.Fatal("expected error for nil repo")
	}
}

func TestListAll_Success(t *testing.T) {
	svc, _ := newTestService()

	_, _ = svc.Create(context.Background(), "user-1", "key1")
	_, _ = svc.Create(context.Background(), "user-2", "key2")

	devices, err := svc.ListAll(context.Background())
	if err != nil {
		t.Fatalf("ListAll() error = %v", err)
	}
	if len(devices) != 2 {
		t.Fatalf("ListAll() returned %d devices, want 2", len(devices))
	}
}

func TestListAll_NilRepo(t *testing.T) {
	svc := &Service{}

	_, err := svc.ListAll(context.Background())
	if err == nil {
		t.Fatal("expected error for nil repo")
	}
}

func TestGetByUserAndPublicKey_Success(t *testing.T) {
	svc, _ := newTestService()

	created, _ := svc.Create(context.Background(), "user-1", "key1")
	got, err := svc.GetByUserAndPublicKey(context.Background(), "user-1", "key1")
	if err != nil {
		t.Fatalf("GetByUserAndPublicKey() error = %v", err)
	}
	if got.ID != created.ID {
		t.Fatalf("ID = %q, want %q", got.ID, created.ID)
	}
}

func TestGetByUserAndPublicKey_InvalidInput(t *testing.T) {
	svc, _ := newTestService()

	_, err := svc.GetByUserAndPublicKey(context.Background(), "", "key1")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestGetByUserAndPublicKey_NilRepo(t *testing.T) {
	svc := &Service{}

	_, err := svc.GetByUserAndPublicKey(context.Background(), "user-1", "key1")
	if err == nil {
		t.Fatal("expected error for nil repo")
	}
}
