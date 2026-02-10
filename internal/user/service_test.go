package user

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeRepo struct {
	users    map[string]User
	profiles map[ID]Profile
	keyEnvs  map[string]DirectoryKeyEnvelope
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{
		users:    make(map[string]User),
		profiles: make(map[ID]Profile),
		keyEnvs:  make(map[string]DirectoryKeyEnvelope),
	}
}

func (r *fakeRepo) Create(_ context.Context, u User) error {
	if _, exists := r.users[u.UsernameHash]; exists {
		return errors.New("duplicate username")
	}
	r.users[u.UsernameHash] = u
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

func (r *fakeRepo) GetByUsernameHash(_ context.Context, usernameHash string) (User, error) {
	u, ok := r.users[usernameHash]
	if !ok {
		return User{}, errors.New("not found")
	}
	return u, nil
}

func (r *fakeRepo) Count(_ context.Context) (int, error) {
	return len(r.users), nil
}

func (r *fakeRepo) UpsertProfile(_ context.Context, profile Profile) error {
	r.profiles[profile.UserID] = profile
	return nil
}

func (r *fakeRepo) ListProfiles(_ context.Context) ([]Profile, error) {
	profiles := make([]Profile, 0, len(r.profiles))
	for _, profile := range r.profiles {
		profiles = append(profiles, profile)
	}
	return profiles, nil
}

func (r *fakeRepo) UpsertDirectoryKeyEnvelope(_ context.Context, env DirectoryKeyEnvelope) error {
	r.keyEnvs[env.DeviceID] = env
	return nil
}

func (r *fakeRepo) GetDirectoryKeyEnvelope(_ context.Context, deviceID string) (DirectoryKeyEnvelope, error) {
	if env, ok := r.keyEnvs[deviceID]; ok {
		return env, nil
	}
	return DirectoryKeyEnvelope{}, errors.New("not found")
}

func newTestService() (*Service, *fakeRepo) {
	repo := newFakeRepo()
	svc := NewService(repo, "test-pepper")
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
	if u.UsernameHash == "" {
		t.Error("UsernameHash should not be empty")
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
	if u.UsernameHash == "" {
		t.Error("UsernameHash should not be empty")
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
	if got.UsernameHash == "" {
		t.Error("UsernameHash should not be empty")
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
	if got.UsernameHash == "" {
		t.Error("UsernameHash should not be empty")
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

func TestCreateWithPasswordAndID_Success(t *testing.T) {
	svc, _ := newTestService()

	u, err := svc.CreateWithPasswordAndID(context.Background(), "id-1", "alice", "hash", true, true)
	if err != nil {
		t.Fatalf("CreateWithPasswordAndID() error = %v", err)
	}
	if u.ID != "id-1" {
		t.Fatalf("ID = %q, want %q", u.ID, "id-1")
	}
	if !u.IsAdmin || !u.IsTrusted {
		t.Fatal("expected admin and trusted flags to be set")
	}
}

func TestCreateWithPasswordAndID_Invalid(t *testing.T) {
	svc, _ := newTestService()

	_, err := svc.CreateWithPasswordAndID(context.Background(), "", "alice", "hash", false, false)
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestNewID(t *testing.T) {
	svc, _ := newTestService()
	if id := svc.NewID(); id == "" {
		t.Fatal("expected non-empty id")
	}
}

func TestCount(t *testing.T) {
	svc, _ := newTestService()

	_, _ = svc.Create(context.Background(), "alice")
	_, _ = svc.Create(context.Background(), "bob")

	count, err := svc.Count(context.Background())
	if err != nil {
		t.Fatalf("Count() error = %v", err)
	}
	if count != 2 {
		t.Fatalf("Count = %d, want 2", count)
	}
}

func TestCount_NilRepo(t *testing.T) {
	svc := &Service{}

	_, err := svc.Count(context.Background())
	if err == nil {
		t.Fatal("expected error for nil repo")
	}
}

func TestUpsertProfile_SetsTime(t *testing.T) {
	svc, repo := newTestService()

	if err := svc.UpsertProfile(context.Background(), "user-1", "enc"); err != nil {
		t.Fatalf("UpsertProfile() error = %v", err)
	}
	profile, ok := repo.profiles[ID("user-1")]
	if !ok {
		t.Fatal("expected profile to be stored")
	}
	if profile.UpdatedAt.IsZero() {
		t.Fatal("expected UpdatedAt to be set")
	}
}

func TestUpsertProfile_InvalidInput(t *testing.T) {
	svc, _ := newTestService()

	if err := svc.UpsertProfile(context.Background(), "", "enc"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestListProfiles(t *testing.T) {
	svc, repo := newTestService()

	repo.profiles[ID("user-1")] = Profile{UserID: ID("user-1"), NameEnc: "a"}
	repo.profiles[ID("user-2")] = Profile{UserID: ID("user-2"), NameEnc: "b"}

	profiles, err := svc.ListProfiles(context.Background())
	if err != nil {
		t.Fatalf("ListProfiles() error = %v", err)
	}
	if len(profiles) != 2 {
		t.Fatalf("ListProfiles() returned %d profiles, want 2", len(profiles))
	}
}

func TestUpsertDirectoryKeyEnvelope_SetsTime(t *testing.T) {
	svc, repo := newTestService()

	env := DirectoryKeyEnvelope{DeviceID: "dev-1", SenderDeviceID: "dev-2", SenderPublicKey: "pub", Envelope: "env"}
	if err := svc.UpsertDirectoryKeyEnvelope(context.Background(), env); err != nil {
		t.Fatalf("UpsertDirectoryKeyEnvelope() error = %v", err)
	}
	stored, ok := repo.keyEnvs["dev-1"]
	if !ok {
		t.Fatal("expected key envelope to be stored")
	}
	if stored.CreatedAt.IsZero() {
		t.Fatal("expected CreatedAt to be set")
	}
}

func TestGetDirectoryKeyEnvelope_InvalidInput(t *testing.T) {
	svc, _ := newTestService()

	_, err := svc.GetDirectoryKeyEnvelope(context.Background(), "")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}
