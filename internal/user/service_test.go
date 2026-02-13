package user

import (
	"context"
	"errors"
	"strings"
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

func TestNewServiceDefaults(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo, "pepper")

	if svc == nil {
		t.Fatalf("expected service instance")
	}
	if svc.repo != repo {
		t.Fatalf("expected repository to be stored on service")
	}
	if svc.idGen == nil || svc.now == nil {
		t.Fatalf("expected idGen and now defaults to be initialized")
	}
	if len(svc.pepper) == 0 {
		t.Fatalf("expected pepper bytes to be initialized")
	}
	if id := svc.NewID(); id == "" {
		t.Fatalf("expected NewID to return a non-empty value")
	}
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

func TestCreate_ShortUsername(t *testing.T) {
	svc, _ := newTestService()

	_, err := svc.Create(context.Background(), "a")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestCreate_LongUsername(t *testing.T) {
	svc, _ := newTestService()
	longName := strings.Repeat("a", 21)

	_, err := svc.Create(context.Background(), longName)
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

func TestGetDirectoryKeyEnvelope_Success(t *testing.T) {
	svc, repo := newTestService()

	repo.keyEnvs["dev-1"] = DirectoryKeyEnvelope{DeviceID: "dev-1", SenderDeviceID: "dev-2", SenderPublicKey: "pub", Envelope: "env"}
	env, err := svc.GetDirectoryKeyEnvelope(context.Background(), "dev-1")
	if err != nil {
		t.Fatalf("GetDirectoryKeyEnvelope() error = %v", err)
	}
	if env.Envelope != "env" {
		t.Fatalf("Envelope = %q, want %q", env.Envelope, "env")
	}
}

func TestGetDirectoryKeyEnvelope_NilRepo(t *testing.T) {
	svc := &Service{}
	_, err := svc.GetDirectoryKeyEnvelope(context.Background(), "dev-1")
	if err == nil {
		t.Fatal("expected error for nil repo")
	}
}

func TestGetDirectoryKeyEnvelope_WhitespaceDeviceID(t *testing.T) {
	svc, _ := newTestService()
	_, err := svc.GetDirectoryKeyEnvelope(context.Background(), "   ")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestCreateWithPassword_NilRepo(t *testing.T) {
	svc := &Service{}
	_, err := svc.CreateWithPassword(context.Background(), "alice", "hash")
	if err == nil {
		t.Fatal("expected error for nil repo")
	}
}

func TestCreateWithPassword_EmptyUsername(t *testing.T) {
	svc, _ := newTestService()
	_, err := svc.CreateWithPassword(context.Background(), "", "hash")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestCreateWithPassword_NoPepper(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo, "")
	_, err := svc.CreateWithPassword(context.Background(), "alice", "hash")
	if err == nil {
		t.Fatal("expected error for empty pepper")
	}
}

func TestCreateWithPasswordAndID_NilRepo(t *testing.T) {
	svc := &Service{}
	_, err := svc.CreateWithPasswordAndID(context.Background(), "id-1", "alice", "hash", false, false)
	if err == nil {
		t.Fatal("expected error for nil repo")
	}
}

func TestCreateWithPasswordAndID_EmptyName(t *testing.T) {
	svc, _ := newTestService()
	_, err := svc.CreateWithPasswordAndID(context.Background(), "id-1", "", "hash", false, false)
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestCreateWithPasswordAndID_EmptyPasswordHash(t *testing.T) {
	svc, _ := newTestService()
	_, err := svc.CreateWithPasswordAndID(context.Background(), "id-1", "alice", "", false, false)
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestCreateWithPasswordAndID_NoPepper(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo, "")
	_, err := svc.CreateWithPasswordAndID(context.Background(), "id-1", "alice", "hash", false, false)
	if err == nil {
		t.Fatal("expected error for empty pepper")
	}
}

func TestCreate_NoPepper(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo, "")
	_, err := svc.Create(context.Background(), "alice")
	if err == nil {
		t.Fatal("expected error for empty pepper")
	}
}

func TestGetByID_NilRepo(t *testing.T) {
	svc := &Service{}
	_, err := svc.GetByID(context.Background(), "id")
	if err == nil {
		t.Fatal("expected error for nil repo")
	}
}

func TestGetByUsername_NilRepo(t *testing.T) {
	svc := &Service{}
	_, err := svc.GetByUsername(context.Background(), "alice")
	if err == nil {
		t.Fatal("expected error for nil repo")
	}
}

func TestGetByUsername_NoPepper(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo, "")
	_, err := svc.GetByUsername(context.Background(), "alice")
	if err == nil {
		t.Fatal("expected error for empty pepper")
	}
}

func TestUpsertProfile_NilRepo(t *testing.T) {
	svc := &Service{}
	err := svc.UpsertProfile(context.Background(), "user-1", "enc")
	if err == nil {
		t.Fatal("expected error for nil repo")
	}
}

func TestUpsertProfile_EmptyNameEnc(t *testing.T) {
	svc, _ := newTestService()
	err := svc.UpsertProfile(context.Background(), "user-1", "")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestUpsertProfile_WhitespaceNameEnc(t *testing.T) {
	svc, _ := newTestService()
	err := svc.UpsertProfile(context.Background(), "user-1", "   ")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestListProfiles_NilRepo(t *testing.T) {
	svc := &Service{}
	_, err := svc.ListProfiles(context.Background())
	if err == nil {
		t.Fatal("expected error for nil repo")
	}
}

func TestUpsertDirectoryKeyEnvelope_NilRepo(t *testing.T) {
	svc := &Service{}
	env := DirectoryKeyEnvelope{DeviceID: "dev-1", SenderDeviceID: "dev-2", SenderPublicKey: "pub", Envelope: "env"}
	err := svc.UpsertDirectoryKeyEnvelope(context.Background(), env)
	if err == nil {
		t.Fatal("expected error for nil repo")
	}
}

func TestUpsertDirectoryKeyEnvelope_EmptyDeviceID(t *testing.T) {
	svc, _ := newTestService()
	env := DirectoryKeyEnvelope{DeviceID: "", SenderDeviceID: "dev-2", SenderPublicKey: "pub", Envelope: "env"}
	err := svc.UpsertDirectoryKeyEnvelope(context.Background(), env)
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestUpsertDirectoryKeyEnvelope_EmptySenderDeviceID(t *testing.T) {
	svc, _ := newTestService()
	env := DirectoryKeyEnvelope{DeviceID: "dev-1", SenderDeviceID: "", SenderPublicKey: "pub", Envelope: "env"}
	err := svc.UpsertDirectoryKeyEnvelope(context.Background(), env)
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestUpsertDirectoryKeyEnvelope_EmptySenderPublicKey(t *testing.T) {
	svc, _ := newTestService()
	env := DirectoryKeyEnvelope{DeviceID: "dev-1", SenderDeviceID: "dev-2", SenderPublicKey: "", Envelope: "env"}
	err := svc.UpsertDirectoryKeyEnvelope(context.Background(), env)
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestUpsertDirectoryKeyEnvelope_EmptyEnvelope(t *testing.T) {
	svc, _ := newTestService()
	env := DirectoryKeyEnvelope{DeviceID: "dev-1", SenderDeviceID: "dev-2", SenderPublicKey: "pub", Envelope: ""}
	err := svc.UpsertDirectoryKeyEnvelope(context.Background(), env)
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestUpsertDirectoryKeyEnvelope_PreservesCreatedAt(t *testing.T) {
	svc, repo := newTestService()
	createdAt := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	env := DirectoryKeyEnvelope{DeviceID: "dev-1", SenderDeviceID: "dev-2", SenderPublicKey: "pub", Envelope: "env", CreatedAt: createdAt}
	if err := svc.UpsertDirectoryKeyEnvelope(context.Background(), env); err != nil {
		t.Fatalf("UpsertDirectoryKeyEnvelope() error = %v", err)
	}
	stored := repo.keyEnvs["dev-1"]
	if !stored.CreatedAt.Equal(createdAt) {
		t.Fatalf("CreatedAt = %v, want %v", stored.CreatedAt, createdAt)
	}
}

func TestNormalizeUsername(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Alice", "alice"},
		{"  BOB  ", "bob"},
		{"", ""},
		{"  ", ""},
	}
	for _, tt := range tests {
		got := normalizeUsername(tt.input)
		if got != tt.want {
			t.Errorf("normalizeUsername(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestHashUsername(t *testing.T) {
	pepper := []byte("pepper")
	h1 := hashUsername(pepper, "alice")
	h2 := hashUsername(pepper, "alice")
	if h1 != h2 {
		t.Fatal("same input should produce same hash")
	}
	h3 := hashUsername(pepper, "bob")
	if h1 == h3 {
		t.Fatal("different inputs should produce different hashes")
	}
}

func TestCreateWithPasswordAndID_RepoError(t *testing.T) {
	repo := newFakeRepo()
	svc, _ := newTestService()
	// Create first user
	_, _ = svc.CreateWithPasswordAndID(context.Background(), "id-1", "alice", "hash", false, false)
	// Try creating with same username hash should fail
	_, err := svc.CreateWithPasswordAndID(context.Background(), "id-2", "alice", "hash2", false, false)
	if err == nil {
		t.Fatal("expected error for duplicate username")
	}
	_ = repo // suppress unused
}

func TestCreateWithPassword_RepoError(t *testing.T) {
	svc, _ := newTestService()
	_, _ = svc.CreateWithPassword(context.Background(), "alice", "hash")
	_, err := svc.CreateWithPassword(context.Background(), "alice", "hash2")
	if err == nil {
		t.Fatal("expected error for duplicate username")
	}
}

func TestCreate_RepoError(t *testing.T) {
	svc, _ := newTestService()
	_, _ = svc.Create(context.Background(), "alice")
	// ID will be same "test-id-1", so second create with different username should work name-wise
	// but the hash will differ, let's test duplicate name_hash
	svc.idGen = func() ID { return "test-id-2" }
	_, err := svc.Create(context.Background(), "alice")
	if err == nil {
		t.Fatal("expected error for duplicate username")
	}
}

func TestGetByID_NotFound(t *testing.T) {
	svc, _ := newTestService()
	_, err := svc.GetByID(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent user")
	}
}

func TestListProfiles_Empty(t *testing.T) {
	svc, _ := newTestService()
	profiles, err := svc.ListProfiles(context.Background())
	if err != nil {
		t.Fatalf("ListProfiles() error = %v", err)
	}
	if len(profiles) != 0 {
		t.Fatalf("expected 0 profiles, got %d", len(profiles))
	}
}
