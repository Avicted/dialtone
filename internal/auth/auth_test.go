package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Avicted/dialtone/internal/device"
	"github.com/Avicted/dialtone/internal/serverinvite"
	"github.com/Avicted/dialtone/internal/user"
)

// ── in-memory fakes ──

type fakeUserRepo struct {
	users map[string]user.User
}

func newFakeUserRepo() *fakeUserRepo {
	return &fakeUserRepo{users: make(map[string]user.User)}
}

func (r *fakeUserRepo) Create(_ context.Context, u user.User) error {
	if _, exists := r.users[u.UsernameHash]; exists {
		return errors.New("duplicate username")
	}
	r.users[u.UsernameHash] = u
	return nil
}

func (r *fakeUserRepo) GetByID(_ context.Context, id user.ID) (user.User, error) {
	for _, u := range r.users {
		if u.ID == id {
			return u, nil
		}
	}
	return user.User{}, errors.New("not found")
}

func (r *fakeUserRepo) GetByUsernameHash(_ context.Context, usernameHash string) (user.User, error) {
	u, ok := r.users[usernameHash]
	if !ok {
		return user.User{}, errors.New("not found")
	}
	return u, nil
}

func (r *fakeUserRepo) Count(_ context.Context) (int, error) {
	return len(r.users), nil
}

func (r *fakeUserRepo) UpsertProfile(_ context.Context, _ user.Profile) error {
	return nil
}

func (r *fakeUserRepo) ListProfiles(_ context.Context) ([]user.Profile, error) {
	return nil, nil
}

func (r *fakeUserRepo) UpsertDirectoryKeyEnvelope(_ context.Context, _ user.DirectoryKeyEnvelope) error {
	return nil
}

func (r *fakeUserRepo) GetDirectoryKeyEnvelope(_ context.Context, _ string) (user.DirectoryKeyEnvelope, error) {
	return user.DirectoryKeyEnvelope{}, errors.New("not found")
}

type fakeDeviceRepo struct {
	devices []device.Device
}

func newFakeDeviceRepo() *fakeDeviceRepo {
	return &fakeDeviceRepo{}
}

func (r *fakeDeviceRepo) Create(_ context.Context, d device.Device) error {
	r.devices = append(r.devices, d)
	return nil
}

func (r *fakeDeviceRepo) GetByID(_ context.Context, id device.ID) (device.Device, error) {
	for _, d := range r.devices {
		if d.ID == id {
			return d, nil
		}
	}
	return device.Device{}, device.ErrNotFound
}

func (r *fakeDeviceRepo) GetByUserAndPublicKey(_ context.Context, userID user.ID, publicKey string) (device.Device, error) {
	for _, d := range r.devices {
		if d.UserID == userID && d.PublicKey == publicKey {
			return d, nil
		}
	}
	return device.Device{}, device.ErrNotFound
}

func (r *fakeDeviceRepo) ListByUser(_ context.Context, userID user.ID) ([]device.Device, error) {
	var result []device.Device
	for _, d := range r.devices {
		if d.UserID == userID {
			result = append(result, d)
		}
	}
	return result, nil
}

func (r *fakeDeviceRepo) ListAll(_ context.Context) ([]device.Device, error) {
	return append([]device.Device(nil), r.devices...), nil
}

func (r *fakeDeviceRepo) UpdateLastSeen(_ context.Context, id device.ID, t time.Time) error {
	for i := range r.devices {
		if r.devices[i].ID == id {
			r.devices[i].LastSeenAt = &t
			return nil
		}
	}
	return errors.New("not found")
}

type fakeInviteRepo struct {
	consumed map[string]bool
}

func newFakeInviteRepo() *fakeInviteRepo {
	return &fakeInviteRepo{consumed: make(map[string]bool)}
}

func (r *fakeInviteRepo) Create(_ context.Context, _ serverinvite.Invite) error {
	return nil
}

func (r *fakeInviteRepo) Consume(_ context.Context, token string, userID user.ID, now time.Time) (serverinvite.Invite, error) {
	if token == "" || userID == "" || now.IsZero() {
		return serverinvite.Invite{}, serverinvite.ErrInvalidInput
	}
	if r.consumed[token] {
		return serverinvite.Invite{}, serverinvite.ErrConsumed
	}
	r.consumed[token] = true
	return serverinvite.Invite{Token: token, CreatedAt: now, ExpiresAt: now.Add(24 * time.Hour)}, nil
}

func newTestService() *Service {
	userRepo := newFakeUserRepo()
	deviceRepo := newFakeDeviceRepo()
	inviteRepo := newFakeInviteRepo()
	userSvc := user.NewService(userRepo, "test-pepper")
	deviceSvc := device.NewService(deviceRepo)
	inviteSvc := serverinvite.NewService(inviteRepo)
	svc := NewService(userSvc, deviceSvc, inviteSvc)
	svc.now = func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	return svc
}

func TestRegister_Success(t *testing.T) {
	svc := newTestService()
	ctx := context.Background()

	u, d, session, err := svc.Register(ctx, "alice", "password123", "dGVzdHB1YmtleQ==", "invite-1")
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if u.UsernameHash == "" {
		t.Error("UsernameHash should not be empty")
	}
	if session.Username != "alice" {
		t.Errorf("session.Username = %q, want %q", session.Username, "alice")
	}
	if d.UserID != u.ID {
		t.Errorf("device.UserID = %q, want %q", d.UserID, u.ID)
	}
	if session.Token == "" {
		t.Error("session token is empty")
	}
	if session.UserID != u.ID {
		t.Errorf("session.UserID = %q, want %q", session.UserID, u.ID)
	}
	if session.ExpiresAt.IsZero() {
		t.Error("session.ExpiresAt is zero")
	}
}

func TestRegister_DuplicateUsername(t *testing.T) {
	svc := newTestService()
	ctx := context.Background()

	_, _, _, err := svc.Register(ctx, "alice", "password123", "a2V5MQ==", "invite-1")
	if err != nil {
		t.Fatalf("first Register() error = %v", err)
	}

	_, _, _, err = svc.Register(ctx, "alice", "password456", "a2V5Mg==", "invite-2")
	if err == nil {
		t.Fatal("expected error for duplicate username")
	}
}

func TestRegister_ShortPassword(t *testing.T) {
	svc := newTestService()
	_, _, _, err := svc.Register(context.Background(), "bob", "short", "a2V5", "invite-1")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestRegister_EmptyPublicKey(t *testing.T) {
	svc := newTestService()
	_, _, _, err := svc.Register(context.Background(), "bob", "password123", "", "invite-1")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestRegister_EmptyUsername(t *testing.T) {
	svc := newTestService()
	_, _, _, err := svc.Register(context.Background(), "", "password123", "a2V5", "invite-1")
	if err == nil {
		t.Fatal("expected error for empty username")
	}
}

func TestRegister_ShortUsername(t *testing.T) {
	svc := newTestService()
	_, _, _, err := svc.Register(context.Background(), "a", "password123", "a2V5", "invite-1")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestRegister_LongUsername(t *testing.T) {
	svc := newTestService()
	longName := strings.Repeat("a", 21)
	_, _, _, err := svc.Register(context.Background(), longName, "password123", "a2V5", "invite-1")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestLogin_Success(t *testing.T) {
	svc := newTestService()
	ctx := context.Background()

	_, _, _, err := svc.Register(ctx, "carol", "password123", "a2V5MQ==", "invite-1")
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	u, d, session, err := svc.Login(ctx, "carol", "password123", "a2V5Mg==")
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if u.UsernameHash == "" {
		t.Error("UsernameHash should not be empty")
	}
	if session.Username != "carol" {
		t.Errorf("session.Username = %q, want %q", session.Username, "carol")
	}
	if d.UserID != u.ID {
		t.Errorf("device.UserID = %q, want %q", d.UserID, u.ID)
	}
	if session.Token == "" {
		t.Error("session token is empty")
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	svc := newTestService()
	ctx := context.Background()

	_, _, _, _ = svc.Register(ctx, "dave", "password123", "a2V5MQ==", "invite-1")
	_, _, _, err := svc.Login(ctx, "dave", "wrongpassword", "a2V5Mg==")
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

func TestLogin_UnknownUser(t *testing.T) {
	svc := newTestService()
	_, _, _, err := svc.Login(context.Background(), "nobody", "password123", "a2V5")
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

func TestLogin_ShortPassword(t *testing.T) {
	svc := newTestService()
	_, _, _, err := svc.Login(context.Background(), "eve", "short", "a2V5")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestValidateToken_Valid(t *testing.T) {
	svc := newTestService()
	ctx := context.Background()

	_, _, session, _ := svc.Register(ctx, "frank", "password123", "a2V5MQ==", "invite-1")

	got, err := svc.ValidateToken(session.Token)
	if err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}
	if got.UserID != session.UserID {
		t.Errorf("UserID = %q, want %q", got.UserID, session.UserID)
	}
}

func TestValidateToken_EmptyToken(t *testing.T) {
	svc := newTestService()
	_, err := svc.ValidateToken("")
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

func TestValidateToken_InvalidToken(t *testing.T) {
	svc := newTestService()
	_, err := svc.ValidateToken("nonexistent-token")
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

func TestValidateToken_Expired(t *testing.T) {
	svc := newTestService()
	ctx := context.Background()

	_, _, session, _ := svc.Register(ctx, "grace", "password123", "a2V5MQ==", "invite-1")

	svc.now = func() time.Time {
		return time.Date(2026, 1, 2, 1, 0, 0, 0, time.UTC)
	}

	_, err := svc.ValidateToken(session.Token)
	if !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
}

func TestValidateToken_WhitespaceOnly(t *testing.T) {
	svc := newTestService()
	_, err := svc.ValidateToken("   ")
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

func TestHashAndCheckPassword(t *testing.T) {
	hash, err := hashPassword("testpass123")
	if err != nil {
		t.Fatalf("hashPassword() error = %v", err)
	}
	if strings.TrimSpace(hash) == "" {
		t.Fatal("hash is empty")
	}
	if err := checkPassword(hash, "testpass123"); err != nil {
		t.Fatalf("checkPassword() error = %v", err)
	}
	if err := checkPassword(hash, "wrongpass"); err == nil {
		t.Fatal("expected error for wrong password")
	}
}

func TestRandomToken(t *testing.T) {
	t1, err := randomToken()
	if err != nil {
		t.Fatalf("randomToken() error = %v", err)
	}
	t2, _ := randomToken()
	if t1 == t2 {
		t.Fatal("two random tokens should not be equal")
	}
	if len(t1) == 0 {
		t.Fatal("token should not be empty")
	}
}

func TestRegister_NilServices(t *testing.T) {
	svc := &Service{}
	_, _, _, err := svc.Register(context.Background(), "alice", "password123", "key", "invite")
	if err == nil {
		t.Fatal("expected error for nil services")
	}
}

func TestRegister_NilInvites(t *testing.T) {
	userRepo := newFakeUserRepo()
	deviceRepo := newFakeDeviceRepo()
	userSvc := user.NewService(userRepo, "pepper")
	deviceSvc := device.NewService(deviceRepo)
	svc := NewService(userSvc, deviceSvc, nil)
	_, _, _, err := svc.Register(context.Background(), "alice", "password123", "key", "invite")
	if err == nil {
		t.Fatal("expected error for nil invites")
	}
}

func TestRegister_EmptyInviteToken(t *testing.T) {
	svc := newTestService()
	_, _, _, err := svc.Register(context.Background(), "alice", "password123", "key", "")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestRegister_WhitespaceInviteToken(t *testing.T) {
	svc := newTestService()
	_, _, _, err := svc.Register(context.Background(), "alice", "password123", "key", "   ")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestRegister_PasswordNoDigit(t *testing.T) {
	svc := newTestService()
	_, _, _, err := svc.Register(context.Background(), "alice", "abcdefgh", "key", "invite")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestRegister_PasswordNoLetter(t *testing.T) {
	svc := newTestService()
	_, _, _, err := svc.Register(context.Background(), "alice", "12345678", "key", "invite")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestRegister_PasswordEmpty(t *testing.T) {
	svc := newTestService()
	_, _, _, err := svc.Register(context.Background(), "alice", "", "key", "invite")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestRegister_PasswordWhitespace(t *testing.T) {
	svc := newTestService()
	_, _, _, err := svc.Register(context.Background(), "alice", "        ", "key", "invite")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestLogin_NilServices(t *testing.T) {
	svc := &Service{}
	_, _, _, err := svc.Login(context.Background(), "alice", "password123", "key")
	if err == nil {
		t.Fatal("expected error for nil services")
	}
}

func TestLogin_EmptyUsername(t *testing.T) {
	svc := newTestService()
	_, _, _, err := svc.Login(context.Background(), "", "password123", "key")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestLogin_EmptyPublicKey(t *testing.T) {
	svc := newTestService()
	_, _, _, err := svc.Login(context.Background(), "alice", "password123", "")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestLogin_WhitespacePublicKey(t *testing.T) {
	svc := newTestService()
	_, _, _, err := svc.Login(context.Background(), "alice", "password123", "   ")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestLogin_EmptyPassword(t *testing.T) {
	svc := newTestService()
	_, _, _, err := svc.Login(context.Background(), "alice", "", "key")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestLogin_ExistingDeviceSamePublicKey(t *testing.T) {
	svc := newTestService()
	ctx := context.Background()
	// Register creates user and device
	_, _, _, err := svc.Register(ctx, "carol", "password123", "a2V5MQ==", "invite-1")
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	// Login with same public key should find existing device
	_, d, _, err := svc.Login(ctx, "carol", "password123", "a2V5MQ==")
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if d.PublicKey != "a2V5MQ==" {
		t.Errorf("PublicKey = %q, want %q", d.PublicKey, "a2V5MQ==")
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

func TestValidateRegisterPassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"valid", "password1", false},
		{"empty", "", true},
		{"whitespace", "   ", true},
		{"short", "abc1", true},
		{"no digit", "abcdefgh", true},
		{"no letter", "12345678", true},
		{"special chars with both", "p@ssw0rd!", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRegisterPassword(tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateRegisterPassword(%q) error = %v, wantErr %v", tt.password, err, tt.wantErr)
			}
		})
	}
}

func TestTokenStore_ConcurrentAccess(t *testing.T) {
	store := newTokenStore()
	s := Session{Token: "tok1", UserID: "u1", ExpiresAt: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)}
	store.store(s)
	got, err := store.validate(time.Now(), "tok1")
	if err != nil {
		t.Fatalf("validate() error = %v", err)
	}
	if got.UserID != "u1" {
		t.Errorf("UserID = %q, want %q", got.UserID, "u1")
	}
}

func TestLogin_UserWithEmptyPasswordHash(t *testing.T) {
	svc := newTestService()
	ctx := context.Background()
	// Create a user without password via the user service directly
	_, err := svc.users.Create(ctx, "testuser")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	_, _, _, err = svc.Login(ctx, "testuser", "password123", "key")
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

func TestRegister_FirstUserIsAdmin(t *testing.T) {
	svc := newTestService()
	ctx := context.Background()
	u, _, _, err := svc.Register(ctx, "first", "password123", "a2V5MQ==", "invite-1")
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if !u.IsAdmin {
		t.Error("first user should be admin")
	}
}

func TestRegister_SecondUserNotAdmin(t *testing.T) {
	svc := newTestService()
	ctx := context.Background()
	_, _, _, _ = svc.Register(ctx, "first", "password123", "a2V5MQ==", "invite-1")
	u, _, _, err := svc.Register(ctx, "second", "password456", "a2V5Mg==", "invite-2")
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if u.IsAdmin {
		t.Error("second user should not be admin")
	}
}

func TestNewService(t *testing.T) {
	userRepo := newFakeUserRepo()
	deviceRepo := newFakeDeviceRepo()
	inviteRepo := newFakeInviteRepo()
	userSvc := user.NewService(userRepo, "pepper")
	deviceSvc := device.NewService(deviceRepo)
	inviteSvc := serverinvite.NewService(inviteRepo)
	svc := NewService(userSvc, deviceSvc, inviteSvc)
	if svc == nil {
		t.Fatal("NewService() returned nil")
	}
	if svc.tokenTTL != 24*time.Hour {
		t.Errorf("tokenTTL = %v, want 24h", svc.tokenTTL)
	}
}

func TestRegister_InvalidConsumedInvite(t *testing.T) {
	svc := newTestService()
	ctx := context.Background()
	// First register consumes invite-1
	_, _, _, _ = svc.Register(ctx, "alice", "password123", "a2V5MQ==", "invite-1")
	// Try to use same invite again
	_, _, _, err := svc.Register(ctx, "bob", "password456", "a2V5Mg==", "invite-1")
	if err == nil {
		t.Fatal("expected error for consumed invite")
	}
}

// ── error-injecting fakes for additional coverage ──

type errUserRepo struct {
	fakeUserRepo
	countErr  error
	createErr error
}

func (r *errUserRepo) Count(_ context.Context) (int, error) {
	if r.countErr != nil {
		return 0, r.countErr
	}
	return r.fakeUserRepo.Count(context.Background())
}

func (r *errUserRepo) Create(ctx context.Context, u user.User) error {
	if r.createErr != nil {
		return r.createErr
	}
	return r.fakeUserRepo.Create(ctx, u)
}

type errDeviceRepo struct {
	fakeDeviceRepo
	createErr          error
	getByUserPubKeyErr error
}

func (r *errDeviceRepo) Create(ctx context.Context, d device.Device) error {
	if r.createErr != nil {
		return r.createErr
	}
	return r.fakeDeviceRepo.Create(ctx, d)
}

func (r *errDeviceRepo) GetByUserAndPublicKey(ctx context.Context, userID user.ID, pk string) (device.Device, error) {
	if r.getByUserPubKeyErr != nil {
		return device.Device{}, r.getByUserPubKeyErr
	}
	return r.fakeDeviceRepo.GetByUserAndPublicKey(ctx, userID, pk)
}

func TestRegister_CountError(t *testing.T) {
	userRepo := &errUserRepo{fakeUserRepo: *newFakeUserRepo(), countErr: errors.New("count failed")}
	deviceRepo := newFakeDeviceRepo()
	inviteRepo := newFakeInviteRepo()
	userSvc := user.NewService(userRepo, "test-pepper")
	deviceSvc := device.NewService(deviceRepo)
	inviteSvc := serverinvite.NewService(inviteRepo)
	svc := NewService(userSvc, deviceSvc, inviteSvc)

	_, _, _, err := svc.Register(context.Background(), "alice", "password123", "a2V5MQ==", "invite-1")
	if err == nil {
		t.Fatal("expected error for count failure")
	}
}

func TestRegister_CreateUserError(t *testing.T) {
	userRepo := &errUserRepo{fakeUserRepo: *newFakeUserRepo(), createErr: errors.New("db error")}
	deviceRepo := newFakeDeviceRepo()
	inviteRepo := newFakeInviteRepo()
	userSvc := user.NewService(userRepo, "test-pepper")
	deviceSvc := device.NewService(deviceRepo)
	inviteSvc := serverinvite.NewService(inviteRepo)
	svc := NewService(userSvc, deviceSvc, inviteSvc)

	_, _, _, err := svc.Register(context.Background(), "alice", "password123", "a2V5MQ==", "invite-1")
	if err == nil {
		t.Fatal("expected error for user creation failure")
	}
}

func TestRegister_CreateDeviceError(t *testing.T) {
	userRepo := newFakeUserRepo()
	deviceRepo := &errDeviceRepo{fakeDeviceRepo: *newFakeDeviceRepo(), createErr: errors.New("device db error")}
	inviteRepo := newFakeInviteRepo()
	userSvc := user.NewService(userRepo, "test-pepper")
	deviceSvc := device.NewService(deviceRepo)
	inviteSvc := serverinvite.NewService(inviteRepo)
	svc := NewService(userSvc, deviceSvc, inviteSvc)

	_, _, _, err := svc.Register(context.Background(), "alice", "password123", "a2V5MQ==", "invite-1")
	if err == nil {
		t.Fatal("expected error for device creation failure")
	}
}

func TestLogin_DeviceLookupNonNotFoundError(t *testing.T) {
	userRepo := newFakeUserRepo()
	deviceRepo := &errDeviceRepo{fakeDeviceRepo: *newFakeDeviceRepo(), getByUserPubKeyErr: errors.New("db connection error")}
	inviteRepo := newFakeInviteRepo()
	userSvc := user.NewService(userRepo, "test-pepper")
	deviceSvc := device.NewService(deviceRepo)
	inviteSvc := serverinvite.NewService(inviteRepo)
	svc := NewService(userSvc, deviceSvc, inviteSvc)

	// Register first to create the user
	_, _, _, err := svc.Register(context.Background(), "alice", "password123", "a2V5MQ==", "invite-1")
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	// Now inject error for device lookup
	deviceRepo.getByUserPubKeyErr = errors.New("db connection error")

	_, _, _, err = svc.Login(context.Background(), "alice", "password123", "a2V5Mg==")
	if err == nil {
		t.Fatal("expected error for device lookup failure")
	}
}

func TestLogin_DeviceCreateError(t *testing.T) {
	userRepo := newFakeUserRepo()
	deviceRepo := &errDeviceRepo{fakeDeviceRepo: *newFakeDeviceRepo()}
	inviteRepo := newFakeInviteRepo()
	userSvc := user.NewService(userRepo, "test-pepper")
	deviceSvc := device.NewService(deviceRepo)
	inviteSvc := serverinvite.NewService(inviteRepo)
	svc := NewService(userSvc, deviceSvc, inviteSvc)

	// Register first
	_, _, _, err := svc.Register(context.Background(), "alice", "password123", "a2V5MQ==", "invite-1")
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	// Now inject error for device creation (new key triggers Create path)
	deviceRepo.createErr = errors.New("device create error")

	_, _, _, err = svc.Login(context.Background(), "alice", "password123", "newkey123")
	if err == nil {
		t.Fatal("expected error for device creation failure during login")
	}
}
