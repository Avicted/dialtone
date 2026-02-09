package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Avicted/dialtone/internal/device"
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

func newTestService() *Service {
	userRepo := newFakeUserRepo()
	deviceRepo := newFakeDeviceRepo()
	userSvc := user.NewService(userRepo)
	deviceSvc := device.NewService(deviceRepo)
	svc := NewService(userSvc, deviceSvc)
	svc.now = func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	return svc
}

func TestRegister_Success(t *testing.T) {
	svc := newTestService()
	ctx := context.Background()

	u, d, session, err := svc.Register(ctx, "alice", "password123", "dGVzdHB1YmtleQ==")
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

	_, _, _, err := svc.Register(ctx, "alice", "password123", "a2V5MQ==")
	if err != nil {
		t.Fatalf("first Register() error = %v", err)
	}

	_, _, _, err = svc.Register(ctx, "alice", "password456", "a2V5Mg==")
	if err == nil {
		t.Fatal("expected error for duplicate username")
	}
}

func TestRegister_ShortPassword(t *testing.T) {
	svc := newTestService()
	_, _, _, err := svc.Register(context.Background(), "bob", "short", "a2V5")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestRegister_EmptyPublicKey(t *testing.T) {
	svc := newTestService()
	_, _, _, err := svc.Register(context.Background(), "bob", "password123", "")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestRegister_EmptyUsername(t *testing.T) {
	svc := newTestService()
	_, _, _, err := svc.Register(context.Background(), "", "password123", "a2V5")
	if err == nil {
		t.Fatal("expected error for empty username")
	}
}

func TestLogin_Success(t *testing.T) {
	svc := newTestService()
	ctx := context.Background()

	_, _, _, err := svc.Register(ctx, "carol", "password123", "a2V5MQ==")
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

	_, _, _, _ = svc.Register(ctx, "dave", "password123", "a2V5MQ==")
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

	_, _, session, _ := svc.Register(ctx, "frank", "password123", "a2V5MQ==")

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

	_, _, session, _ := svc.Register(ctx, "grace", "password123", "a2V5MQ==")

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
