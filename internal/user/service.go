package user

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

var ErrInvalidInput = errors.New("invalid input")

type Service struct {
	repo   Repository
	idGen  func() ID
	now    func() time.Time
	pepper []byte
}

func NewService(repo Repository, pepper string) *Service {
	return &Service{
		repo: repo,
		idGen: func() ID {
			return ID(uuid.NewString())
		},
		now:    time.Now,
		pepper: []byte(pepper),
	}
}

func (s *Service) Create(ctx context.Context, username string) (User, error) {
	if s.repo == nil {
		return User{}, errors.New("repository is required")
	}

	name := normalizeUsername(username)
	if name == "" {
		return User{}, ErrInvalidInput
	}
	if len(s.pepper) == 0 {
		return User{}, errors.New("username pepper is required")
	}
	usernameHash := hashUsername(s.pepper, name)

	u := User{
		ID:           s.idGen(),
		UsernameHash: usernameHash,
		PasswordHash: "",
		IsAdmin:      false,
		IsTrusted:    false,
		CreatedAt:    s.now().UTC(),
	}

	if err := s.repo.Create(ctx, u); err != nil {
		return User{}, err
	}
	return u, nil
}

func (s *Service) CreateWithPassword(ctx context.Context, username, passwordHash string) (User, error) {
	if s.repo == nil {
		return User{}, errors.New("repository is required")
	}

	name := normalizeUsername(username)
	if name == "" || strings.TrimSpace(passwordHash) == "" {
		return User{}, ErrInvalidInput
	}
	if len(s.pepper) == 0 {
		return User{}, errors.New("username pepper is required")
	}
	usernameHash := hashUsername(s.pepper, name)

	u := User{
		ID:           s.idGen(),
		UsernameHash: usernameHash,
		PasswordHash: passwordHash,
		IsAdmin:      false,
		IsTrusted:    false,
		CreatedAt:    s.now().UTC(),
	}

	if err := s.repo.Create(ctx, u); err != nil {
		return User{}, err
	}
	return u, nil
}

func (s *Service) CreateWithPasswordAndID(ctx context.Context, id ID, username, passwordHash string, isAdmin bool, isTrusted bool) (User, error) {
	if s.repo == nil {
		return User{}, errors.New("repository is required")
	}
	if id == "" {
		return User{}, ErrInvalidInput
	}
	name := normalizeUsername(username)
	if name == "" || strings.TrimSpace(passwordHash) == "" {
		return User{}, ErrInvalidInput
	}
	if len(s.pepper) == 0 {
		return User{}, errors.New("username pepper is required")
	}
	usernameHash := hashUsername(s.pepper, name)

	u := User{
		ID:           id,
		UsernameHash: usernameHash,
		PasswordHash: passwordHash,
		IsAdmin:      isAdmin,
		IsTrusted:    isTrusted,
		CreatedAt:    s.now().UTC(),
	}

	if err := s.repo.Create(ctx, u); err != nil {
		return User{}, err
	}
	return u, nil
}

func (s *Service) NewID() ID {
	return s.idGen()
}

func (s *Service) Count(ctx context.Context) (int, error) {
	if s.repo == nil {
		return 0, errors.New("repository is required")
	}
	return s.repo.Count(ctx)
}

func (s *Service) GetByID(ctx context.Context, id ID) (User, error) {
	if s.repo == nil {
		return User{}, errors.New("repository is required")
	}
	if id == "" {
		return User{}, ErrInvalidInput
	}
	return s.repo.GetByID(ctx, id)
}

func (s *Service) GetByUsername(ctx context.Context, username string) (User, error) {
	if s.repo == nil {
		return User{}, errors.New("repository is required")
	}
	name := normalizeUsername(username)
	if name == "" {
		return User{}, ErrInvalidInput
	}
	if len(s.pepper) == 0 {
		return User{}, errors.New("username pepper is required")
	}
	return s.repo.GetByUsernameHash(ctx, hashUsername(s.pepper, name))
}

func (s *Service) UpsertProfile(ctx context.Context, userID ID, nameEnc string) error {
	if s.repo == nil {
		return errors.New("repository is required")
	}
	if userID == "" || strings.TrimSpace(nameEnc) == "" {
		return ErrInvalidInput
	}
	profile := Profile{
		UserID:    userID,
		NameEnc:   strings.TrimSpace(nameEnc),
		UpdatedAt: s.now().UTC(),
	}
	return s.repo.UpsertProfile(ctx, profile)
}

func (s *Service) ListProfiles(ctx context.Context) ([]Profile, error) {
	if s.repo == nil {
		return nil, errors.New("repository is required")
	}
	return s.repo.ListProfiles(ctx)
}

func (s *Service) UpsertDirectoryKeyEnvelope(ctx context.Context, env DirectoryKeyEnvelope) error {
	if s.repo == nil {
		return errors.New("repository is required")
	}
	if strings.TrimSpace(env.DeviceID) == "" || strings.TrimSpace(env.SenderDeviceID) == "" {
		return ErrInvalidInput
	}
	if strings.TrimSpace(env.SenderPublicKey) == "" || strings.TrimSpace(env.Envelope) == "" {
		return ErrInvalidInput
	}
	if env.CreatedAt.IsZero() {
		env.CreatedAt = s.now().UTC()
	}
	return s.repo.UpsertDirectoryKeyEnvelope(ctx, env)
}

func (s *Service) GetDirectoryKeyEnvelope(ctx context.Context, deviceID string) (DirectoryKeyEnvelope, error) {
	if s.repo == nil {
		return DirectoryKeyEnvelope{}, errors.New("repository is required")
	}
	if strings.TrimSpace(deviceID) == "" {
		return DirectoryKeyEnvelope{}, ErrInvalidInput
	}
	return s.repo.GetDirectoryKeyEnvelope(ctx, deviceID)
}

func normalizeUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

func hashUsername(pepper []byte, username string) string {
	mac := hmac.New(sha256.New, pepper)
	_, _ = mac.Write([]byte(username))
	return hex.EncodeToString(mac.Sum(nil))
}
