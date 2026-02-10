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
		CreatedAt:    s.now().UTC(),
	}

	if err := s.repo.Create(ctx, u); err != nil {
		return User{}, err
	}
	return u, nil
}

func (s *Service) CreateWithPasswordAndID(ctx context.Context, id ID, username, passwordHash string, isAdmin bool) (User, error) {
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

func normalizeUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

func hashUsername(pepper []byte, username string) string {
	mac := hmac.New(sha256.New, pepper)
	_, _ = mac.Write([]byte(username))
	return hex.EncodeToString(mac.Sum(nil))
}
