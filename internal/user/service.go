package user

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

var ErrInvalidInput = errors.New("invalid input")

type Service struct {
	repo  Repository
	idGen func() ID
	now   func() time.Time
}

func NewService(repo Repository) *Service {
	return &Service{
		repo: repo,
		idGen: func() ID {
			return ID(uuid.NewString())
		},
		now: time.Now,
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
	usernameHash := hashUsername(name)

	u := User{
		ID:           s.idGen(),
		UsernameHash: usernameHash,
		PasswordHash: "",
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
	usernameHash := hashUsername(name)

	u := User{
		ID:           s.idGen(),
		UsernameHash: usernameHash,
		PasswordHash: passwordHash,
		CreatedAt:    s.now().UTC(),
	}

	if err := s.repo.Create(ctx, u); err != nil {
		return User{}, err
	}
	return u, nil
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
	return s.repo.GetByUsernameHash(ctx, hashUsername(name))
}

func normalizeUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

func hashUsername(username string) string {
	sum := sha256.Sum256([]byte(username))
	return hex.EncodeToString(sum[:])
}
