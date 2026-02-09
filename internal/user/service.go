package user

import (
	"context"
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

	name := strings.TrimSpace(username)
	if name == "" {
		return User{}, ErrInvalidInput
	}

	u := User{
		ID:        s.idGen(),
		Username:  name,
		CreatedAt: s.now().UTC(),
	}

	if err := s.repo.Create(ctx, u); err != nil {
		return User{}, err
	}
	return u, nil
}
