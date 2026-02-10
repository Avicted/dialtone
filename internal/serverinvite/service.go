package serverinvite

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/Avicted/dialtone/internal/user"
	"github.com/google/uuid"
)

type Service struct {
	repo  Repository
	idGen func() string
	now   func() time.Time
}

func NewService(repo Repository) *Service {
	return &Service{
		repo:  repo,
		idGen: func() string { return uuid.NewString() },
		now:   time.Now,
	}
}

func (s *Service) Create(ctx context.Context) (Invite, error) {
	if s.repo == nil {
		return Invite{}, errors.New("repository is required")
	}

	now := s.now().UTC()
	invite := Invite{
		Token:     s.idGen(),
		CreatedAt: now,
		ExpiresAt: now.Add(24 * time.Hour),
	}
	if err := s.repo.Create(ctx, invite); err != nil {
		return Invite{}, err
	}
	return invite, nil
}

func (s *Service) Consume(ctx context.Context, token string, userID user.ID) (Invite, error) {
	if s.repo == nil {
		return Invite{}, errors.New("repository is required")
	}
	if strings.TrimSpace(token) == "" || userID == "" {
		return Invite{}, ErrInvalidInput
	}
	return s.repo.Consume(ctx, strings.TrimSpace(token), userID, s.now().UTC())
}
