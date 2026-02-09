package device

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/Avicted/dialtone/internal/user"
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

func (s *Service) Create(ctx context.Context, userID user.ID, publicKey string) (Device, error) {
	if s.repo == nil {
		return Device{}, errors.New("repository is required")
	}

	key := strings.TrimSpace(publicKey)
	if userID == "" || key == "" {
		return Device{}, ErrInvalidInput
	}

	d := Device{
		ID:        s.idGen(),
		UserID:    userID,
		PublicKey: key,
		CreatedAt: s.now().UTC(),
	}

	if err := s.repo.Create(ctx, d); err != nil {
		return Device{}, err
	}
	return d, nil
}

// ListByUser returns all devices for a given user.
func (s *Service) ListByUser(ctx context.Context, userID user.ID) ([]Device, error) {
	if s.repo == nil {
		return nil, errors.New("repository is required")
	}
	if userID == "" {
		return nil, ErrInvalidInput
	}
	return s.repo.ListByUser(ctx, userID)
}
