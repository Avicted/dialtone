package channel

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/Avicted/dialtone/internal/user"
	"github.com/google/uuid"
)

const defaultHistoryLimit = 100

type Service struct {
	repo  Repository
	users *user.Service
	idGen func() string
	now   func() time.Time
}

func NewService(repo Repository, users *user.Service) *Service {
	return &Service{
		repo:  repo,
		users: users,
		idGen: func() string { return uuid.NewString() },
		now:   time.Now,
	}
}

func (s *Service) CreateChannel(ctx context.Context, userID user.ID, nameEnc string) (Channel, error) {
	if s.repo == nil {
		return Channel{}, errors.New("repository is required")
	}
	if userID == "" {
		return Channel{}, ErrInvalidInput
	}
	if strings.TrimSpace(nameEnc) == "" {
		return Channel{}, ErrInvalidInput
	}
	if err := s.requireAdmin(ctx, userID); err != nil {
		return Channel{}, err
	}

	ch := Channel{
		ID:        ID(s.idGen()),
		NameEnc:   strings.TrimSpace(nameEnc),
		CreatedBy: userID,
		CreatedAt: s.now().UTC(),
	}
	if err := s.repo.CreateChannel(ctx, ch); err != nil {
		return Channel{}, err
	}
	return ch, nil
}

func (s *Service) ListChannels(ctx context.Context, userID user.ID) ([]Channel, error) {
	if s.repo == nil {
		return nil, errors.New("repository is required")
	}
	if userID == "" {
		return nil, ErrInvalidInput
	}
	return s.repo.ListChannels(ctx)
}

func (s *Service) DeleteChannel(ctx context.Context, userID user.ID, channelID ID) error {
	if s.repo == nil {
		return errors.New("repository is required")
	}
	if userID == "" || channelID == "" {
		return ErrInvalidInput
	}
	if err := s.requireAdmin(ctx, userID); err != nil {
		return err
	}
	return s.repo.DeleteChannel(ctx, channelID)
}

func (s *Service) UpdateChannelName(ctx context.Context, userID user.ID, channelID ID, nameEnc string) (Channel, error) {
	if s.repo == nil {
		return Channel{}, errors.New("repository is required")
	}
	if userID == "" || channelID == "" {
		return Channel{}, ErrInvalidInput
	}
	if strings.TrimSpace(nameEnc) == "" {
		return Channel{}, ErrInvalidInput
	}
	if err := s.requireAdmin(ctx, userID); err != nil {
		return Channel{}, err
	}
	if err := s.repo.UpdateChannelName(ctx, channelID, strings.TrimSpace(nameEnc)); err != nil {
		return Channel{}, err
	}
	return s.repo.GetChannel(ctx, channelID)
}

func (s *Service) requireAdmin(ctx context.Context, userID user.ID) error {
	if s.users == nil {
		return errors.New("user service is required")
	}
	adminUser, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return err
	}
	if !adminUser.IsAdmin {
		return ErrForbidden
	}
	return nil
}

func (s *Service) ListMessages(ctx context.Context, userID user.ID, channelID ID, limit int) ([]Message, error) {
	if s.repo == nil {
		return nil, errors.New("repository is required")
	}
	if userID == "" || channelID == "" {
		return nil, ErrInvalidInput
	}
	if limit <= 0 {
		limit = defaultHistoryLimit
	}
	return s.repo.ListRecentMessages(ctx, channelID, limit)
}
