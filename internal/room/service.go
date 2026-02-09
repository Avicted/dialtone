package room

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

func (s *Service) CreateRoom(ctx context.Context, userID user.ID, nameEnc, displayNameEnc string) (Room, error) {
	if s.repo == nil {
		return Room{}, errors.New("repository is required")
	}
	if userID == "" {
		return Room{}, ErrInvalidInput
	}
	if strings.TrimSpace(nameEnc) == "" || strings.TrimSpace(displayNameEnc) == "" {
		return Room{}, ErrInvalidInput
	}

	room := Room{
		ID:        ID(s.idGen()),
		NameEnc:   strings.TrimSpace(nameEnc),
		CreatedBy: userID,
		CreatedAt: s.now().UTC(),
	}
	if err := s.repo.CreateRoom(ctx, room); err != nil {
		return Room{}, err
	}
	if err := s.repo.AddMember(ctx, room.ID, userID, strings.TrimSpace(displayNameEnc), s.now().UTC()); err != nil {
		return Room{}, err
	}
	return room, nil
}

func (s *Service) ListRooms(ctx context.Context, userID user.ID) ([]Room, error) {
	if s.repo == nil {
		return nil, errors.New("repository is required")
	}
	if userID == "" {
		return nil, ErrInvalidInput
	}
	return s.repo.ListRoomsForUser(ctx, userID)
}

func (s *Service) CreateInvite(ctx context.Context, userID user.ID, roomID ID) (Invite, error) {
	if s.repo == nil {
		return Invite{}, errors.New("repository is required")
	}
	if userID == "" || roomID == "" {
		return Invite{}, ErrInvalidInput
	}

	isMember, err := s.repo.IsMember(ctx, roomID, userID)
	if err != nil {
		return Invite{}, err
	}
	if !isMember {
		return Invite{}, ErrNotFound
	}

	now := s.now().UTC()
	invite := Invite{
		Token:     s.idGen(),
		RoomID:    roomID,
		CreatedBy: userID,
		CreatedAt: now,
		ExpiresAt: now.Add(24 * time.Hour),
	}
	if err := s.repo.CreateInvite(ctx, invite); err != nil {
		return Invite{}, err
	}
	return invite, nil
}

func (s *Service) JoinWithInvite(ctx context.Context, userID user.ID, token, displayNameEnc string) (Room, time.Time, []Message, error) {
	if s.repo == nil {
		return Room{}, time.Time{}, nil, errors.New("repository is required")
	}
	if userID == "" || strings.TrimSpace(token) == "" || strings.TrimSpace(displayNameEnc) == "" {
		return Room{}, time.Time{}, nil, ErrInvalidInput
	}

	invite, err := s.repo.ConsumeInvite(ctx, strings.TrimSpace(token), userID, strings.TrimSpace(displayNameEnc), s.now().UTC())
	if err != nil {
		return Room{}, time.Time{}, nil, err
	}

	rm, err := s.repo.GetRoom(ctx, invite.RoomID)
	if err != nil {
		return Room{}, time.Time{}, nil, err
	}

	limit := defaultHistoryLimit
	msgs, err := s.repo.ListRecentMessages(ctx, rm.ID, limit)
	if err != nil {
		return Room{}, time.Time{}, nil, err
	}

	joinedAt := s.now().UTC()
	if invite.ConsumedAt != nil {
		joinedAt = invite.ConsumedAt.UTC()
	}

	return rm, joinedAt, msgs, nil
}

func (s *Service) ListMessages(ctx context.Context, userID user.ID, roomID ID, limit int) ([]Message, error) {
	if s.repo == nil {
		return nil, errors.New("repository is required")
	}
	if userID == "" || roomID == "" {
		return nil, ErrInvalidInput
	}
	if limit <= 0 {
		limit = defaultHistoryLimit
	}
	isMember, err := s.repo.IsMember(ctx, roomID, userID)
	if err != nil {
		return nil, err
	}
	if !isMember {
		return nil, ErrNotFound
	}
	return s.repo.ListRecentMessages(ctx, roomID, limit)
}

func (s *Service) ListMembers(ctx context.Context, userID user.ID, roomID ID) ([]Member, error) {
	if s.repo == nil {
		return nil, errors.New("repository is required")
	}
	if userID == "" || roomID == "" {
		return nil, ErrInvalidInput
	}
	isMember, err := s.repo.IsMember(ctx, roomID, userID)
	if err != nil {
		return nil, err
	}
	if !isMember {
		return nil, ErrNotFound
	}
	return s.repo.ListMembers(ctx, roomID)
}
