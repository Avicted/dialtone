package room

import (
	"context"
	"errors"
	"time"

	"github.com/Avicted/dialtone/internal/user"
)

type ID string

type Room struct {
	ID        ID
	NameEnc   string
	CreatedBy user.ID
	CreatedAt time.Time
}

type Invite struct {
	Token      string
	RoomID     ID
	CreatedBy  user.ID
	CreatedAt  time.Time
	ExpiresAt  time.Time
	ConsumedAt *time.Time
	ConsumedBy *user.ID
}

type Message struct {
	ID            string
	RoomID        ID
	SenderID      user.ID
	SenderNameEnc string
	Body          string
	SentAt        time.Time
}

type Member struct {
	UserID         user.ID
	DisplayNameEnc string
}

var (
	ErrInvalidInput   = errors.New("invalid input")
	ErrNotFound       = errors.New("not found")
	ErrInviteExpired  = errors.New("invite expired")
	ErrInviteConsumed = errors.New("invite already used")
)

type Repository interface {
	CreateRoom(ctx context.Context, room Room) error
	GetRoom(ctx context.Context, id ID) (Room, error)
	ListRoomsForUser(ctx context.Context, userID user.ID) ([]Room, error)
	AddMember(ctx context.Context, roomID ID, userID user.ID, displayNameEnc string, joinedAt time.Time) error
	IsMember(ctx context.Context, roomID ID, userID user.ID) (bool, error)
	ListMembers(ctx context.Context, roomID ID) ([]Member, error)
	GetMemberDisplayNameEnc(ctx context.Context, roomID ID, userID user.ID) (string, error)
	CreateInvite(ctx context.Context, invite Invite) error
	ConsumeInvite(ctx context.Context, token string, userID user.ID, displayNameEnc string, now time.Time) (Invite, error)
	SaveMessage(ctx context.Context, msg Message) error
	ListRecentMessages(ctx context.Context, roomID ID, limit int) ([]Message, error)
}
