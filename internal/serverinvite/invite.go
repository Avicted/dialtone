package serverinvite

import (
	"context"
	"errors"
	"time"

	"github.com/Avicted/dialtone/internal/user"
)

type Invite struct {
	Token      string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	ConsumedAt *time.Time
	ConsumedBy *user.ID
}

var (
	ErrInvalidInput = errors.New("invalid input")
	ErrNotFound     = errors.New("not found")
	ErrExpired      = errors.New("invite expired")
	ErrConsumed     = errors.New("invite already used")
)

type Repository interface {
	Create(ctx context.Context, invite Invite) error
	Consume(ctx context.Context, token string, userID user.ID, now time.Time) (Invite, error)
}
