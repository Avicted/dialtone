package device

import (
	"context"
	"time"

	"github.com/Avicted/dialtone/internal/user"
)

type ID string

type Device struct {
	ID         ID
	UserID     user.ID
	PublicKey  string
	CreatedAt  time.Time
	LastSeenAt *time.Time
}

type Repository interface {
	Create(ctx context.Context, device Device) error
	GetByID(ctx context.Context, id ID) (Device, error)
	ListByUser(ctx context.Context, userID user.ID) ([]Device, error)
	UpdateLastSeen(ctx context.Context, id ID, lastSeenAt time.Time) error
}
