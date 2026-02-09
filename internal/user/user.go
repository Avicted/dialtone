package user

import (
	"context"
	"time"
)

type ID string

type User struct {
	ID           ID
	Username     string
	PasswordHash string
	CreatedAt    time.Time
}

type Repository interface {
	Create(ctx context.Context, user User) error
	GetByID(ctx context.Context, id ID) (User, error)
	GetByUsername(ctx context.Context, username string) (User, error)
}
