package user

import (
	"context"
	"time"
)

type ID string

type User struct {
	ID           ID
	UsernameHash string
	PasswordHash string
	IsAdmin      bool
	CreatedAt    time.Time
}

type Repository interface {
	Create(ctx context.Context, user User) error
	GetByID(ctx context.Context, id ID) (User, error)
	GetByUsernameHash(ctx context.Context, usernameHash string) (User, error)
	Count(ctx context.Context) (int, error)
}
