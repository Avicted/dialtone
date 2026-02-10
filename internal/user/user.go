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
	IsTrusted    bool
	CreatedAt    time.Time
}

type Profile struct {
	UserID    ID
	NameEnc   string
	UpdatedAt time.Time
}

type DirectoryKeyEnvelope struct {
	DeviceID        string
	SenderDeviceID  string
	SenderPublicKey string
	Envelope        string
	CreatedAt       time.Time
}

type Repository interface {
	Create(ctx context.Context, user User) error
	GetByID(ctx context.Context, id ID) (User, error)
	GetByUsernameHash(ctx context.Context, usernameHash string) (User, error)
	Count(ctx context.Context) (int, error)
	UpsertProfile(ctx context.Context, profile Profile) error
	ListProfiles(ctx context.Context) ([]Profile, error)
	UpsertDirectoryKeyEnvelope(ctx context.Context, env DirectoryKeyEnvelope) error
	GetDirectoryKeyEnvelope(ctx context.Context, deviceID string) (DirectoryKeyEnvelope, error)
}
