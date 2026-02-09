package storage

import (
	"context"
	"errors"

	"github.com/Avicted/dialtone/internal/device"
	"github.com/Avicted/dialtone/internal/message"
	"github.com/Avicted/dialtone/internal/user"
)

var ErrNotFound = errors.New("not found")

type Store interface {
	Close(ctx context.Context) error
	Migrate(ctx context.Context) error
	Users() user.Repository
	Devices() device.Repository
	Messages() message.Repository
}

type NopStore struct{}

func NewNopStore() *NopStore {
	return &NopStore{}
}

func (s *NopStore) Close(ctx context.Context) error {
	_ = ctx
	return nil
}

func (s *NopStore) Migrate(ctx context.Context) error {
	_ = ctx
	return nil
}

func (s *NopStore) Users() user.Repository {
	return nil
}

func (s *NopStore) Devices() device.Repository {
	return nil
}

func (s *NopStore) Messages() message.Repository {
	return nil
}
