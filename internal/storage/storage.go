package storage

import (
	"context"
	"errors"

	"github.com/Avicted/dialtone/internal/channel"
	"github.com/Avicted/dialtone/internal/device"
	"github.com/Avicted/dialtone/internal/message"
	"github.com/Avicted/dialtone/internal/serverinvite"
	"github.com/Avicted/dialtone/internal/user"
)

var ErrNotFound = errors.New("not found")

type Store interface {
	Close(ctx context.Context) error
	Migrate(ctx context.Context) error
	Users() user.Repository
	Devices() device.Repository
	Broadcasts() message.BroadcastRepository
	Channels() channel.Repository
	ServerInvites() serverinvite.Repository
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

func (s *NopStore) Broadcasts() message.BroadcastRepository {
	return nil
}

func (s *NopStore) Channels() channel.Repository {
	return nil
}

func (s *NopStore) ServerInvites() serverinvite.Repository {
	return nil
}
