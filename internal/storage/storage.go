package storage

import "context"

type Store interface {
	Close(ctx context.Context) error
}

type NopStore struct{}

func NewNopStore() *NopStore {
	return &NopStore{}
}

func (s *NopStore) Close(ctx context.Context) error {
	return nil
}
