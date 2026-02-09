package storage

import "context"

type PostgresStore struct{}

func NewPostgresStore(ctx context.Context, dbURL string) (*PostgresStore, error) {
	_ = ctx
	_ = dbURL
	return &PostgresStore{}, nil
}

func (s *PostgresStore) Close(ctx context.Context) error {
	_ = ctx
	return nil
}
