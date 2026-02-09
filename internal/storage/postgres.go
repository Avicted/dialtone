package storage

import (
	"context"
	"database/sql"
	"fmt"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore(ctx context.Context, dbURL string) (*PostgresStore, error) {
	if dbURL == "" {
		return nil, fmt.Errorf("db url is required")
	}

	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping db: %w", err)
	}

	return &PostgresStore{db: db}, nil
}

func (s *PostgresStore) Close(ctx context.Context) error {
	_ = ctx
	return s.db.Close()
}

func (s *PostgresStore) Migrate(ctx context.Context) error {
	migrator := NewMigrator(s.db, migrationsFS)
	return migrator.Up(ctx)
}
