package storage

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/Avicted/dialtone/internal/device"
	"github.com/Avicted/dialtone/internal/message"
	"github.com/Avicted/dialtone/internal/securestore"
	"github.com/Avicted/dialtone/internal/user"
	_ "github.com/jackc/pgx/v5/stdlib"
)

type PostgresStore struct {
	db         *sql.DB
	users      *userRepo
	devices    *deviceRepo
	messages   *messageRepo
	broadcasts *broadcastRepo
}

func NewPostgresStore(ctx context.Context, dbURL string, crypto *securestore.FieldCrypto) (*PostgresStore, error) {
	if dbURL == "" {
		return nil, fmt.Errorf("db url is required")
	}
	if crypto == nil {
		return nil, fmt.Errorf("field crypto is required")
	}

	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping db: %w", err)
	}

	store := &PostgresStore{db: db}
	store.users = &userRepo{db: db, crypto: crypto}
	store.devices = &deviceRepo{db: db, crypto: crypto}
	store.messages = &messageRepo{db: db}
	store.broadcasts = &broadcastRepo{db: db, crypto: crypto}
	return store, nil
}

func (s *PostgresStore) Close(ctx context.Context) error {
	_ = ctx
	return s.db.Close()
}

func (s *PostgresStore) Migrate(ctx context.Context) error {
	migrator := NewMigrator(s.db, migrationsFS)
	return migrator.Up(ctx)
}

func (s *PostgresStore) Users() user.Repository {
	return s.users
}

func (s *PostgresStore) Devices() device.Repository {
	return s.devices
}

func (s *PostgresStore) Messages() message.Repository {
	return s.messages
}

func (s *PostgresStore) Broadcasts() message.BroadcastRepository {
	return s.broadcasts
}
