package storage

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/Avicted/dialtone/internal/device"
	"github.com/Avicted/dialtone/internal/message"
	"github.com/Avicted/dialtone/internal/room"
	"github.com/Avicted/dialtone/internal/user"
	_ "github.com/jackc/pgx/v5/stdlib"
)

type PostgresStore struct {
	db         *sql.DB
	users      *userRepo
	devices    *deviceRepo
	messages   *messageRepo
	broadcasts *broadcastRepo
	rooms      *roomRepo
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

	store := &PostgresStore{db: db}
	store.users = &userRepo{db: db}
	store.devices = &deviceRepo{db: db}
	store.messages = &messageRepo{db: db}
	store.broadcasts = &broadcastRepo{db: db}
	store.rooms = &roomRepo{db: db}
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

func (s *PostgresStore) Rooms() room.Repository {
	return s.rooms
}
