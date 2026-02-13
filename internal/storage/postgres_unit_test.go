package storage

import (
	"context"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestNewPostgresStoreValidationAndPingFailure(t *testing.T) {
	ctx := context.Background()

	store, err := NewPostgresStore(ctx, "")
	if err == nil || !strings.Contains(err.Error(), "db url is required") {
		t.Fatalf("expected db url required error, got store=%v err=%v", store, err)
	}

	expiredCtx, cancel := context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer cancel()
	store, err = NewPostgresStore(expiredCtx, "postgres://dialtone:dialtone@127.0.0.1:1/dialtone?sslmode=disable")
	if err == nil || !strings.Contains(err.Error(), "ping db") {
		t.Fatalf("expected ping db failure, got store=%v err=%v", store, err)
	}
}

func TestPostgresStoreMigrateAndAccessors(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	store := &PostgresStore{
		db:            db,
		users:         &userRepo{db: db},
		devices:       &deviceRepo{db: db},
		broadcasts:    &broadcastRepo{db: db},
		channels:      &channelRepo{db: db},
		serverInvites: &serverInviteRepo{db: db},
	}

	files, err := fs.Glob(migrationsFS, "migrations/*.sql")
	if err != nil {
		t.Fatalf("glob migrations: %v", err)
	}
	rows := sqlmock.NewRows([]string{"id"})
	for _, file := range files {
		rows.AddRow(filepath.Base(file))
	}

	mock.ExpectExec(`CREATE TABLE IF NOT EXISTS schema_migrations`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT id FROM schema_migrations`).WillReturnRows(rows)
	mock.ExpectClose()

	if err := store.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate() error: %v", err)
	}
	if got := store.Users(); got != store.users {
		t.Fatalf("Users() returned unexpected repository pointer")
	}
	if got := store.Devices(); got != store.devices {
		t.Fatalf("Devices() returned unexpected repository pointer")
	}
	if got := store.Broadcasts(); got != store.broadcasts {
		t.Fatalf("Broadcasts() returned unexpected repository pointer")
	}
	if got := store.Channels(); got != store.channels {
		t.Fatalf("Channels() returned unexpected repository pointer")
	}
	if got := store.ServerInvites(); got != store.serverInvites {
		t.Fatalf("ServerInvites() returned unexpected repository pointer")
	}
	if err := store.Close(context.Background()); err != nil {
		t.Fatalf("Close() error: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("sqlmock expectations: %v", err)
	}
}

func TestPostgresStoreMigrateNilDB(t *testing.T) {
	store := &PostgresStore{}
	err := store.Migrate(context.Background())
	if err == nil || !strings.Contains(err.Error(), "db is required") {
		t.Fatalf("expected nil-db migrate error, got %v", err)
	}
}
