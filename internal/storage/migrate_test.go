package storage

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func setupPostgresDB(t *testing.T) (*sql.DB, func()) {
	t.Helper()
	if err := testcontainers.SkipIfDockerNotAvailable(); err != nil {
		t.Skip("docker not available for testcontainers")
	}

	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "dialtone",
			"POSTGRES_PASSWORD": "dialtone",
			"POSTGRES_DB":       "dialtone",
		},
		WaitingFor: wait.ForLog("database system is ready to accept connections").WithStartupTimeout(60 * time.Second),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("start postgres: %v", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		_ = container.Terminate(ctx)
		t.Fatalf("postgres host: %v", err)
	}
	port, err := container.MappedPort(ctx, "5432/tcp")
	if err != nil {
		_ = container.Terminate(ctx)
		t.Fatalf("postgres port: %v", err)
	}
	conn := fmt.Sprintf("postgres://dialtone:dialtone@%s:%s/dialtone?sslmode=disable", host, port.Port())

	db, err := sql.Open("pgx", conn)
	if err != nil {
		_ = container.Terminate(ctx)
		t.Fatalf("open db: %v", err)
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		_ = container.Terminate(ctx)
		t.Fatalf("ping db: %v", err)
	}

	cleanup := func() {
		_ = db.Close()
		_ = container.Terminate(context.Background())
	}
	return db, cleanup
}

func TestMigrator_RecordApplied(t *testing.T) {
	db, cleanup := setupPostgresDB(t)
	defer cleanup()

	m := NewMigrator(db, migrationsFS)
	ctx := context.Background()
	if err := m.ensureTable(ctx); err != nil {
		t.Fatalf("ensureTable() error = %v", err)
	}

	if err := m.recordApplied(ctx, "0001_schema.sql"); err != nil {
		t.Fatalf("recordApplied() error = %v", err)
	}

	var id string
	var appliedAt time.Time
	row := db.QueryRowContext(ctx, `SELECT id, applied_at FROM schema_migrations WHERE id = $1`, "0001_schema.sql")
	if err := row.Scan(&id, &appliedAt); err != nil {
		t.Fatalf("scan schema_migrations: %v", err)
	}
	if id != "0001_schema.sql" {
		t.Fatalf("id = %q, want %q", id, "0001_schema.sql")
	}
	if appliedAt.IsZero() {
		t.Fatal("expected applied_at to be set")
	}
}
