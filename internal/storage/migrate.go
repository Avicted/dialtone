package storage

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type Migrator struct {
	db *sql.DB
	fs fs.FS
}

func NewMigrator(db *sql.DB, migrations fs.FS) *Migrator {
	return &Migrator{db: db, fs: migrations}
}

func (m *Migrator) Up(ctx context.Context) error {
	if m.db == nil {
		return fmt.Errorf("db is required")
	}

	if err := m.ensureTable(ctx); err != nil {
		return err
	}

	files, err := fs.Glob(m.fs, "migrations/*.sql")
	if err != nil {
		return fmt.Errorf("list migrations: %w", err)
	}
	if len(files) == 0 {
		return nil
	}

	sort.Strings(files)

	applied, err := m.appliedMigrations(ctx)
	if err != nil {
		return err
	}

	for _, file := range files {
		id := filepath.Base(file)
		if applied[id] {
			continue
		}

		content, err := fs.ReadFile(m.fs, file)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", file, err)
		}

		sqlText := stripLineComments(string(content))
		if strings.TrimSpace(sqlText) == "" {
			if err := m.recordApplied(ctx, id); err != nil {
				return err
			}
			continue
		}

		if err := m.applyOne(ctx, id, sqlText); err != nil {
			return err
		}
	}

	return nil
}

func (m *Migrator) ensureTable(ctx context.Context) error {
	_, err := m.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		id TEXT PRIMARY KEY,
		applied_at TIMESTAMPTZ NOT NULL
	)`)
	if err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}
	return nil
}

func (m *Migrator) appliedMigrations(ctx context.Context) (map[string]bool, error) {
	rows, err := m.db.QueryContext(ctx, `SELECT id FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("list schema_migrations: %w", err)
	}
	defer rows.Close()

	applied := make(map[string]bool)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan schema_migrations: %w", err)
		}
		applied[id] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate schema_migrations: %w", err)
	}
	return applied, nil
}

func (m *Migrator) applyOne(ctx context.Context, id, sqlText string) error {
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration %s: %w", id, err)
	}

	if _, err := tx.ExecContext(ctx, sqlText); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("exec migration %s: %w", id, err)
	}

	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (id, applied_at) VALUES ($1, $2)`, id, time.Now().UTC()); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("record migration %s: %w", id, err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration %s: %w", id, err)
	}
	return nil
}

func (m *Migrator) recordApplied(ctx context.Context, id string) error {
	_, err := m.db.ExecContext(ctx, `INSERT INTO schema_migrations (id, applied_at) VALUES ($1, $2)`, id, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("record migration %s: %w", id, err)
	}
	return nil
}

func stripLineComments(sqlText string) string {
	lines := strings.Split(sqlText, "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "--") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}
