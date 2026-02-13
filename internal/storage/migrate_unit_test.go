package storage

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/DATA-DOG/go-sqlmock"
)

func newSQLMockDB(t *testing.T) (sqlmock.Sqlmock, func()) {
	t.Helper()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	cleanup := func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("sqlmock expectations: %v", err)
		}
		_ = db.Close()
	}
	return mock, cleanup
}

func newMigratorWithMock(t *testing.T, migrationFS fs.FS) (*Migrator, sqlmock.Sqlmock, func()) {
	t.Helper()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	cleanup := func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("sqlmock expectations: %v", err)
		}
		_ = db.Close()
	}
	return NewMigrator(db, migrationFS), mock, cleanup
}

func TestMigratorUpRequiresDB(t *testing.T) {
	m := NewMigrator(nil, fstest.MapFS{})
	err := m.Up(context.Background())
	if err == nil || !strings.Contains(err.Error(), "db is required") {
		t.Fatalf("expected db required error, got %v", err)
	}
}

func TestMigratorUpNoMigrations(t *testing.T) {
	m, mock, cleanup := newMigratorWithMock(t, fstest.MapFS{})
	defer cleanup()

	mock.ExpectExec(`CREATE TABLE IF NOT EXISTS schema_migrations`).WillReturnResult(sqlmock.NewResult(0, 0))

	if err := m.Up(context.Background()); err != nil {
		t.Fatalf("Up() no migrations: %v", err)
	}
}

func TestMigratorUpAppliesAndRecordsCommentOnly(t *testing.T) {
	migrationFS := fstest.MapFS{
		"migrations/0002_apply.sql":   &fstest.MapFile{Data: []byte("CREATE TABLE demo_table (id INT);\n")},
		"migrations/0001_already.sql": &fstest.MapFile{Data: []byte("CREATE TABLE already_table (id INT);\n")},
		"migrations/0003_comment.sql": &fstest.MapFile{Data: []byte("-- comment only\n  -- still comment\n")},
	}
	m, mock, cleanup := newMigratorWithMock(t, migrationFS)
	defer cleanup()

	mock.ExpectExec(`CREATE TABLE IF NOT EXISTS schema_migrations`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT id FROM schema_migrations`).WillReturnRows(
		sqlmock.NewRows([]string{"id"}).AddRow("0001_already.sql"),
	)

	mock.ExpectBegin()
	mock.ExpectExec(`CREATE TABLE demo_table`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`INSERT INTO schema_migrations`).WithArgs("0002_apply.sql", sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	mock.ExpectExec(`INSERT INTO schema_migrations`).WithArgs("0003_comment.sql", sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))

	if err := m.Up(context.Background()); err != nil {
		t.Fatalf("Up() apply + comment-only record: %v", err)
	}
}

func TestMigratorUpApplyExecErrorRollsBack(t *testing.T) {
	migrationFS := fstest.MapFS{
		"migrations/0001_fail.sql": &fstest.MapFile{Data: []byte("CREATE TABLE broken_table (id INT);")},
	}
	m, mock, cleanup := newMigratorWithMock(t, migrationFS)
	defer cleanup()

	mock.ExpectExec(`CREATE TABLE IF NOT EXISTS schema_migrations`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT id FROM schema_migrations`).WillReturnRows(sqlmock.NewRows([]string{"id"}))
	mock.ExpectBegin()
	mock.ExpectExec(`CREATE TABLE broken_table`).WillReturnError(errors.New("exec boom"))
	mock.ExpectRollback()

	err := m.Up(context.Background())
	if err == nil || !strings.Contains(err.Error(), "exec migration 0001_fail.sql") {
		t.Fatalf("expected exec migration error, got %v", err)
	}
}

func TestMigratorEnsureTableAndAppliedErrors(t *testing.T) {
	t.Run("ensureTable exec error", func(t *testing.T) {
		m, mock, cleanup := newMigratorWithMock(t, fstest.MapFS{})
		defer cleanup()

		mock.ExpectExec(`CREATE TABLE IF NOT EXISTS schema_migrations`).WillReturnError(errors.New("create failed"))
		err := m.ensureTable(context.Background())
		if err == nil || !strings.Contains(err.Error(), "create schema_migrations") {
			t.Fatalf("expected ensureTable error, got %v", err)
		}
	})

	t.Run("appliedMigrations query error", func(t *testing.T) {
		m, mock, cleanup := newMigratorWithMock(t, fstest.MapFS{})
		defer cleanup()

		mock.ExpectQuery(`SELECT id FROM schema_migrations`).WillReturnError(errors.New("query failed"))
		_, err := m.appliedMigrations(context.Background())
		if err == nil || !strings.Contains(err.Error(), "list schema_migrations") {
			t.Fatalf("expected appliedMigrations query error, got %v", err)
		}
	})

	t.Run("appliedMigrations scan error", func(t *testing.T) {
		m, mock, cleanup := newMigratorWithMock(t, fstest.MapFS{})
		defer cleanup()

		rows := sqlmock.NewRows([]string{"id", "extra"}).AddRow("0001", "x")
		mock.ExpectQuery(`SELECT id FROM schema_migrations`).WillReturnRows(rows)
		_, err := m.appliedMigrations(context.Background())
		if err == nil || !strings.Contains(err.Error(), "scan schema_migrations") {
			t.Fatalf("expected appliedMigrations scan error, got %v", err)
		}
	})
}

func TestMigratorApplyOneAndRecordAppliedErrors(t *testing.T) {
	t.Run("applyOne record insert error rolls back", func(t *testing.T) {
		m, mock, cleanup := newMigratorWithMock(t, fstest.MapFS{})
		defer cleanup()

		mock.ExpectBegin()
		mock.ExpectExec(`CREATE TABLE t`).WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectExec(`INSERT INTO schema_migrations`).WithArgs("0001.sql", sqlmock.AnyArg()).WillReturnError(errors.New("insert failed"))
		mock.ExpectRollback()

		err := m.applyOne(context.Background(), "0001.sql", "CREATE TABLE t (id INT)")
		if err == nil || !strings.Contains(err.Error(), "record migration 0001.sql") {
			t.Fatalf("expected applyOne record error, got %v", err)
		}
	})

	t.Run("applyOne commit error", func(t *testing.T) {
		m, mock, cleanup := newMigratorWithMock(t, fstest.MapFS{})
		defer cleanup()

		mock.ExpectBegin()
		mock.ExpectExec(`CREATE TABLE t2`).WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectExec(`INSERT INTO schema_migrations`).WithArgs("0002.sql", sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit().WillReturnError(errors.New("commit failed"))

		err := m.applyOne(context.Background(), "0002.sql", "CREATE TABLE t2 (id INT)")
		if err == nil || !strings.Contains(err.Error(), "commit migration 0002.sql") {
			t.Fatalf("expected applyOne commit error, got %v", err)
		}
	})

	t.Run("recordApplied exec error", func(t *testing.T) {
		m, mock, cleanup := newMigratorWithMock(t, fstest.MapFS{})
		defer cleanup()

		mock.ExpectExec(`INSERT INTO schema_migrations`).WithArgs("0003.sql", sqlmock.AnyArg()).WillReturnError(errors.New("insert failed"))
		err := m.recordApplied(context.Background(), "0003.sql")
		if err == nil || !strings.Contains(err.Error(), "record migration 0003.sql") {
			t.Fatalf("expected recordApplied error, got %v", err)
		}
	})
}

func TestStripLineComments(t *testing.T) {
	input := strings.Join([]string{
		"-- top comment",
		"CREATE TABLE x (id INT);",
		"  -- indented comment",
		"INSERT INTO x VALUES (1);",
	}, "\n")

	out := stripLineComments(input)
	if strings.Contains(out, "--") {
		t.Fatalf("expected line comments removed, got %q", out)
	}
	if !strings.Contains(out, "CREATE TABLE x") || !strings.Contains(out, "INSERT INTO x") {
		t.Fatalf("expected SQL statements preserved, got %q", out)
	}
}

func TestEmbeddedMigrationsBasenameSanity(t *testing.T) {
	files, err := fs.Glob(migrationsFS, "migrations/*.sql")
	if err != nil {
		t.Fatalf("glob embedded migrations: %v", err)
	}
	for _, file := range files {
		if base := filepath.Base(file); base == "" || base == "." || base == "/" {
			t.Fatalf("invalid migration basename for %q", file)
		}
	}
}
