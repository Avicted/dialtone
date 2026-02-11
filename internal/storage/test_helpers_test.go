package storage

import (
	"context"
	"database/sql"
	"testing"
	"time"
)

func waitForPostgres(t *testing.T, conn string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		db, err := sql.Open("pgx", conn)
		if err == nil {
			err = db.PingContext(context.Background())
		}
		if db != nil {
			_ = db.Close()
		}
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("wait for postgres: %v", err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}
