package storage

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"github.com/Avicted/dialtone/internal/channel"
	"github.com/Avicted/dialtone/internal/device"
	"github.com/Avicted/dialtone/internal/message"
	"github.com/Avicted/dialtone/internal/serverinvite"
	"github.com/Avicted/dialtone/internal/user"
)

func newRepoSQLMock(t *testing.T) (*sql.DB, sqlmock.Sqlmock, func()) {
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
	return db, mock, cleanup
}

func TestUserRepoSQL(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()

	t.Run("Create validation", func(t *testing.T) {
		repo := &userRepo{}
		err := repo.Create(ctx, user.User{})
		if err == nil || !strings.Contains(err.Error(), "required") {
			t.Fatalf("expected validation error, got %v", err)
		}
	})

	t.Run("Create success", func(t *testing.T) {
		db, mock, cleanup := newRepoSQLMock(t)
		defer cleanup()

		repo := &userRepo{db: db}
		u := user.User{ID: "u1", UsernameHash: "h1", PasswordHash: "pw", CreatedAt: now}
		mock.ExpectExec(`INSERT INTO users`).
			WithArgs(u.ID, u.UsernameHash, u.PasswordHash, false, false, u.CreatedAt).
			WillReturnResult(sqlmock.NewResult(1, 1))

		if err := repo.Create(ctx, u); err != nil {
			t.Fatalf("Create() error: %v", err)
		}
	})

	t.Run("GetByID success", func(t *testing.T) {
		db, mock, cleanup := newRepoSQLMock(t)
		defer cleanup()

		repo := &userRepo{db: db}
		rows := sqlmock.NewRows([]string{"id", "username_hash", "password_hash", "is_admin", "is_trusted", "created_at"}).
			AddRow("u1", "h1", "pw", true, false, now)
		mock.ExpectQuery(`FROM users WHERE id = \$1`).WithArgs(user.ID("u1")).WillReturnRows(rows)

		u, err := repo.GetByID(ctx, "u1")
		if err != nil {
			t.Fatalf("GetByID() error: %v", err)
		}
		if u.UsernameHash != "h1" || u.PasswordHash != "pw" {
			t.Fatalf("unexpected user: %+v", u)
		}
	})

	t.Run("GetByID not found", func(t *testing.T) {
		db, mock, cleanup := newRepoSQLMock(t)
		defer cleanup()

		repo := &userRepo{db: db}
		rows := sqlmock.NewRows([]string{"id", "username_hash", "password_hash", "is_admin", "is_trusted", "created_at"})
		mock.ExpectQuery(`FROM users WHERE id = \$1`).WithArgs(user.ID("missing")).WillReturnRows(rows)

		_, err := repo.GetByID(ctx, "missing")
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("GetByUsernameHash success", func(t *testing.T) {
		db, mock, cleanup := newRepoSQLMock(t)
		defer cleanup()

		repo := &userRepo{db: db}
		rows := sqlmock.NewRows([]string{"id", "username_hash", "password_hash", "is_admin", "is_trusted", "created_at"}).
			AddRow("u1", "h1", "pw", false, true, now)
		mock.ExpectQuery(`FROM users WHERE username_hash = \$1`).WithArgs("h1").WillReturnRows(rows)

		u, err := repo.GetByUsernameHash(ctx, "h1")
		if err != nil {
			t.Fatalf("GetByUsernameHash() error: %v", err)
		}
		if u.ID != "u1" {
			t.Fatalf("unexpected user: %+v", u)
		}
	})

	t.Run("GetByUsernameHash not found", func(t *testing.T) {
		db, mock, cleanup := newRepoSQLMock(t)
		defer cleanup()

		repo := &userRepo{db: db}
		rows := sqlmock.NewRows([]string{"id", "username_hash", "password_hash", "is_admin", "is_trusted", "created_at"})
		mock.ExpectQuery(`FROM users WHERE username_hash = \$1`).WithArgs("missing").WillReturnRows(rows)

		_, err := repo.GetByUsernameHash(ctx, "missing")
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("Count success", func(t *testing.T) {
		db, mock, cleanup := newRepoSQLMock(t)
		defer cleanup()

		repo := &userRepo{db: db}
		mock.ExpectQuery(`SELECT COUNT\(\*\) FROM users`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(3))

		count, err := repo.Count(ctx)
		if err != nil {
			t.Fatalf("Count() error: %v", err)
		}
		if count != 3 {
			t.Fatalf("count=%d, want 3", count)
		}
	})

	t.Run("UpsertProfile validation", func(t *testing.T) {
		repo := &userRepo{}
		err := repo.UpsertProfile(ctx, user.Profile{})
		if err == nil || !strings.Contains(err.Error(), "required") {
			t.Fatalf("expected validation error, got %v", err)
		}
	})

	t.Run("UpsertProfile success", func(t *testing.T) {
		db, mock, cleanup := newRepoSQLMock(t)
		defer cleanup()

		repo := &userRepo{db: db}
		profile := user.Profile{UserID: "u1", NameEnc: "name", UpdatedAt: now}
		mock.ExpectExec(`INSERT INTO user_profiles`).WithArgs(profile.UserID, profile.NameEnc, profile.UpdatedAt).
			WillReturnResult(sqlmock.NewResult(1, 1))

		if err := repo.UpsertProfile(ctx, profile); err != nil {
			t.Fatalf("UpsertProfile() error: %v", err)
		}
	})

	t.Run("ListProfiles success", func(t *testing.T) {
		db, mock, cleanup := newRepoSQLMock(t)
		defer cleanup()

		repo := &userRepo{db: db}
		rows := sqlmock.NewRows([]string{"user_id", "name_enc", "updated_at"}).AddRow("u1", "name", now)
		mock.ExpectQuery(`SELECT user_id, name_enc, updated_at FROM user_profiles`).WillReturnRows(rows)

		profiles, err := repo.ListProfiles(ctx)
		if err != nil {
			t.Fatalf("ListProfiles() error: %v", err)
		}
		if len(profiles) != 1 || profiles[0].UserID != "u1" {
			t.Fatalf("unexpected profiles: %+v", profiles)
		}
	})

	t.Run("UpsertDirectoryKeyEnvelope validation", func(t *testing.T) {
		repo := &userRepo{}
		err := repo.UpsertDirectoryKeyEnvelope(ctx, user.DirectoryKeyEnvelope{})
		if err == nil || !strings.Contains(err.Error(), "required") {
			t.Fatalf("expected validation error, got %v", err)
		}
	})

	t.Run("UpsertDirectoryKeyEnvelope success", func(t *testing.T) {
		db, mock, cleanup := newRepoSQLMock(t)
		defer cleanup()

		repo := &userRepo{db: db}
		env := user.DirectoryKeyEnvelope{DeviceID: "d1", SenderDeviceID: "d2", SenderPublicKey: "pk", Envelope: "env", CreatedAt: now}
		mock.ExpectExec(`INSERT INTO directory_key_envelopes`).
			WithArgs(env.DeviceID, env.SenderDeviceID, env.SenderPublicKey, env.Envelope, env.CreatedAt).
			WillReturnResult(sqlmock.NewResult(1, 1))

		if err := repo.UpsertDirectoryKeyEnvelope(ctx, env); err != nil {
			t.Fatalf("UpsertDirectoryKeyEnvelope() error: %v", err)
		}
	})

	t.Run("GetDirectoryKeyEnvelope success", func(t *testing.T) {
		db, mock, cleanup := newRepoSQLMock(t)
		defer cleanup()

		repo := &userRepo{db: db}
		rows := sqlmock.NewRows([]string{"device_id", "sender_device_id", "sender_public_key", "envelope", "created_at"}).
			AddRow("d1", "d2", "pk", "env", now)
		mock.ExpectQuery(`FROM directory_key_envelopes WHERE device_id = \$1`).WithArgs("d1").WillReturnRows(rows)

		env, err := repo.GetDirectoryKeyEnvelope(ctx, "d1")
		if err != nil {
			t.Fatalf("GetDirectoryKeyEnvelope() error: %v", err)
		}
		if env.Envelope != "env" {
			t.Fatalf("unexpected envelope: %+v", env)
		}
	})

	t.Run("GetDirectoryKeyEnvelope not found", func(t *testing.T) {
		db, mock, cleanup := newRepoSQLMock(t)
		defer cleanup()

		repo := &userRepo{db: db}
		rows := sqlmock.NewRows([]string{"device_id", "sender_device_id", "sender_public_key", "envelope", "created_at"})
		mock.ExpectQuery(`FROM directory_key_envelopes WHERE device_id = \$1`).WithArgs("missing").WillReturnRows(rows)

		_, err := repo.GetDirectoryKeyEnvelope(ctx, "missing")
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("expected ErrNotFound, got %v", err)
		}
	})
}

func TestDeviceRepoSQL(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()

	t.Run("Create validation", func(t *testing.T) {
		repo := &deviceRepo{}
		err := repo.Create(ctx, device.Device{})
		if err == nil || !strings.Contains(err.Error(), "required") {
			t.Fatalf("expected validation error, got %v", err)
		}
	})

	t.Run("Create success", func(t *testing.T) {
		db, mock, cleanup := newRepoSQLMock(t)
		defer cleanup()

		repo := &deviceRepo{db: db}
		d := device.Device{ID: "d1", UserID: "u1", PublicKey: "pk", CreatedAt: now}
		mock.ExpectExec(`INSERT INTO devices`).WithArgs(d.ID, d.UserID, d.PublicKey, d.CreatedAt, nil).
			WillReturnResult(sqlmock.NewResult(1, 1))

		if err := repo.Create(ctx, d); err != nil {
			t.Fatalf("Create() error: %v", err)
		}
	})

	t.Run("GetByID success", func(t *testing.T) {
		db, mock, cleanup := newRepoSQLMock(t)
		defer cleanup()

		repo := &deviceRepo{db: db}
		lastSeen := now.Add(-time.Minute)
		rows := sqlmock.NewRows([]string{"id", "user_id", "public_key", "created_at", "last_seen_at"}).
			AddRow("d1", "u1", "pk", now, lastSeen)
		mock.ExpectQuery(`FROM devices WHERE id = \$1`).WithArgs(device.ID("d1")).WillReturnRows(rows)

		d, err := repo.GetByID(ctx, "d1")
		if err != nil {
			t.Fatalf("GetByID() error: %v", err)
		}
		if d.PublicKey != "pk" || d.LastSeenAt == nil {
			t.Fatalf("unexpected device: %+v", d)
		}
	})

	t.Run("GetByID not found", func(t *testing.T) {
		db, mock, cleanup := newRepoSQLMock(t)
		defer cleanup()

		repo := &deviceRepo{db: db}
		rows := sqlmock.NewRows([]string{"id", "user_id", "public_key", "created_at", "last_seen_at"})
		mock.ExpectQuery(`FROM devices WHERE id = \$1`).WithArgs(device.ID("missing")).WillReturnRows(rows)

		_, err := repo.GetByID(ctx, "missing")
		if !errors.Is(err, device.ErrNotFound) {
			t.Fatalf("expected device.ErrNotFound, got %v", err)
		}
	})

	t.Run("GetByUserAndPublicKey success", func(t *testing.T) {
		db, mock, cleanup := newRepoSQLMock(t)
		defer cleanup()

		repo := &deviceRepo{db: db}
		rows := sqlmock.NewRows([]string{"id", "user_id", "public_key", "created_at", "last_seen_at"}).
			AddRow("d1", "u1", "pk", now, nil)
		mock.ExpectQuery(`FROM devices WHERE user_id = \$1 AND public_key = \$2`).WithArgs(user.ID("u1"), "pk").WillReturnRows(rows)

		d, err := repo.GetByUserAndPublicKey(ctx, "u1", "pk")
		if err != nil {
			t.Fatalf("GetByUserAndPublicKey() error: %v", err)
		}
		if d.ID != "d1" {
			t.Fatalf("unexpected device: %+v", d)
		}
	})

	t.Run("GetByUserAndPublicKey not found", func(t *testing.T) {
		db, mock, cleanup := newRepoSQLMock(t)
		defer cleanup()

		repo := &deviceRepo{db: db}
		rows := sqlmock.NewRows([]string{"id", "user_id", "public_key", "created_at", "last_seen_at"})
		mock.ExpectQuery(`FROM devices WHERE user_id = \$1 AND public_key = \$2`).WithArgs(user.ID("u1"), "missing").WillReturnRows(rows)

		_, err := repo.GetByUserAndPublicKey(ctx, "u1", "missing")
		if !errors.Is(err, device.ErrNotFound) {
			t.Fatalf("expected device.ErrNotFound, got %v", err)
		}
	})

	t.Run("ListByUser filters empty public key", func(t *testing.T) {
		db, mock, cleanup := newRepoSQLMock(t)
		defer cleanup()

		repo := &deviceRepo{db: db}
		rows := sqlmock.NewRows([]string{"id", "user_id", "public_key", "created_at", "last_seen_at"}).
			AddRow("d1", "u1", "pk", now, nil).
			AddRow("d2", "u1", nil, now, nil)
		mock.ExpectQuery(`FROM devices WHERE user_id = \$1 ORDER BY created_at`).WithArgs(user.ID("u1")).WillReturnRows(rows)

		devices, err := repo.ListByUser(ctx, "u1")
		if err != nil {
			t.Fatalf("ListByUser() error: %v", err)
		}
		if len(devices) != 1 || devices[0].ID != "d1" {
			t.Fatalf("unexpected devices: %+v", devices)
		}
	})

	t.Run("ListAll success", func(t *testing.T) {
		db, mock, cleanup := newRepoSQLMock(t)
		defer cleanup()

		repo := &deviceRepo{db: db}
		rows := sqlmock.NewRows([]string{"id", "user_id", "public_key", "created_at", "last_seen_at"}).
			AddRow("d1", "u1", "pk", now, nil)
		mock.ExpectQuery(`FROM devices ORDER BY created_at`).WillReturnRows(rows)

		devices, err := repo.ListAll(ctx)
		if err != nil {
			t.Fatalf("ListAll() error: %v", err)
		}
		if len(devices) != 1 {
			t.Fatalf("unexpected devices len=%d", len(devices))
		}
	})

	t.Run("UpdateLastSeen validation", func(t *testing.T) {
		repo := &deviceRepo{}
		err := repo.UpdateLastSeen(ctx, "", time.Time{})
		if err == nil || !strings.Contains(err.Error(), "required") {
			t.Fatalf("expected validation error, got %v", err)
		}
	})

	t.Run("UpdateLastSeen not found", func(t *testing.T) {
		db, mock, cleanup := newRepoSQLMock(t)
		defer cleanup()

		repo := &deviceRepo{db: db}
		mock.ExpectExec(`UPDATE devices SET last_seen_at = \$2 WHERE id = \$1`).WithArgs(device.ID("d1"), now).
			WillReturnResult(sqlmock.NewResult(0, 0))

		err := repo.UpdateLastSeen(ctx, "d1", now)
		if !errors.Is(err, device.ErrNotFound) {
			t.Fatalf("expected device.ErrNotFound, got %v", err)
		}
	})

	t.Run("UpdateLastSeen success", func(t *testing.T) {
		db, mock, cleanup := newRepoSQLMock(t)
		defer cleanup()

		repo := &deviceRepo{db: db}
		mock.ExpectExec(`UPDATE devices SET last_seen_at = \$2 WHERE id = \$1`).WithArgs(device.ID("d1"), now).
			WillReturnResult(sqlmock.NewResult(0, 1))

		if err := repo.UpdateLastSeen(ctx, "d1", now); err != nil {
			t.Fatalf("UpdateLastSeen() error: %v", err)
		}
	})
}

func TestBroadcastRepoSQL(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()

	t.Run("Save validation", func(t *testing.T) {
		repo := &broadcastRepo{}
		err := repo.Save(ctx, message.BroadcastMessage{})
		if err == nil || !strings.Contains(err.Error(), "required") {
			t.Fatalf("expected validation error, got %v", err)
		}
	})

	t.Run("Save success", func(t *testing.T) {
		db, mock, cleanup := newRepoSQLMock(t)
		defer cleanup()

		repo := &broadcastRepo{db: db}
		msg := message.BroadcastMessage{
			ID:              "b1",
			SenderID:        "u1",
			SenderPublicKey: "pk",
			SenderNameEnc:   "name",
			Body:            "body",
			Envelopes:       map[string]string{"d1": "env"},
			SentAt:          now,
		}
		mock.ExpectExec(`INSERT INTO broadcast_messages`).
			WithArgs(msg.ID, msg.SenderID, msg.SenderPublicKey, msg.SenderNameEnc, msg.Body, sqlmock.AnyArg(), msg.SentAt).
			WillReturnResult(sqlmock.NewResult(1, 1))

		if err := repo.Save(ctx, msg); err != nil {
			t.Fatalf("Save() error: %v", err)
		}
	})

	t.Run("ListRecent validation", func(t *testing.T) {
		repo := &broadcastRepo{}
		msgs, err := repo.ListRecent(ctx, 0)
		if err == nil || msgs != nil {
			t.Fatalf("expected validation error with nil messages, got msgs=%v err=%v", msgs, err)
		}
	})

	t.Run("ListRecent success and chronological order", func(t *testing.T) {
		db, mock, cleanup := newRepoSQLMock(t)
		defer cleanup()

		repo := &broadcastRepo{db: db}
		newer := now
		older := now.Add(-time.Minute)
		rows := sqlmock.NewRows([]string{"id", "sender_id", "sender_public_key", "sender_name_enc", "body", "key_envelopes", "sent_at"}).
			AddRow("new", "u1", "pk", "n1", "b1", `{"d1":"e1"}`, newer).
			AddRow("old", "u1", "pk", "n1", "b0", `{"d2":"e2"}`, older)
		mock.ExpectQuery(`FROM broadcast_messages ORDER BY sent_at DESC LIMIT \$1`).WithArgs(2).WillReturnRows(rows)

		msgs, err := repo.ListRecent(ctx, 2)
		if err != nil {
			t.Fatalf("ListRecent() error: %v", err)
		}
		if len(msgs) != 2 || msgs[0].ID != "old" || msgs[1].ID != "new" {
			t.Fatalf("unexpected order/messages: %+v", msgs)
		}
		if msgs[0].Envelopes["d2"] != "e2" {
			t.Fatalf("expected decoded envelopes, got %+v", msgs[0].Envelopes)
		}
	})
}

func TestChannelRepoSQL(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()

	t.Run("CreateChannel validation", func(t *testing.T) {
		repo := &channelRepo{}
		err := repo.CreateChannel(ctx, channel.Channel{})
		if err == nil || !strings.Contains(err.Error(), "required") {
			t.Fatalf("expected validation error, got %v", err)
		}
	})

	t.Run("CreateChannel success", func(t *testing.T) {
		db, mock, cleanup := newRepoSQLMock(t)
		defer cleanup()

		repo := &channelRepo{db: db}
		ch := channel.Channel{ID: "c1", NameEnc: "name", CreatedBy: "u1", CreatedAt: now}
		mock.ExpectExec(`INSERT INTO channels`).WithArgs(ch.ID, ch.NameEnc, ch.CreatedBy, ch.CreatedAt).
			WillReturnResult(sqlmock.NewResult(1, 1))

		if err := repo.CreateChannel(ctx, ch); err != nil {
			t.Fatalf("CreateChannel() error: %v", err)
		}
	})

	t.Run("GetChannel not found", func(t *testing.T) {
		db, mock, cleanup := newRepoSQLMock(t)
		defer cleanup()

		repo := &channelRepo{db: db}
		rows := sqlmock.NewRows([]string{"id", "name_enc", "created_by", "created_at"})
		mock.ExpectQuery(`FROM channels WHERE id = \$1`).WithArgs(channel.ID("missing")).WillReturnRows(rows)

		_, err := repo.GetChannel(ctx, "missing")
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("GetChannel success", func(t *testing.T) {
		db, mock, cleanup := newRepoSQLMock(t)
		defer cleanup()

		repo := &channelRepo{db: db}
		rows := sqlmock.NewRows([]string{"id", "name_enc", "created_by", "created_at"}).AddRow("c1", "name", "u1", now)
		mock.ExpectQuery(`FROM channels WHERE id = \$1`).WithArgs(channel.ID("c1")).WillReturnRows(rows)

		ch, err := repo.GetChannel(ctx, "c1")
		if err != nil {
			t.Fatalf("GetChannel() error: %v", err)
		}
		if ch.ID != "c1" {
			t.Fatalf("unexpected channel: %+v", ch)
		}
	})

	t.Run("ListChannels success", func(t *testing.T) {
		db, mock, cleanup := newRepoSQLMock(t)
		defer cleanup()

		repo := &channelRepo{db: db}
		rows := sqlmock.NewRows([]string{"id", "name_enc", "created_by", "created_at"}).AddRow("c1", "n1", "u1", now)
		mock.ExpectQuery(`FROM channels ORDER BY created_at DESC`).WillReturnRows(rows)

		channels, err := repo.ListChannels(ctx)
		if err != nil {
			t.Fatalf("ListChannels() error: %v", err)
		}
		if len(channels) != 1 {
			t.Fatalf("unexpected channels len=%d", len(channels))
		}
	})

	t.Run("DeleteChannel validation", func(t *testing.T) {
		repo := &channelRepo{}
		err := repo.DeleteChannel(ctx, "")
		if err == nil || !strings.Contains(err.Error(), "required") {
			t.Fatalf("expected validation error, got %v", err)
		}
	})

	t.Run("DeleteChannel not found", func(t *testing.T) {
		db, mock, cleanup := newRepoSQLMock(t)
		defer cleanup()

		repo := &channelRepo{db: db}
		mock.ExpectExec(`DELETE FROM channels WHERE id = \$1`).WithArgs(channel.ID("c1")).
			WillReturnResult(sqlmock.NewResult(0, 0))

		err := repo.DeleteChannel(ctx, "c1")
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("DeleteChannel success", func(t *testing.T) {
		db, mock, cleanup := newRepoSQLMock(t)
		defer cleanup()

		repo := &channelRepo{db: db}
		mock.ExpectExec(`DELETE FROM channels WHERE id = \$1`).WithArgs(channel.ID("c1")).
			WillReturnResult(sqlmock.NewResult(0, 1))

		if err := repo.DeleteChannel(ctx, "c1"); err != nil {
			t.Fatalf("DeleteChannel() error: %v", err)
		}
	})

	t.Run("UpdateChannelName validation", func(t *testing.T) {
		repo := &channelRepo{}
		err := repo.UpdateChannelName(ctx, "", "")
		if err == nil || !strings.Contains(err.Error(), "required") {
			t.Fatalf("expected validation error, got %v", err)
		}
	})

	t.Run("UpdateChannelName not found", func(t *testing.T) {
		db, mock, cleanup := newRepoSQLMock(t)
		defer cleanup()

		repo := &channelRepo{db: db}
		mock.ExpectExec(`UPDATE channels SET name_enc = \$2 WHERE id = \$1`).WithArgs(channel.ID("c1"), "name").
			WillReturnResult(sqlmock.NewResult(0, 0))

		err := repo.UpdateChannelName(ctx, "c1", "name")
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("UpdateChannelName success", func(t *testing.T) {
		db, mock, cleanup := newRepoSQLMock(t)
		defer cleanup()

		repo := &channelRepo{db: db}
		mock.ExpectExec(`UPDATE channels SET name_enc = \$2 WHERE id = \$1`).WithArgs(channel.ID("c1"), "name").
			WillReturnResult(sqlmock.NewResult(0, 1))

		if err := repo.UpdateChannelName(ctx, "c1", "name"); err != nil {
			t.Fatalf("UpdateChannelName() error: %v", err)
		}
	})

	t.Run("SaveMessage validation", func(t *testing.T) {
		repo := &channelRepo{}
		err := repo.SaveMessage(ctx, channel.Message{})
		if err == nil || !strings.Contains(err.Error(), "required") {
			t.Fatalf("expected validation error, got %v", err)
		}
	})

	t.Run("SaveMessage success", func(t *testing.T) {
		db, mock, cleanup := newRepoSQLMock(t)
		defer cleanup()

		repo := &channelRepo{db: db}
		msg := channel.Message{ID: "m1", ChannelID: "c1", SenderID: "u1", SenderNameEnc: "name", Body: "body", SentAt: now}
		mock.ExpectExec(`INSERT INTO channel_messages`).WithArgs(msg.ID, msg.ChannelID, msg.SenderID, msg.SenderNameEnc, msg.Body, msg.SentAt).
			WillReturnResult(sqlmock.NewResult(1, 1))

		if err := repo.SaveMessage(ctx, msg); err != nil {
			t.Fatalf("SaveMessage() error: %v", err)
		}
	})

	t.Run("ListRecentMessages validation", func(t *testing.T) {
		repo := &channelRepo{}
		msgs, err := repo.ListRecentMessages(ctx, "", 0)
		if err == nil || msgs != nil {
			t.Fatalf("expected validation error with nil messages, got msgs=%v err=%v", msgs, err)
		}
	})

	t.Run("ListRecentMessages success and chronological order", func(t *testing.T) {
		db, mock, cleanup := newRepoSQLMock(t)
		defer cleanup()

		repo := &channelRepo{db: db}
		newer := now
		older := now.Add(-time.Minute)
		rows := sqlmock.NewRows([]string{"id", "channel_id", "sender_id", "sender_name_enc", "body", "sent_at"}).
			AddRow("new", "c1", "u1", "n1", "b1", newer).
			AddRow("old", "c1", "u1", "n1", "b0", older)
		mock.ExpectQuery(`FROM channel_messages WHERE channel_id = \$1 ORDER BY sent_at DESC LIMIT \$2`).WithArgs(channel.ID("c1"), 2).
			WillReturnRows(rows)

		msgs, err := repo.ListRecentMessages(ctx, "c1", 2)
		if err != nil {
			t.Fatalf("ListRecentMessages() error: %v", err)
		}
		if len(msgs) != 2 || msgs[0].ID != "old" || msgs[1].ID != "new" {
			t.Fatalf("unexpected order/messages: %+v", msgs)
		}
	})

	t.Run("UpsertKeyEnvelope validation", func(t *testing.T) {
		repo := &channelRepo{}
		err := repo.UpsertKeyEnvelope(ctx, channel.KeyEnvelope{})
		if err == nil || !strings.Contains(err.Error(), "required") {
			t.Fatalf("expected validation error, got %v", err)
		}
	})

	t.Run("UpsertKeyEnvelope success", func(t *testing.T) {
		db, mock, cleanup := newRepoSQLMock(t)
		defer cleanup()

		repo := &channelRepo{db: db}
		env := channel.KeyEnvelope{ChannelID: "c1", DeviceID: "d1", SenderDeviceID: "d2", SenderPublicKey: "pk", Envelope: "env", CreatedAt: now}
		mock.ExpectExec(`INSERT INTO channel_key_envelopes`).
			WithArgs(env.ChannelID, env.DeviceID, env.SenderDeviceID, env.SenderPublicKey, env.Envelope, env.CreatedAt).
			WillReturnResult(sqlmock.NewResult(1, 1))

		if err := repo.UpsertKeyEnvelope(ctx, env); err != nil {
			t.Fatalf("UpsertKeyEnvelope() error: %v", err)
		}
	})

	t.Run("GetKeyEnvelope validation", func(t *testing.T) {
		repo := &channelRepo{}
		_, err := repo.GetKeyEnvelope(ctx, "", "")
		if err == nil || !strings.Contains(err.Error(), "required") {
			t.Fatalf("expected validation error, got %v", err)
		}
	})

	t.Run("GetKeyEnvelope not found", func(t *testing.T) {
		db, mock, cleanup := newRepoSQLMock(t)
		defer cleanup()

		repo := &channelRepo{db: db}
		rows := sqlmock.NewRows([]string{"channel_id", "device_id", "sender_device_id", "sender_public_key", "envelope", "created_at"})
		mock.ExpectQuery(`FROM channel_key_envelopes WHERE channel_id = \$1 AND device_id = \$2`).WithArgs(channel.ID("c1"), device.ID("d1")).WillReturnRows(rows)

		_, err := repo.GetKeyEnvelope(ctx, "c1", "d1")
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("GetKeyEnvelope success", func(t *testing.T) {
		db, mock, cleanup := newRepoSQLMock(t)
		defer cleanup()

		repo := &channelRepo{db: db}
		rows := sqlmock.NewRows([]string{"channel_id", "device_id", "sender_device_id", "sender_public_key", "envelope", "created_at"}).
			AddRow("c1", "d1", "d2", "pk", "env", now)
		mock.ExpectQuery(`FROM channel_key_envelopes WHERE channel_id = \$1 AND device_id = \$2`).WithArgs(channel.ID("c1"), device.ID("d1")).WillReturnRows(rows)

		env, err := repo.GetKeyEnvelope(ctx, "c1", "d1")
		if err != nil {
			t.Fatalf("GetKeyEnvelope() error: %v", err)
		}
		if env.Envelope != "env" {
			t.Fatalf("unexpected envelope: %+v", env)
		}
	})
}

func TestServerInviteRepoSQL(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()

	t.Run("Create validation", func(t *testing.T) {
		repo := &serverInviteRepo{}
		err := repo.Create(ctx, serverinvite.Invite{})
		if err == nil || !strings.Contains(err.Error(), "required") {
			t.Fatalf("expected validation error, got %v", err)
		}
	})

	t.Run("Create success", func(t *testing.T) {
		db, mock, cleanup := newRepoSQLMock(t)
		defer cleanup()

		repo := &serverInviteRepo{db: db}
		invite := serverinvite.Invite{Token: "tok", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
		mock.ExpectExec(`INSERT INTO server_invites`).WithArgs(invite.Token, invite.CreatedAt, invite.ExpiresAt).
			WillReturnResult(sqlmock.NewResult(1, 1))

		if err := repo.Create(ctx, invite); err != nil {
			t.Fatalf("Create() error: %v", err)
		}
	})

	t.Run("Consume invalid input", func(t *testing.T) {
		repo := &serverInviteRepo{}
		_, err := repo.Consume(ctx, "", "", time.Time{})
		if !errors.Is(err, serverinvite.ErrInvalidInput) {
			t.Fatalf("expected ErrInvalidInput, got %v", err)
		}
	})

	t.Run("Consume success", func(t *testing.T) {
		db, mock, cleanup := newRepoSQLMock(t)
		defer cleanup()

		repo := &serverInviteRepo{db: db}
		rows := sqlmock.NewRows([]string{"id", "created_at", "expires_at", "consumed_at", "consumed_by"}).
			AddRow("tok", now.Add(-time.Minute), now.Add(time.Hour), now, nil)
		mock.ExpectQuery(`UPDATE server_invites`).WithArgs("tok", now).WillReturnRows(rows)

		invite, err := repo.Consume(ctx, "tok", "u1", now)
		if err != nil {
			t.Fatalf("Consume() error: %v", err)
		}
		if invite.Token != "tok" || invite.ConsumedAt == nil {
			t.Fatalf("unexpected invite: %+v", invite)
		}
	})

	t.Run("Consume not found after fallback", func(t *testing.T) {
		db, mock, cleanup := newRepoSQLMock(t)
		defer cleanup()

		repo := &serverInviteRepo{db: db}
		emptyUpdate := sqlmock.NewRows([]string{"id", "created_at", "expires_at", "consumed_at", "consumed_by"})
		emptySelect := sqlmock.NewRows([]string{"id", "created_at", "expires_at", "consumed_at", "consumed_by"})
		mock.ExpectQuery(`UPDATE server_invites`).WithArgs("missing", now).WillReturnRows(emptyUpdate)
		mock.ExpectQuery(`FROM server_invites WHERE id = \$1`).WithArgs("missing").WillReturnRows(emptySelect)

		_, err := repo.Consume(ctx, "missing", "u1", now)
		if !errors.Is(err, serverinvite.ErrNotFound) {
			t.Fatalf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("Consume consumed after fallback", func(t *testing.T) {
		db, mock, cleanup := newRepoSQLMock(t)
		defer cleanup()

		repo := &serverInviteRepo{db: db}
		emptyUpdate := sqlmock.NewRows([]string{"id", "created_at", "expires_at", "consumed_at", "consumed_by"})
		consumed := sqlmock.NewRows([]string{"id", "created_at", "expires_at", "consumed_at", "consumed_by"}).
			AddRow("tok", now.Add(-time.Hour), now.Add(time.Hour), now.Add(-time.Minute), "u1")
		mock.ExpectQuery(`UPDATE server_invites`).WithArgs("tok", now).WillReturnRows(emptyUpdate)
		mock.ExpectQuery(`FROM server_invites WHERE id = \$1`).WithArgs("tok").WillReturnRows(consumed)

		_, err := repo.Consume(ctx, "tok", "u1", now)
		if !errors.Is(err, serverinvite.ErrConsumed) {
			t.Fatalf("expected ErrConsumed, got %v", err)
		}
	})

	t.Run("Consume expired after fallback", func(t *testing.T) {
		db, mock, cleanup := newRepoSQLMock(t)
		defer cleanup()

		repo := &serverInviteRepo{db: db}
		emptyUpdate := sqlmock.NewRows([]string{"id", "created_at", "expires_at", "consumed_at", "consumed_by"})
		expired := sqlmock.NewRows([]string{"id", "created_at", "expires_at", "consumed_at", "consumed_by"}).
			AddRow("tok", now.Add(-2*time.Hour), now.Add(-time.Hour), nil, nil)
		mock.ExpectQuery(`UPDATE server_invites`).WithArgs("tok", now).WillReturnRows(emptyUpdate)
		mock.ExpectQuery(`FROM server_invites WHERE id = \$1`).WithArgs("tok").WillReturnRows(expired)

		_, err := repo.Consume(ctx, "tok", "u1", now)
		if !errors.Is(err, serverinvite.ErrExpired) {
			t.Fatalf("expected ErrExpired, got %v", err)
		}
	})
}
