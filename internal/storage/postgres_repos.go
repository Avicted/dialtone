package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Avicted/dialtone/internal/device"
	"github.com/Avicted/dialtone/internal/message"
	"github.com/Avicted/dialtone/internal/user"
)

type userRepo struct {
	db *sql.DB
}

func (r *userRepo) Create(ctx context.Context, u user.User) error {
	if u.ID == "" || u.Username == "" || u.CreatedAt.IsZero() {
		return fmt.Errorf("user id, username, and created_at are required")
	}

	var passwordHash any
	if u.PasswordHash != "" {
		passwordHash = u.PasswordHash
	}

	_, err := r.db.ExecContext(ctx, `INSERT INTO users (id, username, password_hash, created_at)
		VALUES ($1, $2, $3, $4)`, u.ID, u.Username, passwordHash, u.CreatedAt)
	if err != nil {
		return fmt.Errorf("insert user: %w", err)
	}
	return nil
}

func (r *userRepo) GetByID(ctx context.Context, id user.ID) (user.User, error) {
	row := r.db.QueryRowContext(ctx, `SELECT id, username, password_hash, created_at FROM users WHERE id = $1`, id)
	var u user.User
	var passwordHash sql.NullString
	if err := row.Scan(&u.ID, &u.Username, &passwordHash, &u.CreatedAt); err != nil {
		if err == sql.ErrNoRows {
			return user.User{}, ErrNotFound
		}
		return user.User{}, fmt.Errorf("select user by id: %w", err)
	}
	if passwordHash.Valid {
		u.PasswordHash = passwordHash.String
	}
	return u, nil
}

func (r *userRepo) GetByUsername(ctx context.Context, username string) (user.User, error) {
	row := r.db.QueryRowContext(ctx, `SELECT id, username, password_hash, created_at FROM users WHERE username = $1`, username)
	var u user.User
	var passwordHash sql.NullString
	if err := row.Scan(&u.ID, &u.Username, &passwordHash, &u.CreatedAt); err != nil {
		if err == sql.ErrNoRows {
			return user.User{}, ErrNotFound
		}
		return user.User{}, fmt.Errorf("select user by username: %w", err)
	}
	if passwordHash.Valid {
		u.PasswordHash = passwordHash.String
	}
	return u, nil
}

type deviceRepo struct {
	db *sql.DB
}

func (r *deviceRepo) Create(ctx context.Context, d device.Device) error {
	if d.ID == "" || d.UserID == "" || d.PublicKey == "" || d.CreatedAt.IsZero() {
		return fmt.Errorf("device id, user_id, public_key, and created_at are required")
	}

	var lastSeen any
	if d.LastSeenAt != nil {
		lastSeen = *d.LastSeenAt
	}

	_, err := r.db.ExecContext(ctx, `INSERT INTO devices (id, user_id, public_key, created_at, last_seen_at)
		VALUES ($1, $2, $3, $4, $5)`, d.ID, d.UserID, d.PublicKey, d.CreatedAt, lastSeen)
	if err != nil {
		return fmt.Errorf("insert device: %w", err)
	}
	return nil
}

func (r *deviceRepo) GetByID(ctx context.Context, id device.ID) (device.Device, error) {
	row := r.db.QueryRowContext(ctx, `SELECT id, user_id, public_key, created_at, last_seen_at FROM devices WHERE id = $1`, id)
	var d device.Device
	var lastSeen sql.NullTime
	if err := row.Scan(&d.ID, &d.UserID, &d.PublicKey, &d.CreatedAt, &lastSeen); err != nil {
		if err == sql.ErrNoRows {
			return device.Device{}, device.ErrNotFound
		}
		return device.Device{}, fmt.Errorf("select device by id: %w", err)
	}
	if lastSeen.Valid {
		t := lastSeen.Time
		d.LastSeenAt = &t
	}
	return d, nil
}

func (r *deviceRepo) GetByUserAndPublicKey(ctx context.Context, userID user.ID, publicKey string) (device.Device, error) {
	row := r.db.QueryRowContext(ctx, `SELECT id, user_id, public_key, created_at, last_seen_at
		FROM devices WHERE user_id = $1 AND public_key = $2`, userID, publicKey)
	var d device.Device
	var lastSeen sql.NullTime
	if err := row.Scan(&d.ID, &d.UserID, &d.PublicKey, &d.CreatedAt, &lastSeen); err != nil {
		if err == sql.ErrNoRows {
			return device.Device{}, device.ErrNotFound
		}
		return device.Device{}, fmt.Errorf("select device by user and public key: %w", err)
	}
	if lastSeen.Valid {
		t := lastSeen.Time
		d.LastSeenAt = &t
	}
	return d, nil
}

func (r *deviceRepo) ListByUser(ctx context.Context, userID user.ID) ([]device.Device, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id, user_id, public_key, created_at, last_seen_at
		FROM devices WHERE user_id = $1 ORDER BY created_at`, userID)
	if err != nil {
		return nil, fmt.Errorf("list devices by user: %w", err)
	}
	defer rows.Close()

	var devices []device.Device
	for rows.Next() {
		var d device.Device
		var lastSeen sql.NullTime
		if err := rows.Scan(&d.ID, &d.UserID, &d.PublicKey, &d.CreatedAt, &lastSeen); err != nil {
			return nil, fmt.Errorf("scan device: %w", err)
		}
		if lastSeen.Valid {
			t := lastSeen.Time
			d.LastSeenAt = &t
		}
		devices = append(devices, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate devices: %w", err)
	}
	return devices, nil
}

func (r *deviceRepo) ListAll(ctx context.Context) ([]device.Device, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id, user_id, public_key, created_at, last_seen_at
		FROM devices ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("list devices: %w", err)
	}
	defer rows.Close()

	var devices []device.Device
	for rows.Next() {
		var d device.Device
		var lastSeen sql.NullTime
		if err := rows.Scan(&d.ID, &d.UserID, &d.PublicKey, &d.CreatedAt, &lastSeen); err != nil {
			return nil, fmt.Errorf("scan device: %w", err)
		}
		if lastSeen.Valid {
			t := lastSeen.Time
			d.LastSeenAt = &t
		}
		devices = append(devices, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate devices: %w", err)
	}
	return devices, nil
}

func (r *deviceRepo) UpdateLastSeen(ctx context.Context, id device.ID, lastSeenAt time.Time) error {
	if id == "" || lastSeenAt.IsZero() {
		return fmt.Errorf("device id and last_seen_at are required")
	}

	res, err := r.db.ExecContext(ctx, `UPDATE devices SET last_seen_at = $2 WHERE id = $1`, id, lastSeenAt)
	if err != nil {
		return fmt.Errorf("update last_seen_at: %w", err)
	}

	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return device.ErrNotFound
	}
	return nil
}

type messageRepo struct {
	db *sql.DB
}

func (r *messageRepo) Save(ctx context.Context, msg message.Message) error {
	if msg.ID == "" || msg.SenderID == "" || msg.RecipientID == "" || msg.RecipientDeviceID == "" {
		return fmt.Errorf("message ids are required")
	}
	if len(msg.Ciphertext) == 0 || msg.SentAt.IsZero() {
		return fmt.Errorf("ciphertext and sent_at are required")
	}

	_, err := r.db.ExecContext(ctx, `INSERT INTO message_envelopes
		(id, sender_id, recipient_id, recipient_device_id, ciphertext, sent_at)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		msg.ID, msg.SenderID, msg.RecipientID, msg.RecipientDeviceID, msg.Ciphertext, msg.SentAt)
	if err != nil {
		return fmt.Errorf("insert message envelope: %w", err)
	}
	return nil
}

func (r *messageRepo) ListForRecipientDevice(ctx context.Context, deviceID device.ID, limit int) ([]message.Message, error) {
	if deviceID == "" {
		return nil, fmt.Errorf("device id is required")
	}
	if limit <= 0 {
		return nil, fmt.Errorf("limit must be positive")
	}

	rows, err := r.db.QueryContext(ctx, `SELECT id, sender_id, recipient_id, recipient_device_id, ciphertext, sent_at
		FROM message_envelopes WHERE recipient_device_id = $1 ORDER BY sent_at ASC LIMIT $2`, deviceID, limit)
	if err != nil {
		return nil, fmt.Errorf("list envelopes: %w", err)
	}
	defer rows.Close()

	var msgs []message.Message
	for rows.Next() {
		var msg message.Message
		if err := rows.Scan(&msg.ID, &msg.SenderID, &msg.RecipientID, &msg.RecipientDeviceID, &msg.Ciphertext, &msg.SentAt); err != nil {
			return nil, fmt.Errorf("scan envelope: %w", err)
		}
		msgs = append(msgs, msg)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate envelopes: %w", err)
	}
	return msgs, nil
}

type broadcastRepo struct {
	db *sql.DB
}

func (r *broadcastRepo) Save(ctx context.Context, msg message.BroadcastMessage) error {
	if msg.ID == "" || msg.SenderID == "" || msg.Body == "" || msg.SentAt.IsZero() {
		return fmt.Errorf("broadcast message fields are required")
	}

	var envelopes any
	if msg.Envelopes != nil {
		data, err := json.Marshal(msg.Envelopes)
		if err != nil {
			return fmt.Errorf("encode envelopes: %w", err)
		}
		envelopes = data
	}

	_, err := r.db.ExecContext(ctx, `INSERT INTO broadcast_messages
		(id, sender_id, sender_name, sender_public_key, body, key_envelopes, sent_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		msg.ID, msg.SenderID, msg.SenderName, msg.SenderPublicKey, msg.Body, envelopes, msg.SentAt)
	if err != nil {
		return fmt.Errorf("insert broadcast message: %w", err)
	}
	return nil
}

func (r *broadcastRepo) ListRecent(ctx context.Context, limit int) ([]message.BroadcastMessage, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("limit must be positive")
	}

	rows, err := r.db.QueryContext(ctx, `SELECT id, sender_id, sender_name, sender_public_key, body, key_envelopes, sent_at
		FROM broadcast_messages ORDER BY sent_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list broadcasts: %w", err)
	}
	defer rows.Close()

	var msgs []message.BroadcastMessage
	for rows.Next() {
		var msg message.BroadcastMessage
		var envelopes sql.NullString
		if err := rows.Scan(&msg.ID, &msg.SenderID, &msg.SenderName, &msg.SenderPublicKey, &msg.Body, &envelopes, &msg.SentAt); err != nil {
			return nil, fmt.Errorf("scan broadcast: %w", err)
		}
		if envelopes.Valid && envelopes.String != "" {
			var decoded map[string]string
			if err := json.Unmarshal([]byte(envelopes.String), &decoded); err != nil {
				return nil, fmt.Errorf("decode envelopes: %w", err)
			}
			msg.Envelopes = decoded
		}
		msgs = append(msgs, msg)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate broadcasts: %w", err)
	}
	// Reverse to chronological order (oldest first).
	for i, j := 0, len(msgs)-1; i < j; i, j = i+1, j-1 {
		msgs[i], msgs[j] = msgs[j], msgs[i]
	}
	return msgs, nil
}
