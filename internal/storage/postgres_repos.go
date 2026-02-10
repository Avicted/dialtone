package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Avicted/dialtone/internal/channel"
	"github.com/Avicted/dialtone/internal/device"
	"github.com/Avicted/dialtone/internal/message"
	"github.com/Avicted/dialtone/internal/serverinvite"
	"github.com/Avicted/dialtone/internal/user"
)

type userRepo struct {
	db *sql.DB
}

func (r *userRepo) Create(ctx context.Context, u user.User) error {
	if u.ID == "" || u.UsernameHash == "" || u.CreatedAt.IsZero() {
		return fmt.Errorf("user id, username_hash, and created_at are required")
	}

	var passwordHash any
	if u.PasswordHash != "" {
		passwordHash = u.PasswordHash
	}

	_, err := r.db.ExecContext(ctx, `INSERT INTO users (id, username_hash, password_hash, is_admin, created_at)
		VALUES ($1, $2, $3, $4, $5)`, u.ID, u.UsernameHash, passwordHash, u.IsAdmin, u.CreatedAt)
	if err != nil {
		return fmt.Errorf("insert user: %w", err)
	}
	return nil
}

func (r *userRepo) GetByID(ctx context.Context, id user.ID) (user.User, error) {
	row := r.db.QueryRowContext(ctx, `SELECT id, username_hash, password_hash, is_admin, created_at
		FROM users WHERE id = $1`, id)
	var u user.User
	var usernameHash sql.NullString
	var passwordHash sql.NullString
	if err := row.Scan(&u.ID, &usernameHash, &passwordHash, &u.IsAdmin, &u.CreatedAt); err != nil {
		if err == sql.ErrNoRows {
			return user.User{}, ErrNotFound
		}
		return user.User{}, fmt.Errorf("select user by id: %w", err)
	}
	if usernameHash.Valid {
		u.UsernameHash = usernameHash.String
	}
	if passwordHash.Valid {
		u.PasswordHash = passwordHash.String
	}
	if u.UsernameHash == "" {
		return user.User{}, ErrNotFound
	}
	return u, nil
}

func (r *userRepo) GetByUsernameHash(ctx context.Context, usernameHash string) (user.User, error) {
	row := r.db.QueryRowContext(ctx, `SELECT id, username_hash, password_hash, is_admin, created_at
		FROM users WHERE username_hash = $1`, usernameHash)
	var u user.User
	var storedHash sql.NullString
	var passwordHash sql.NullString
	if err := row.Scan(&u.ID, &storedHash, &passwordHash, &u.IsAdmin, &u.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return user.User{}, ErrNotFound
		}
		return user.User{}, fmt.Errorf("select user by username hash: %w", err)
	}
	if storedHash.Valid {
		u.UsernameHash = storedHash.String
	}
	if passwordHash.Valid {
		u.PasswordHash = passwordHash.String
	}
	if u.UsernameHash == "" {
		return user.User{}, ErrNotFound
	}
	return u, nil
}

func (r *userRepo) Count(ctx context.Context) (int, error) {
	row := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`)
	var count int
	if err := row.Scan(&count); err != nil {
		return 0, fmt.Errorf("count users: %w", err)
	}
	return count, nil
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
	row := r.db.QueryRowContext(ctx, `SELECT id, user_id, public_key, created_at, last_seen_at
		FROM devices WHERE id = $1`, id)
	var d device.Device
	var publicKey sql.NullString
	var lastSeen sql.NullTime
	if err := row.Scan(&d.ID, &d.UserID, &publicKey, &d.CreatedAt, &lastSeen); err != nil {
		if err == sql.ErrNoRows {
			return device.Device{}, device.ErrNotFound
		}
		return device.Device{}, fmt.Errorf("select device by id: %w", err)
	}
	if publicKey.Valid {
		d.PublicKey = publicKey.String
	}
	if lastSeen.Valid {
		t := lastSeen.Time
		d.LastSeenAt = &t
	}
	if d.PublicKey == "" {
		return device.Device{}, device.ErrNotFound
	}
	return d, nil
}

func (r *deviceRepo) GetByUserAndPublicKey(ctx context.Context, userID user.ID, publicKey string) (device.Device, error) {
	row := r.db.QueryRowContext(ctx, `SELECT id, user_id, public_key, created_at, last_seen_at
		FROM devices WHERE user_id = $1 AND public_key = $2`, userID, publicKey)
	var d device.Device
	var storedPublicKey sql.NullString
	var lastSeen sql.NullTime
	if err := row.Scan(&d.ID, &d.UserID, &storedPublicKey, &d.CreatedAt, &lastSeen); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return device.Device{}, device.ErrNotFound
		}
		return device.Device{}, fmt.Errorf("select device by user and public key: %w", err)
	}
	if storedPublicKey.Valid {
		d.PublicKey = storedPublicKey.String
	}
	if lastSeen.Valid {
		t := lastSeen.Time
		d.LastSeenAt = &t
	}
	if d.PublicKey == "" {
		return device.Device{}, device.ErrNotFound
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
		var publicKey sql.NullString
		var lastSeen sql.NullTime
		if err := rows.Scan(&d.ID, &d.UserID, &publicKey, &d.CreatedAt, &lastSeen); err != nil {
			return nil, fmt.Errorf("scan device: %w", err)
		}
		if publicKey.Valid {
			d.PublicKey = publicKey.String
		}
		if lastSeen.Valid {
			t := lastSeen.Time
			d.LastSeenAt = &t
		}
		if d.PublicKey != "" {
			devices = append(devices, d)
		}
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
		var publicKey sql.NullString
		var lastSeen sql.NullTime
		if err := rows.Scan(&d.ID, &d.UserID, &publicKey, &d.CreatedAt, &lastSeen); err != nil {
			return nil, fmt.Errorf("scan device: %w", err)
		}
		if publicKey.Valid {
			d.PublicKey = publicKey.String
		}
		if lastSeen.Valid {
			t := lastSeen.Time
			d.LastSeenAt = &t
		}
		if d.PublicKey != "" {
			devices = append(devices, d)
		}
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

type broadcastRepo struct {
	db *sql.DB
}

func (r *broadcastRepo) Save(ctx context.Context, msg message.BroadcastMessage) error {
	if msg.ID == "" || msg.SenderID == "" || msg.SenderNameEnc == "" || msg.Body == "" || msg.SentAt.IsZero() {
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
		(id, sender_id, sender_public_key, sender_name_enc, body, key_envelopes, sent_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		msg.ID, msg.SenderID, msg.SenderPublicKey, msg.SenderNameEnc, msg.Body, envelopes, msg.SentAt)
	if err != nil {
		return fmt.Errorf("insert broadcast message: %w", err)
	}
	return nil
}

func (r *broadcastRepo) ListRecent(ctx context.Context, limit int) ([]message.BroadcastMessage, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("limit must be positive")
	}

	rows, err := r.db.QueryContext(ctx, `SELECT id, sender_id, sender_public_key, sender_name_enc, body, key_envelopes, sent_at
		FROM broadcast_messages ORDER BY sent_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list broadcasts: %w", err)
	}
	defer rows.Close()

	var msgs []message.BroadcastMessage
	for rows.Next() {
		var msg message.BroadcastMessage
		var senderKey sql.NullString
		var senderNameEnc sql.NullString
		var envelopes sql.NullString
		if err := rows.Scan(&msg.ID, &msg.SenderID, &senderKey, &senderNameEnc, &msg.Body, &envelopes, &msg.SentAt); err != nil {
			return nil, fmt.Errorf("scan broadcast: %w", err)
		}
		if senderKey.Valid {
			msg.SenderPublicKey = senderKey.String
		}
		if senderNameEnc.Valid {
			msg.SenderNameEnc = senderNameEnc.String
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

type channelRepo struct {
	db *sql.DB
}

func (r *channelRepo) CreateChannel(ctx context.Context, ch channel.Channel) error {
	if ch.ID == "" || ch.NameEnc == "" || ch.CreatedBy == "" || ch.CreatedAt.IsZero() {
		return fmt.Errorf("channel fields are required")
	}
	_, err := r.db.ExecContext(ctx, `INSERT INTO channels (id, name_enc, created_by, created_at)
		VALUES ($1, $2, $3, $4)`, ch.ID, ch.NameEnc, ch.CreatedBy, ch.CreatedAt)
	if err != nil {
		return fmt.Errorf("insert channel: %w", err)
	}
	return nil
}

func (r *channelRepo) GetChannel(ctx context.Context, id channel.ID) (channel.Channel, error) {
	row := r.db.QueryRowContext(ctx, `SELECT id, name_enc, created_by, created_at FROM channels WHERE id = $1`, id)
	var ch channel.Channel
	if err := row.Scan(&ch.ID, &ch.NameEnc, &ch.CreatedBy, &ch.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return channel.Channel{}, ErrNotFound
		}
		return channel.Channel{}, fmt.Errorf("select channel: %w", err)
	}
	return ch, nil
}

func (r *channelRepo) ListChannels(ctx context.Context) ([]channel.Channel, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id, name_enc, created_by, created_at
		FROM channels ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list channels: %w", err)
	}
	defer rows.Close()

	var channels []channel.Channel
	for rows.Next() {
		var ch channel.Channel
		if err := rows.Scan(&ch.ID, &ch.NameEnc, &ch.CreatedBy, &ch.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan channel: %w", err)
		}
		channels = append(channels, ch)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate channels: %w", err)
	}
	return channels, nil
}

func (r *channelRepo) DeleteChannel(ctx context.Context, id channel.ID) error {
	if id == "" {
		return fmt.Errorf("channel id is required")
	}
	res, err := r.db.ExecContext(ctx, `DELETE FROM channels WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete channel: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *channelRepo) UpdateChannelName(ctx context.Context, id channel.ID, nameEnc string) error {
	if id == "" || strings.TrimSpace(nameEnc) == "" {
		return fmt.Errorf("channel id and name_enc are required")
	}
	res, err := r.db.ExecContext(ctx, `UPDATE channels SET name_enc = $2 WHERE id = $1`, id, strings.TrimSpace(nameEnc))
	if err != nil {
		return fmt.Errorf("update channel: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *channelRepo) SaveMessage(ctx context.Context, msg channel.Message) error {
	if msg.ID == "" || msg.ChannelID == "" || msg.SenderID == "" || msg.SenderNameEnc == "" || msg.Body == "" || msg.SentAt.IsZero() {
		return fmt.Errorf("channel message fields are required")
	}
	_, err := r.db.ExecContext(ctx, `INSERT INTO channel_messages (id, channel_id, sender_id, sender_name_enc, body, sent_at)
		VALUES ($1, $2, $3, $4, $5, $6)`, msg.ID, msg.ChannelID, msg.SenderID, msg.SenderNameEnc, msg.Body, msg.SentAt)
	if err != nil {
		return fmt.Errorf("insert channel message: %w", err)
	}
	return nil
}

func (r *channelRepo) ListRecentMessages(ctx context.Context, channelID channel.ID, limit int) ([]channel.Message, error) {
	if channelID == "" || limit <= 0 {
		return nil, fmt.Errorf("channel id and positive limit are required")
	}
	rows, err := r.db.QueryContext(ctx, `SELECT id, channel_id, sender_id, sender_name_enc, body, sent_at
		FROM channel_messages WHERE channel_id = $1 ORDER BY sent_at DESC LIMIT $2`, channelID, limit)
	if err != nil {
		return nil, fmt.Errorf("list channel messages: %w", err)
	}
	defer rows.Close()

	var msgs []channel.Message
	for rows.Next() {
		var msg channel.Message
		if err := rows.Scan(&msg.ID, &msg.ChannelID, &msg.SenderID, &msg.SenderNameEnc, &msg.Body, &msg.SentAt); err != nil {
			return nil, fmt.Errorf("scan channel message: %w", err)
		}
		msgs = append(msgs, msg)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate channel messages: %w", err)
	}
	for i, j := 0, len(msgs)-1; i < j; i, j = i+1, j-1 {
		msgs[i], msgs[j] = msgs[j], msgs[i]
	}
	return msgs, nil
}

type serverInviteRepo struct {
	db *sql.DB
}

func (r *serverInviteRepo) Create(ctx context.Context, invite serverinvite.Invite) error {
	if invite.Token == "" || invite.CreatedAt.IsZero() || invite.ExpiresAt.IsZero() {
		return fmt.Errorf("invite token, created_at, and expires_at are required")
	}
	_, err := r.db.ExecContext(ctx, `INSERT INTO server_invites (id, created_at, expires_at)
		VALUES ($1, $2, $3)`, invite.Token, invite.CreatedAt, invite.ExpiresAt)
	if err != nil {
		return fmt.Errorf("insert server invite: %w", err)
	}
	return nil
}

func (r *serverInviteRepo) Consume(ctx context.Context, token string, userID user.ID, now time.Time) (serverinvite.Invite, error) {
	if token == "" || userID == "" || now.IsZero() {
		return serverinvite.Invite{}, serverinvite.ErrInvalidInput
	}

	row := r.db.QueryRowContext(ctx, `UPDATE server_invites
		SET consumed_at = $2
		WHERE id = $1 AND consumed_at IS NULL AND expires_at > $2
		RETURNING id, created_at, expires_at, consumed_at, consumed_by`, token, now)

	var invite serverinvite.Invite
	var consumedAt sql.NullTime
	var consumedBy sql.NullString
	if err := row.Scan(&invite.Token, &invite.CreatedAt, &invite.ExpiresAt, &consumedAt, &consumedBy); err == nil {
		if consumedAt.Valid {
			t := consumedAt.Time
			invite.ConsumedAt = &t
		}
		if consumedBy.Valid {
			id := user.ID(consumedBy.String)
			invite.ConsumedBy = &id
		}
		return invite, nil
	}

	row = r.db.QueryRowContext(ctx, `SELECT id, created_at, expires_at, consumed_at, consumed_by
		FROM server_invites WHERE id = $1`, token)
	if err := row.Scan(&invite.Token, &invite.CreatedAt, &invite.ExpiresAt, &consumedAt, &consumedBy); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return serverinvite.Invite{}, serverinvite.ErrNotFound
		}
		return serverinvite.Invite{}, fmt.Errorf("select server invite: %w", err)
	}
	if consumedAt.Valid {
		return serverinvite.Invite{}, serverinvite.ErrConsumed
	}
	if !invite.ExpiresAt.IsZero() && !invite.ExpiresAt.After(now) {
		return serverinvite.Invite{}, serverinvite.ErrExpired
	}
	return serverinvite.Invite{}, serverinvite.ErrNotFound
}
