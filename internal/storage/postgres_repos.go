package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Avicted/dialtone/internal/device"
	"github.com/Avicted/dialtone/internal/message"
	"github.com/Avicted/dialtone/internal/room"
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
	row := r.db.QueryRowContext(ctx, `SELECT id, username, password_hash, created_at
		FROM users WHERE id = $1`, id)
	var u user.User
	var username sql.NullString
	var passwordHash sql.NullString
	if err := row.Scan(&u.ID, &username, &passwordHash, &u.CreatedAt); err != nil {
		if err == sql.ErrNoRows {
			return user.User{}, ErrNotFound
		}
		return user.User{}, fmt.Errorf("select user by id: %w", err)
	}
	if username.Valid {
		u.Username = username.String
	}
	if passwordHash.Valid {
		u.PasswordHash = passwordHash.String
	}
	if u.Username == "" {
		return user.User{}, ErrNotFound
	}
	return u, nil
}

func (r *userRepo) GetByUsername(ctx context.Context, username string) (user.User, error) {
	row := r.db.QueryRowContext(ctx, `SELECT id, username, password_hash, created_at
		FROM users WHERE username = $1`, username)
	var u user.User
	var storedUsername sql.NullString
	var passwordHash sql.NullString
	if err := row.Scan(&u.ID, &storedUsername, &passwordHash, &u.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return user.User{}, ErrNotFound
		}
		return user.User{}, fmt.Errorf("select user by username: %w", err)
	}
	if storedUsername.Valid {
		u.Username = storedUsername.String
	}
	if passwordHash.Valid {
		u.PasswordHash = passwordHash.String
	}
	if u.Username == "" {
		return user.User{}, ErrNotFound
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
		var senderName sql.NullString
		var senderKey sql.NullString
		var envelopes sql.NullString
		if err := rows.Scan(&msg.ID, &msg.SenderID, &senderName, &senderKey, &msg.Body, &envelopes, &msg.SentAt); err != nil {
			return nil, fmt.Errorf("scan broadcast: %w", err)
		}
		if senderName.Valid {
			msg.SenderName = senderName.String
		}
		if senderKey.Valid {
			msg.SenderPublicKey = senderKey.String
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

type roomRepo struct {
	db *sql.DB
}

func (r *roomRepo) CreateRoom(ctx context.Context, rm room.Room) error {
	if rm.ID == "" || rm.NameEnc == "" || rm.CreatedBy == "" || rm.CreatedAt.IsZero() {
		return fmt.Errorf("room fields are required")
	}
	_, err := r.db.ExecContext(ctx, `INSERT INTO rooms (id, name, name_enc, created_by, created_at)
		VALUES ($1, $2, $3, $4, $5)`, rm.ID, "", rm.NameEnc, rm.CreatedBy, rm.CreatedAt)
	if err != nil {
		return fmt.Errorf("insert room: %w", err)
	}
	return nil
}

func (r *roomRepo) GetRoom(ctx context.Context, id room.ID) (room.Room, error) {
	row := r.db.QueryRowContext(ctx, `SELECT id, name, name_enc, created_by, created_at FROM rooms WHERE id = $1`, id)
	var rm room.Room
	if err := row.Scan(&rm.ID, &rm.Name, &rm.NameEnc, &rm.CreatedBy, &rm.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return room.Room{}, ErrNotFound
		}
		return room.Room{}, fmt.Errorf("select room: %w", err)
	}
	return rm, nil
}

func (r *roomRepo) ListRoomsForUser(ctx context.Context, userID user.ID) ([]room.Room, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT r.id, r.name, r.name_enc, r.created_by, r.created_at
		FROM rooms r
		JOIN room_members m ON m.room_id = r.id
		WHERE m.user_id = $1
		ORDER BY r.created_at DESC`, userID)
	if err != nil {
		return nil, fmt.Errorf("list rooms: %w", err)
	}
	defer rows.Close()

	var rooms []room.Room
	for rows.Next() {
		var rm room.Room
		if err := rows.Scan(&rm.ID, &rm.Name, &rm.NameEnc, &rm.CreatedBy, &rm.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan room: %w", err)
		}
		rooms = append(rooms, rm)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rooms: %w", err)
	}
	return rooms, nil
}

func (r *roomRepo) AddMember(ctx context.Context, roomID room.ID, userID user.ID, displayNameEnc string, joinedAt time.Time) error {
	if roomID == "" || userID == "" || displayNameEnc == "" || joinedAt.IsZero() {
		return fmt.Errorf("member fields are required")
	}
	_, err := r.db.ExecContext(ctx, `INSERT INTO room_members (room_id, user_id, display_name_enc, joined_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (room_id, user_id) DO NOTHING`, roomID, userID, displayNameEnc, joinedAt)
	if err != nil {
		return fmt.Errorf("insert member: %w", err)
	}
	return nil
}

func (r *roomRepo) IsMember(ctx context.Context, roomID room.ID, userID user.ID) (bool, error) {
	row := r.db.QueryRowContext(ctx, `SELECT 1 FROM room_members WHERE room_id = $1 AND user_id = $2`, roomID, userID)
	var exists int
	if err := row.Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("check membership: %w", err)
	}
	return true, nil
}

func (r *roomRepo) ListMembers(ctx context.Context, roomID room.ID) ([]room.Member, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT user_id, display_name_enc FROM room_members WHERE room_id = $1`, roomID)
	if err != nil {
		return nil, fmt.Errorf("list members: %w", err)
	}
	defer rows.Close()

	var members []room.Member
	for rows.Next() {
		var member room.Member
		if err := rows.Scan(&member.UserID, &member.DisplayNameEnc); err != nil {
			return nil, fmt.Errorf("scan member: %w", err)
		}
		members = append(members, member)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate members: %w", err)
	}
	return members, nil
}

func (r *roomRepo) GetMemberDisplayNameEnc(ctx context.Context, roomID room.ID, userID user.ID) (string, error) {
	row := r.db.QueryRowContext(ctx, `SELECT display_name_enc FROM room_members WHERE room_id = $1 AND user_id = $2`, roomID, userID)
	var displayName string
	if err := row.Scan(&displayName); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("select display name: %w", err)
	}
	if displayName == "" {
		return "", ErrNotFound
	}
	return displayName, nil
}

func (r *roomRepo) CreateInvite(ctx context.Context, invite room.Invite) error {
	if invite.Token == "" || invite.RoomID == "" || invite.CreatedBy == "" || invite.CreatedAt.IsZero() || invite.ExpiresAt.IsZero() {
		return fmt.Errorf("invite fields are required")
	}
	_, err := r.db.ExecContext(ctx, `INSERT INTO room_invites (id, room_id, created_by, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5)`, invite.Token, invite.RoomID, invite.CreatedBy, invite.CreatedAt, invite.ExpiresAt)
	if err != nil {
		return fmt.Errorf("insert invite: %w", err)
	}
	return nil
}

func (r *roomRepo) ConsumeInvite(ctx context.Context, token string, userID user.ID, displayNameEnc string, now time.Time) (room.Invite, error) {
	if token == "" || userID == "" || displayNameEnc == "" || now.IsZero() {
		return room.Invite{}, fmt.Errorf("consume fields are required")
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return room.Invite{}, fmt.Errorf("begin consume: %w", err)
	}

	var invite room.Invite
	row := tx.QueryRowContext(ctx, `UPDATE room_invites
		SET consumed_at = $2, consumed_by = $3
		WHERE id = $1 AND consumed_at IS NULL AND expires_at > $2
		RETURNING id, room_id, created_by, created_at, expires_at, consumed_at, consumed_by`, token, now, userID)
	if err := row.Scan(&invite.Token, &invite.RoomID, &invite.CreatedBy, &invite.CreatedAt, &invite.ExpiresAt, &invite.ConsumedAt, &invite.ConsumedBy); err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			_ = tx.Rollback()
			return room.Invite{}, fmt.Errorf("consume invite: %w", err)
		}

		check := tx.QueryRowContext(ctx, `SELECT id, room_id, created_by, created_at, expires_at, consumed_at, consumed_by
			FROM room_invites WHERE id = $1`, token)
		var existing room.Invite
		if err := check.Scan(&existing.Token, &existing.RoomID, &existing.CreatedBy, &existing.CreatedAt, &existing.ExpiresAt, &existing.ConsumedAt, &existing.ConsumedBy); err != nil {
			_ = tx.Rollback()
			if errors.Is(err, sql.ErrNoRows) {
				return room.Invite{}, ErrNotFound
			}
			return room.Invite{}, fmt.Errorf("lookup invite: %w", err)
		}
		_ = tx.Rollback()
		if existing.ConsumedAt != nil {
			return room.Invite{}, room.ErrInviteConsumed
		}
		if !existing.ExpiresAt.IsZero() && !existing.ExpiresAt.After(now) {
			return room.Invite{}, room.ErrInviteExpired
		}
		return room.Invite{}, ErrNotFound
	}

	if _, err := tx.ExecContext(ctx, `INSERT INTO room_members (room_id, user_id, display_name_enc, joined_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (room_id, user_id) DO NOTHING`, invite.RoomID, userID, displayNameEnc, now); err != nil {
		_ = tx.Rollback()
		return room.Invite{}, fmt.Errorf("insert member: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return room.Invite{}, fmt.Errorf("commit consume: %w", err)
	}
	return invite, nil
}

func (r *roomRepo) SaveMessage(ctx context.Context, msg room.Message) error {
	if msg.ID == "" || msg.RoomID == "" || msg.SenderID == "" || msg.SenderNameEnc == "" || msg.Body == "" || msg.SentAt.IsZero() {
		return fmt.Errorf("room message fields are required")
	}
	_, err := r.db.ExecContext(ctx, `INSERT INTO room_messages (id, room_id, sender_id, sender_name, sender_name_enc, body, sent_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`, msg.ID, msg.RoomID, msg.SenderID, "", msg.SenderNameEnc, msg.Body, msg.SentAt)
	if err != nil {
		return fmt.Errorf("insert room message: %w", err)
	}
	return nil
}

func (r *roomRepo) ListRecentMessages(ctx context.Context, roomID room.ID, limit int) ([]room.Message, error) {
	if roomID == "" || limit <= 0 {
		return nil, fmt.Errorf("room id and positive limit are required")
	}
	rows, err := r.db.QueryContext(ctx, `SELECT id, room_id, sender_id, sender_name, sender_name_enc, body, sent_at
		FROM room_messages WHERE room_id = $1 ORDER BY sent_at DESC LIMIT $2`, roomID, limit)
	if err != nil {
		return nil, fmt.Errorf("list room messages: %w", err)
	}
	defer rows.Close()

	var msgs []room.Message
	for rows.Next() {
		var msg room.Message
		if err := rows.Scan(&msg.ID, &msg.RoomID, &msg.SenderID, &msg.SenderName, &msg.SenderNameEnc, &msg.Body, &msg.SentAt); err != nil {
			return nil, fmt.Errorf("scan room message: %w", err)
		}
		msgs = append(msgs, msg)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate room messages: %w", err)
	}
	for i, j := 0, len(msgs)-1; i < j; i, j = i+1, j-1 {
		msgs[i], msgs[j] = msgs[j], msgs[i]
	}
	return msgs, nil
}
