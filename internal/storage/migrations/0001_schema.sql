-- Users
CREATE TABLE IF NOT EXISTS users (
	id TEXT PRIMARY KEY,
	username_hash TEXT NOT NULL,
	password_hash TEXT,
	created_at TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_hash ON users(username_hash);

-- Devices
CREATE TABLE IF NOT EXISTS devices (
	id TEXT PRIMARY KEY,
	user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	public_key TEXT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL,
	last_seen_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_devices_user_id ON devices(user_id);

-- Direct message envelopes
CREATE TABLE IF NOT EXISTS message_envelopes (
	id TEXT PRIMARY KEY,
	sender_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
	recipient_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
	recipient_device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE RESTRICT,
	ciphertext BYTEA NOT NULL,
	sent_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_message_envelopes_recipient_id ON message_envelopes(recipient_id);
CREATE INDEX IF NOT EXISTS idx_message_envelopes_recipient_device_id ON message_envelopes(recipient_device_id);
CREATE INDEX IF NOT EXISTS idx_message_envelopes_sender_id ON message_envelopes(sender_id);

-- Broadcast messages (body and sender_name_enc are ciphertext from client)
CREATE TABLE IF NOT EXISTS broadcast_messages (
	id TEXT PRIMARY KEY,
	sender_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
	sender_public_key TEXT NOT NULL DEFAULT '',
	sender_name_enc TEXT NOT NULL,
	body TEXT NOT NULL,
	key_envelopes JSONB,
	sent_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_broadcast_messages_sent_at ON broadcast_messages(sent_at);

-- Rooms
CREATE TABLE IF NOT EXISTS rooms (
	id TEXT PRIMARY KEY,
	name_enc TEXT NOT NULL,
	created_by TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
	created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS room_members (
	room_id TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
	user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	display_name_enc TEXT NOT NULL,
	joined_at TIMESTAMPTZ NOT NULL,
	PRIMARY KEY (room_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_room_members_user_id ON room_members(user_id);

CREATE TABLE IF NOT EXISTS room_invites (
	id TEXT PRIMARY KEY,
	room_id TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
	created_by TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
	created_at TIMESTAMPTZ NOT NULL,
	expires_at TIMESTAMPTZ NOT NULL,
	consumed_at TIMESTAMPTZ,
	consumed_by TEXT REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_room_invites_room_id ON room_invites(room_id);
CREATE INDEX IF NOT EXISTS idx_room_invites_expires_at ON room_invites(expires_at);

CREATE TABLE IF NOT EXISTS room_messages (
	id TEXT PRIMARY KEY,
	room_id TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
	sender_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
	sender_name_enc TEXT NOT NULL,
	body TEXT NOT NULL,
	sent_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_room_messages_room_id ON room_messages(room_id);
CREATE INDEX IF NOT EXISTS idx_room_messages_sent_at ON room_messages(sent_at);
