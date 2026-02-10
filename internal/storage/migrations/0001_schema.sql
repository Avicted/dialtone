-- Users
CREATE TABLE IF NOT EXISTS users (
	id TEXT PRIMARY KEY,
	username_hash TEXT NOT NULL,
	password_hash TEXT,
	is_admin BOOLEAN NOT NULL DEFAULT FALSE,
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

-- Channels
CREATE TABLE IF NOT EXISTS channels (
	id TEXT PRIMARY KEY,
	name_enc TEXT NOT NULL,
	created_by TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
	created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS channel_messages (
	id TEXT PRIMARY KEY,
	channel_id TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
	sender_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
	sender_name_enc TEXT NOT NULL,
	body TEXT NOT NULL,
	sent_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_channel_messages_channel_id ON channel_messages(channel_id);
CREATE INDEX IF NOT EXISTS idx_channel_messages_sent_at ON channel_messages(sent_at);

-- Server invites (invite-only registration)
CREATE TABLE IF NOT EXISTS server_invites (
	id TEXT PRIMARY KEY,
	created_at TIMESTAMPTZ NOT NULL,
	expires_at TIMESTAMPTZ NOT NULL,
	consumed_at TIMESTAMPTZ,
	consumed_by TEXT REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_server_invites_expires_at ON server_invites(expires_at);
