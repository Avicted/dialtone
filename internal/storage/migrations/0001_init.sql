CREATE TABLE IF NOT EXISTS users (
	id TEXT PRIMARY KEY,
	username TEXT NOT NULL UNIQUE,
	created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
	id TEXT PRIMARY KEY,
	user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	public_key TEXT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL,
	last_seen_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_devices_user_id ON devices(user_id);

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
