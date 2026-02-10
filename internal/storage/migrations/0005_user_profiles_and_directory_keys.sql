ALTER TABLE users
	ADD COLUMN IF NOT EXISTS is_trusted BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS user_profiles (
	user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
	name_enc TEXT NOT NULL,
	updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS directory_key_envelopes (
	device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
	sender_device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
	sender_public_key TEXT NOT NULL,
	envelope TEXT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_user_profiles_updated_at ON user_profiles(updated_at);
CREATE INDEX IF NOT EXISTS idx_directory_key_envelopes_device_id ON directory_key_envelopes(device_id);
