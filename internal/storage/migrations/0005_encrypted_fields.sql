ALTER TABLE users
	ADD COLUMN IF NOT EXISTS username_enc TEXT,
	ADD COLUMN IF NOT EXISTS username_hash TEXT;

ALTER TABLE users
	ALTER COLUMN username DROP NOT NULL;

ALTER TABLE users
	DROP CONSTRAINT IF EXISTS users_username_key;

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_hash
	ON users(username_hash)
	WHERE username_hash IS NOT NULL;

ALTER TABLE devices
	ADD COLUMN IF NOT EXISTS public_key_enc TEXT,
	ADD COLUMN IF NOT EXISTS public_key_hash TEXT;

ALTER TABLE devices
	ALTER COLUMN public_key DROP NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_user_pubkey_hash
	ON devices(user_id, public_key_hash)
	WHERE public_key_hash IS NOT NULL;

ALTER TABLE broadcast_messages
	ADD COLUMN IF NOT EXISTS sender_name_enc TEXT,
	ADD COLUMN IF NOT EXISTS sender_public_key_enc TEXT;
