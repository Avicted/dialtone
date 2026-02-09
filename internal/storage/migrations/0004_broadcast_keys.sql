ALTER TABLE broadcast_messages
	ADD COLUMN IF NOT EXISTS sender_public_key TEXT NOT NULL DEFAULT '',
	ADD COLUMN IF NOT EXISTS key_envelopes JSONB;
