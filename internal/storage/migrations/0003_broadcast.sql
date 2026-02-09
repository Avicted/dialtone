CREATE TABLE IF NOT EXISTS broadcast_messages (
	id TEXT PRIMARY KEY,
	sender_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
	sender_name TEXT NOT NULL DEFAULT '',
	body TEXT NOT NULL,
	sent_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_broadcast_messages_sent_at ON broadcast_messages(sent_at);
