CREATE TABLE IF NOT EXISTS rooms (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	created_by TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
	created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS room_members (
	room_id TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
	user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
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
	sender_name TEXT NOT NULL,
	body TEXT NOT NULL,
	sent_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_room_messages_room_id ON room_messages(room_id);
CREATE INDEX IF NOT EXISTS idx_room_messages_sent_at ON room_messages(sent_at);
