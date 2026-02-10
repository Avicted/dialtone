-- Channel key envelopes (per-device encrypted channel keys)
CREATE TABLE IF NOT EXISTS channel_key_envelopes (
	channel_id TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
	device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
	sender_device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
	sender_public_key TEXT NOT NULL,
	envelope TEXT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL,
	PRIMARY KEY (channel_id, device_id)
);

CREATE INDEX IF NOT EXISTS idx_channel_key_envelopes_channel_id ON channel_key_envelopes(channel_id);
CREATE INDEX IF NOT EXISTS idx_channel_key_envelopes_device_id ON channel_key_envelopes(device_id);
