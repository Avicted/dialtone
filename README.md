# dialtone

Real-time chat backend in Go with end-to-end encryption. The server never sees plaintext messages.

## Requirements
- Go 1.22+

## Run (development)
Create an env file:

```
cp .env.example .env
```

Update the values inside `.env`, then load env vars:

```
set -a
. ./.env
set +a
```

Generate a channel key:

```
openssl rand -base64 32
```

Set `DIALTONE_USERNAME_PEPPER` and `DIALTONE_ADMIN_TOKEN` in `.env`. The pepper is a server secret used for username hashing, and the admin token is required to mint server invites.

Then start the server:

```
go run ./cmd/server
```

## Encryption at rest
The server encrypts sensitive fields before storing them in Postgres. A channel key is required and must be provided via `DIALTONE_CHANNEL_KEY` as a base64-encoded 32-byte value.

Encrypted fields:
- users.username
- devices.public_key
- broadcast_messages.sender_name
- broadcast_messages.sender_public_key

Lookup behavior:
- The application stores a keyed hash of usernames and device public keys for equality lookups.
- Existing plaintext rows are encrypted lazily the first time they are read.

Migrations:
- Ensure migrations are applied before running the server so the encrypted columns and indexes exist.

## Structure
- cmd/server: entrypoint
- internal/auth: authentication middleware
- internal/crypto: encryption primitives and key exchange
- internal/ws: WebSocket hub and client handling
- internal/storage: data persistence interfaces and implementations
- internal/user: user domain
- internal/message: message domain
- pkg: shared packages intended for external use

## Security constraints
- TLS for all transport
- Message content must be encrypted before reaching the server
- Use only Go standard library crypto packages

## Docker Compose
Start Postgres using the env file:

```
docker compose up -d
```

The compose file reads `.env` and uses `POSTGRES_*` values to configure the database. For local development outside of compose, update `DIALTONE_DB_URL` to point at `localhost` instead of `postgres`.
