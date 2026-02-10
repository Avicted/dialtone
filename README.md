# dialtone

Real-time chat backend in Go with end-to-end encryption. The server never sees plaintext messages.

## Requirements
- Go 1.22+
- Postgres 16+

## Configuration
Copy the example env file and update values:

```bash
cp .env.example .env
```

Set these required values in `.env`:
- `DIALTONE_DB_URL`
- `DIALTONE_USERNAME_PEPPER`
- `DIALTONE_CHANNEL_KEY`
- `DIALTONE_ADMIN_TOKEN`

Generate secrets:

```bash
openssl rand -base64 32
```

Use that output for both `DIALTONE_USERNAME_PEPPER` and `DIALTONE_CHANNEL_KEY`. Set a strong random value for `DIALTONE_ADMIN_TOKEN`.

## Run (development)
Load env vars, then start the server:

```bash
set -a
. ./.env
set +a

go run ./cmd/server
```

## Docker Compose (Postgres only)
Start Postgres using the env file:

```bash
docker compose up -d
```

For local development outside of compose, `DIALTONE_DB_URL` should point at `localhost` instead of `postgres`.

## Create the initial invite
Invites are created by `POST /server/invites` and require the admin token in the `X-Admin-Token` header.

If the server runs in a container named `dialup`:

```bash
docker exec -it dialup sh -lc 'curl -s -X POST http://localhost:8080/server/invites -H "X-Admin-Token: $DIALTONE_ADMIN_TOKEN"'
```

If you are calling the server directly:

```bash
curl -s -X POST https://your-domain/server/invites -H "X-Admin-Token: $DIALTONE_ADMIN_TOKEN"
```

The response includes `token` and `expires_at`. Use the token when registering a new user.

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

## Project layout
- cmd/server: server entrypoint
- cmd/client: terminal client
- internal/auth: authentication
- internal/crypto: encryption primitives and key exchange
- internal/httpapi: REST handlers
- internal/ws: WebSocket hub and client handling
- internal/storage: data persistence interfaces and implementations
- internal/user: user domain
- internal/message: message domain

## Security constraints
- TLS for all transport
- Message content must be encrypted before reaching the server
- Use only Go standard library crypto packages
