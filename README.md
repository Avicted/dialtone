# dialtone

Real-time chat backend in Go with end-to-end encryption. The server never sees plaintext messages.

## Requirements
- Go 1.22+

## Run (development)
Set env vars:

```
export DIALTONE_DB_URL=postgres://user:pass@localhost:5432/dialtone?sslmode=disable
export DIALTONE_LISTEN_ADDR=:8080
export DIALTONE_MASTER_KEY=<base64-encoded-32-byte-key>
```

Generate a master key:

```
openssl rand -base64 32
```

Then start the server:

```
go run ./cmd/server
```

## Encryption at rest
The server encrypts sensitive fields before storing them in Postgres. A master key is required and must be provided via `DIALTONE_MASTER_KEY` as a base64-encoded 32-byte value.

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


