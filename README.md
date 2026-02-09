# dialtone

Real-time chat backend in Go with end-to-end encryption. The server never sees plaintext messages.

## Requirements
- Go 1.22+

## Run (development)
Set env vars:

```
export DIALTONE_DB_URL=postgres://user:pass@localhost:5432/dialtone?sslmode=disable
export DIALTONE_LISTEN_ADDR=:8080
```

Then start the server:

```
go run ./cmd/server
```

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
