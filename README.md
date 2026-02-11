# dialtone

[![CI](https://github.com/Avicted/dialtone/actions/workflows/ci.yml/badge.svg)](https://github.com/Avicted/dialtone/actions/workflows/ci.yml)
[![Coverage](https://avicted.github.io/dialtone/badges/coverage.svg)](https://github.com/Avicted/dialtone/actions/workflows/ci.yml)

Dialtone uses symmetric encryption for content and metadata, and public key encryption to share those symmetric keys across devices. The server never sees plaintext message content or channel names, but it can see routing metadata required for the system to function. Usernames are sent in plaintext during login/register and stored only as a peppered hash (no plaintext usernames in the database).

## Quick start

### Requirements
- Go 1.22+
- Postgres 16+

### Configure
Copy the example env file and set required values:

```bash
cp .env.example .env
```

Required variables:
- DIALTONE_DB_URL
- DIALTONE_USERNAME_PEPPER
- DIALTONE_CHANNEL_KEY
- DIALTONE_ADMIN_TOKEN

Generate secrets:

```bash
openssl rand -base64 32
```

Use the output for DIALTONE_USERNAME_PEPPER and DIALTONE_CHANNEL_KEY. Set a strong random value for DIALTONE_ADMIN_TOKEN.

### Run server

```bash
set -a
. ./.env
set +a

go run ./cmd/server
```

### Create initial invite

```bash
curl -s -X POST http://localhost:8080/server/invites \
  -H "X-Admin-Token: $DIALTONE_ADMIN_TOKEN"
```

#### From withing the dialtone docker container using curl:
```bash
set -a
. ./.env
set +a

docker exec -it dialtone sh -c 'curl -X POST \
  -H "X-Admin-Token: $DIALTONE_ADMIN_TOKEN" \
  http://localhost:8080/server/invites'
```

The response includes token and expires_at. Use the token when registering a new user.

## Reverse proxy
You can place a reverse proxy (for example HAProxy) in front of the server to perform SSL/TLS termination. Keep the backend connection private and protected.

## Client storage
Local client keys are stored under ~/.config/dialtone on Linux and %APPDATA%\\dialtone on Windows. The keystore is encrypted with a passphrase you enter at login.

## Documentation
- [API](docs/API.md)
- [Encryption flow](docs/ENCRYPTION_FLOW.md)


## License
MIT
