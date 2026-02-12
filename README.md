# dialtone

[![CI](https://github.com/Avicted/dialtone/actions/workflows/ci.yml/badge.svg)](https://github.com/Avicted/dialtone/actions/workflows/ci.yml)
[![Coverage](https://avicted.github.io/dialtone/badges/coverage.svg)](https://github.com/Avicted/dialtone/actions/workflows/ci.yml)

Dialtone is a realtime websocket chat with end-to-end encrypted message bodies and channel names.

Dialtone uses symmetric encryption for message bodies and channel names, and public key encryption to share those symmetric keys across devices. The server never sees plaintext message content or channel names, but it can see routing metadata required for the system to function. Usernames are sent in plaintext during login/register and stored only as a peppered hash (no plaintext usernames in the database).

## Client
![docs/dialtone-client-01.png](docs/dialtone-client-01.png)
![docs/dialtone-client-02.png](docs/dialtone-client-02.png)

## Quick start (server)

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
export $(grep -v '^#' .env | xargs)

go run ./cmd/server
```

## Voice (TURN/STUN)

Dialtone voice uses WebRTC and benefits from TURN for NAT traversal. A coturn service is included in docker-compose for local testing.

### Voice requirements

- CGO enabled (`CGO_ENABLED=1`)
- libopus installed (for Opus encoding)
- An audio backend (ALSA/PulseAudio/PipeWire on Linux; WASAPI on Windows)

### Configure TURN

Update `.env` with TURN settings:

```
TURN_USER=turn
TURN_PASS=replace-with-strong-random-password
TURN_REALM=turn.example.com
TURN_EXTERNAL_IP=<public_server_ip>
TURN_PORT=3478
TURN_TLS_PORT=5349
TURN_CERT_FILE=/etc/coturn/certs/fullchain.pem
TURN_KEY_FILE=/etc/coturn/certs/privkey.pem
TURN_MIN_PORT=49152
TURN_MAX_PORT=49252
```

Use a DNS record such as `turn.example.com` that resolves to your server's public IP.

Open firewall ports for TURN:

- `3478/tcp` and `3478/udp`
- `5349/tcp`
- `TURN_MIN_PORT`-`TURN_MAX_PORT` (UDP relay range)

If a host port is already in use, choose a different TURN listening port or relay UDP range.

Start coturn:

```bash
docker compose up -d coturn
```

Build and run the client with TURN (and optional STUN) settings:

```bash
go build -o ./bin/client ./cmd/client

./bin/client \
  --server https://dialtone.domain.com \
  --voice-debug \
  --voice-ptt caps \
  --voice-meter \
  --voice-ptt-backend portal \
  --voice-turn "turn:turn.dialtone.domain.com:3478?transport=udp,turn:turn.dialtone.domain.com:3478?transport=tcp,turns:turn.dialtone.domain.com:5349?transport=tcp" \
  --voice-turn-user "<TURN_USER>" \
  --voice-turn-pass "<TURN_PASS>"
  
```

You can also provide STUN servers with `--stun`

Client auto-start (recommended for debugging):

```bash
# Voice activation
./bin/client --voice-debug --voice-ptt "" --voice-meter --voice-vad 20

# PTT
./bin/client --voice-debug --voice-meter --voice-ptt-backend portal --voice-ptt caps
```

- `--voice-debug` writes `dialtone-voiced` logs to a file (see the client UI for the log path).
- On Linux, global PTT uses the XDG Desktop Portal (`org.freedesktop.portal.GlobalShortcuts`) over D-Bus (your desktop may prompt for permission).
- `--voice-ptt ""` disables push-to-talk and uses VAD.
- `--ptt-backend` (`auto|portal|hotkey`) controls daemon PTT backend selection.
- `--voice-ptt-backend` (`auto|portal|hotkey`) passes backend selection to auto-started `dialtone-voiced`.
- `--voice-vad <n>` lowers or raises the VAD threshold (lower = more sensitive).
- `--voice-meter` logs mic levels to the `dialtone-voiced` log file once per second.
- `--voice-stun/--voice-turn/--voice-turn-user/--voice-turn-pass` are passed to the auto-started `dialtone-voiced` daemon.
- On Wayland (`auto` backend), Dialtone requires portal global shortcuts by default. To force direct hotkey fallback anyway, set `DIALTONE_PTT_WAYLAND_HOTKEY_FALLBACK=1`.
- On non-Wayland Linux, if portal registration is unavailable, Dialtone falls back to direct hotkey registration.

### Create initial invite

```bash
curl -s -X POST http://localhost:8080/server/invites \
  -H "X-Admin-Token: $DIALTONE_ADMIN_TOKEN"
```

#### From within the dialtone docker container using curl:
```bash
export $(grep -v '^#' .env | xargs)

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
