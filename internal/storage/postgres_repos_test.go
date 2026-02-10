package storage

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/Avicted/dialtone/internal/channel"
	"github.com/Avicted/dialtone/internal/device"
	"github.com/Avicted/dialtone/internal/message"
	"github.com/Avicted/dialtone/internal/serverinvite"
	"github.com/Avicted/dialtone/internal/user"
)

func setupPostgresStore(t *testing.T) (*PostgresStore, func()) {
	t.Helper()

	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "dialtone",
			"POSTGRES_PASSWORD": "dialtone",
			"POSTGRES_DB":       "dialtone",
		},
		WaitingFor: wait.ForListeningPort("5432/tcp"),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("start postgres: %v", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		_ = container.Terminate(ctx)
		t.Fatalf("postgres host: %v", err)
	}
	port, err := container.MappedPort(ctx, "5432/tcp")
	if err != nil {
		_ = container.Terminate(ctx)
		t.Fatalf("postgres port: %v", err)
	}
	conn := fmt.Sprintf("postgres://dialtone:dialtone@%s:%s/dialtone?sslmode=disable", host, port.Port())

	store, err := NewPostgresStore(ctx, conn)
	if err != nil {
		_ = container.Terminate(ctx)
		t.Fatalf("init store: %v", err)
	}
	if err := store.Migrate(ctx); err != nil {
		_ = store.Close(ctx)
		_ = container.Terminate(ctx)
		t.Fatalf("migrate: %v", err)
	}

	cleanup := func() {
		_ = store.Close(context.Background())
		_ = container.Terminate(context.Background())
	}
	return store, cleanup
}

func TestPostgresUserRepo(t *testing.T) {
	store, cleanup := setupPostgresStore(t)
	defer cleanup()

	repo := store.Users()
	deviceRepo := store.Devices()

	u := user.User{
		ID:           "user-1",
		UsernameHash: "hash-1",
		PasswordHash: "pw",
		IsAdmin:      true,
		IsTrusted:    true,
		CreatedAt:    time.Now().UTC(),
	}
	if err := repo.Create(context.Background(), u); err != nil {
		t.Fatalf("create user: %v", err)
	}
	if _, err := repo.GetByID(context.Background(), u.ID); err != nil {
		t.Fatalf("get user: %v", err)
	}
	if _, err := repo.GetByUsernameHash(context.Background(), u.UsernameHash); err != nil {
		t.Fatalf("get user by hash: %v", err)
	}
	if count, err := repo.Count(context.Background()); err != nil || count != 1 {
		t.Fatalf("count users = %d, err = %v", count, err)
	}

	profile := user.Profile{UserID: u.ID, NameEnc: "enc-name", UpdatedAt: time.Now().UTC()}
	if err := repo.UpsertProfile(context.Background(), profile); err != nil {
		t.Fatalf("upsert profile: %v", err)
	}
	profiles, err := repo.ListProfiles(context.Background())
	if err != nil {
		t.Fatalf("list profiles: %v", err)
	}
	if len(profiles) != 1 {
		t.Fatalf("profiles = %d, want 1", len(profiles))
	}

	if err := deviceRepo.Create(context.Background(), device.Device{
		ID:        "dev-1",
		UserID:    u.ID,
		PublicKey: "pub",
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create device: %v", err)
	}

	env := user.DirectoryKeyEnvelope{
		DeviceID:        "dev-1",
		SenderDeviceID:  "dev-1",
		SenderPublicKey: "pub",
		Envelope:        "env",
		CreatedAt:       time.Now().UTC(),
	}
	if err := repo.UpsertDirectoryKeyEnvelope(context.Background(), env); err != nil {
		t.Fatalf("upsert directory envelope: %v", err)
	}
	if _, err := repo.GetDirectoryKeyEnvelope(context.Background(), env.DeviceID); err != nil {
		t.Fatalf("get directory envelope: %v", err)
	}
}

func TestPostgresDeviceRepo(t *testing.T) {
	store, cleanup := setupPostgresStore(t)
	defer cleanup()

	userRepo := store.Users()
	deviceRepo := store.Devices()

	u := user.User{ID: "user-1", UsernameHash: "hash-1", CreatedAt: time.Now().UTC()}
	if err := userRepo.Create(context.Background(), u); err != nil {
		t.Fatalf("create user: %v", err)
	}

	d := device.Device{ID: "dev-1", UserID: u.ID, PublicKey: "pub", CreatedAt: time.Now().UTC()}
	if err := deviceRepo.Create(context.Background(), d); err != nil {
		t.Fatalf("create device: %v", err)
	}
	if _, err := deviceRepo.GetByID(context.Background(), d.ID); err != nil {
		t.Fatalf("get device: %v", err)
	}
	if _, err := deviceRepo.GetByUserAndPublicKey(context.Background(), u.ID, d.PublicKey); err != nil {
		t.Fatalf("get device by user/key: %v", err)
	}
	if list, err := deviceRepo.ListByUser(context.Background(), u.ID); err != nil || len(list) != 1 {
		t.Fatalf("list by user = %d, err = %v", len(list), err)
	}
	if list, err := deviceRepo.ListAll(context.Background()); err != nil || len(list) != 1 {
		t.Fatalf("list all = %d, err = %v", len(list), err)
	}
	if err := deviceRepo.UpdateLastSeen(context.Background(), d.ID, time.Now().UTC()); err != nil {
		t.Fatalf("update last seen: %v", err)
	}
}

func TestPostgresChannelRepo(t *testing.T) {
	store, cleanup := setupPostgresStore(t)
	defer cleanup()

	userRepo := store.Users()
	deviceRepo := store.Devices()
	channelRepo := store.Channels()

	u := user.User{ID: "user-1", UsernameHash: "hash-1", CreatedAt: time.Now().UTC()}
	if err := userRepo.Create(context.Background(), u); err != nil {
		t.Fatalf("create user: %v", err)
	}

	d := device.Device{ID: "dev-1", UserID: u.ID, PublicKey: "pub", CreatedAt: time.Now().UTC()}
	if err := deviceRepo.Create(context.Background(), d); err != nil {
		t.Fatalf("create device: %v", err)
	}

	ch := channel.Channel{ID: "ch-1", NameEnc: "enc", CreatedBy: u.ID, CreatedAt: time.Now().UTC()}
	if err := channelRepo.CreateChannel(context.Background(), ch); err != nil {
		t.Fatalf("create channel: %v", err)
	}
	if _, err := channelRepo.GetChannel(context.Background(), ch.ID); err != nil {
		t.Fatalf("get channel: %v", err)
	}
	if list, err := channelRepo.ListChannels(context.Background()); err != nil || len(list) != 1 {
		t.Fatalf("list channels = %d, err = %v", len(list), err)
	}
	if err := channelRepo.UpdateChannelName(context.Background(), ch.ID, "enc2"); err != nil {
		t.Fatalf("update channel: %v", err)
	}

	msg := channel.Message{
		ID:            "msg-1",
		ChannelID:     ch.ID,
		SenderID:      u.ID,
		SenderNameEnc: "enc-sender",
		Body:          "enc-body",
		SentAt:        time.Now().UTC(),
	}
	if err := channelRepo.SaveMessage(context.Background(), msg); err != nil {
		t.Fatalf("save message: %v", err)
	}
	if list, err := channelRepo.ListRecentMessages(context.Background(), ch.ID, 10); err != nil || len(list) != 1 {
		t.Fatalf("list messages = %d, err = %v", len(list), err)
	}

	env := channel.KeyEnvelope{
		ChannelID:       ch.ID,
		DeviceID:        d.ID,
		SenderDeviceID:  d.ID,
		SenderPublicKey: "pub",
		Envelope:        "env",
		CreatedAt:       time.Now().UTC(),
	}
	if err := channelRepo.UpsertKeyEnvelope(context.Background(), env); err != nil {
		t.Fatalf("upsert key envelope: %v", err)
	}
	if _, err := channelRepo.GetKeyEnvelope(context.Background(), ch.ID, d.ID); err != nil {
		t.Fatalf("get key envelope: %v", err)
	}

	if err := channelRepo.DeleteChannel(context.Background(), ch.ID); err != nil {
		t.Fatalf("delete channel: %v", err)
	}
}

func TestPostgresBroadcastRepo(t *testing.T) {
	store, cleanup := setupPostgresStore(t)
	defer cleanup()

	userRepo := store.Users()
	broadcastRepo := store.Broadcasts()

	u := user.User{ID: "user-1", UsernameHash: "hash-1", CreatedAt: time.Now().UTC()}
	if err := userRepo.Create(context.Background(), u); err != nil {
		t.Fatalf("create user: %v", err)
	}

	msg := message.BroadcastMessage{
		ID:              "b-1",
		SenderID:        u.ID,
		SenderNameEnc:   "enc-name",
		SenderPublicKey: "pub",
		Body:            "enc-body",
		Envelopes:       map[string]string{"dev-1": "env"},
		SentAt:          time.Now().UTC(),
	}
	if err := broadcastRepo.Save(context.Background(), msg); err != nil {
		t.Fatalf("save broadcast: %v", err)
	}
	if list, err := broadcastRepo.ListRecent(context.Background(), 10); err != nil || len(list) != 1 {
		t.Fatalf("list broadcasts = %d, err = %v", len(list), err)
	}
}

func TestPostgresServerInviteRepo(t *testing.T) {
	store, cleanup := setupPostgresStore(t)
	defer cleanup()

	repo := store.ServerInvites()

	invite := serverinvite.Invite{Token: "inv-1", CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(1 * time.Hour)}
	if err := repo.Create(context.Background(), invite); err != nil {
		t.Fatalf("create invite: %v", err)
	}
	if _, err := repo.Consume(context.Background(), invite.Token, "user-1", time.Now().UTC()); err != nil {
		t.Fatalf("consume invite: %v", err)
	}

	expired := serverinvite.Invite{Token: "inv-2", CreatedAt: time.Now().Add(-2 * time.Hour), ExpiresAt: time.Now().Add(-1 * time.Hour)}
	if err := repo.Create(context.Background(), expired); err != nil {
		t.Fatalf("create expired invite: %v", err)
	}
	if _, err := repo.Consume(context.Background(), expired.Token, "user-1", time.Now().UTC()); !errors.Is(err, serverinvite.ErrExpired) {
		t.Fatalf("consume expired invite error = %v", err)
	}
}
