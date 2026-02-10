package channel

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Avicted/dialtone/internal/device"
	"github.com/Avicted/dialtone/internal/user"
)

type fakeRepo struct {
	channel  Channel
	messages []Message
	keyEnv   KeyEnvelope
	limit    int
}

func (r *fakeRepo) CreateChannel(_ context.Context, ch Channel) error {
	r.channel = ch
	return nil
}

func (r *fakeRepo) GetChannel(_ context.Context, id ID) (Channel, error) {
	if r.channel.ID == id {
		return r.channel, nil
	}
	return Channel{}, ErrNotFound
}

func (r *fakeRepo) ListChannels(_ context.Context) ([]Channel, error) {
	if r.channel.ID == "" {
		return nil, nil
	}
	return []Channel{r.channel}, nil
}

func (r *fakeRepo) UpdateChannelName(_ context.Context, id ID, nameEnc string) error {
	if r.channel.ID != id {
		return ErrNotFound
	}
	r.channel.NameEnc = nameEnc
	return nil
}

func (r *fakeRepo) DeleteChannel(_ context.Context, id ID) error {
	if r.channel.ID != id {
		return ErrNotFound
	}
	r.channel = Channel{}
	return nil
}

func (r *fakeRepo) SaveMessage(_ context.Context, msg Message) error {
	r.messages = append(r.messages, msg)
	return nil
}

func (r *fakeRepo) ListRecentMessages(_ context.Context, _ ID, limit int) ([]Message, error) {
	r.limit = limit
	return r.messages, nil
}

func (r *fakeRepo) UpsertKeyEnvelope(_ context.Context, env KeyEnvelope) error {
	r.keyEnv = env
	return nil
}

func (r *fakeRepo) GetKeyEnvelope(_ context.Context, channelID ID, deviceID device.ID) (KeyEnvelope, error) {
	if r.keyEnv.ChannelID == channelID && r.keyEnv.DeviceID == deviceID {
		return r.keyEnv, nil
	}
	return KeyEnvelope{}, ErrNotFound
}

type fakeUserRepo struct {
	user user.User
}

func (r *fakeUserRepo) Create(_ context.Context, _ user.User) error { return nil }
func (r *fakeUserRepo) GetByID(_ context.Context, id user.ID) (user.User, error) {
	if r.user.ID == id {
		return r.user, nil
	}
	return user.User{}, errors.New("not found")
}
func (r *fakeUserRepo) GetByUsernameHash(_ context.Context, _ string) (user.User, error) {
	return user.User{}, errors.New("not found")
}
func (r *fakeUserRepo) Count(_ context.Context) (int, error)                   { return 0, nil }
func (r *fakeUserRepo) UpsertProfile(_ context.Context, _ user.Profile) error  { return nil }
func (r *fakeUserRepo) ListProfiles(_ context.Context) ([]user.Profile, error) { return nil, nil }
func (r *fakeUserRepo) UpsertDirectoryKeyEnvelope(_ context.Context, _ user.DirectoryKeyEnvelope) error {
	return nil
}
func (r *fakeUserRepo) GetDirectoryKeyEnvelope(_ context.Context, _ string) (user.DirectoryKeyEnvelope, error) {
	return user.DirectoryKeyEnvelope{}, errors.New("not found")
}

func newServiceWithAdmin(isAdmin bool) (*Service, *fakeRepo) {
	repo := &fakeRepo{}
	userRepo := &fakeUserRepo{user: user.User{ID: "admin", IsAdmin: isAdmin}}
	userSvc := user.NewService(userRepo, "pepper")
	svc := NewService(repo, userSvc)
	svc.idGen = func() string { return "ch-1" }
	svc.now = func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	return svc, repo
}

func TestCreateChannel_Admin(t *testing.T) {
	svc, repo := newServiceWithAdmin(true)

	ch, err := svc.CreateChannel(context.Background(), "admin", "enc")
	if err != nil {
		t.Fatalf("CreateChannel() error = %v", err)
	}
	if ch.ID == "" || repo.channel.ID == "" {
		t.Fatal("expected channel to be created")
	}
}

func TestCreateChannel_Forbidden(t *testing.T) {
	svc, _ := newServiceWithAdmin(false)

	_, err := svc.CreateChannel(context.Background(), "admin", "enc")
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected ErrForbidden, got %v", err)
	}
}

func TestUpdateChannelName_Admin(t *testing.T) {
	svc, repo := newServiceWithAdmin(true)

	_, _ = svc.CreateChannel(context.Background(), "admin", "enc")
	if _, err := svc.UpdateChannelName(context.Background(), "admin", "ch-1", "enc2"); err != nil {
		t.Fatalf("UpdateChannelName() error = %v", err)
	}
	if repo.channel.NameEnc != "enc2" {
		t.Fatalf("expected updated name")
	}
}

func TestListMessages_DefaultLimit(t *testing.T) {
	svc, repo := newServiceWithAdmin(true)

	_, _ = svc.CreateChannel(context.Background(), "admin", "enc")
	_, _ = svc.ListMessages(context.Background(), "admin", "ch-1", 0)
	if repo.limit != defaultHistoryLimit {
		t.Fatalf("limit = %d, want %d", repo.limit, defaultHistoryLimit)
	}
}

func TestUpsertKeyEnvelope_SetsTime(t *testing.T) {
	svc, repo := newServiceWithAdmin(true)

	env := KeyEnvelope{ChannelID: "ch-1", DeviceID: "dev-1", SenderDeviceID: "dev-1", SenderPublicKey: "pub", Envelope: "env"}
	if err := svc.UpsertKeyEnvelope(context.Background(), "admin", env); err != nil {
		t.Fatalf("UpsertKeyEnvelope() error = %v", err)
	}
	if repo.keyEnv.CreatedAt.IsZero() {
		t.Fatalf("expected CreatedAt to be set")
	}
}

func TestListChannels_InvalidUser(t *testing.T) {
	svc, _ := newServiceWithAdmin(true)

	_, err := svc.ListChannels(context.Background(), "")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestListChannels_Success(t *testing.T) {
	svc, repo := newServiceWithAdmin(true)

	_, _ = svc.CreateChannel(context.Background(), "admin", "enc")
	channels, err := svc.ListChannels(context.Background(), "admin")
	if err != nil {
		t.Fatalf("ListChannels() error = %v", err)
	}
	if len(channels) != 1 {
		t.Fatalf("ListChannels() returned %d channels, want 1", len(channels))
	}
	if channels[0].ID != repo.channel.ID {
		t.Fatalf("channel ID = %q, want %q", channels[0].ID, repo.channel.ID)
	}
}

func TestGetChannel_InvalidInput(t *testing.T) {
	svc, _ := newServiceWithAdmin(true)

	_, err := svc.GetChannel(context.Background(), "", "ch-1")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestGetChannel_Success(t *testing.T) {
	svc, _ := newServiceWithAdmin(true)

	created, _ := svc.CreateChannel(context.Background(), "admin", "enc")
	got, err := svc.GetChannel(context.Background(), "admin", created.ID)
	if err != nil {
		t.Fatalf("GetChannel() error = %v", err)
	}
	if got.ID != created.ID {
		t.Fatalf("ID = %q, want %q", got.ID, created.ID)
	}
}

func TestDeleteChannel_Admin(t *testing.T) {
	svc, repo := newServiceWithAdmin(true)

	_, _ = svc.CreateChannel(context.Background(), "admin", "enc")
	if err := svc.DeleteChannel(context.Background(), "admin", "ch-1"); err != nil {
		t.Fatalf("DeleteChannel() error = %v", err)
	}
	if repo.channel.ID != "" {
		t.Fatal("expected channel to be deleted")
	}
}

func TestGetKeyEnvelope_InvalidInput(t *testing.T) {
	svc, _ := newServiceWithAdmin(true)

	_, err := svc.GetKeyEnvelope(context.Background(), "", "ch-1", "dev-1")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestGetKeyEnvelope_Found(t *testing.T) {
	svc, repo := newServiceWithAdmin(true)

	repo.keyEnv = KeyEnvelope{
		ChannelID:       "ch-1",
		DeviceID:        "dev-1",
		SenderDeviceID:  "dev-1",
		SenderPublicKey: "pub",
		Envelope:        "env",
	}
	got, err := svc.GetKeyEnvelope(context.Background(), "admin", "ch-1", "dev-1")
	if err != nil {
		t.Fatalf("GetKeyEnvelope() error = %v", err)
	}
	if got.Envelope != "env" {
		t.Fatalf("Envelope = %q, want %q", got.Envelope, "env")
	}
}
