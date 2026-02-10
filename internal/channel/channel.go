package channel

import (
	"context"
	"errors"
	"time"

	"github.com/Avicted/dialtone/internal/user"
)

type ID string

type Channel struct {
	ID        ID
	NameEnc   string
	CreatedBy user.ID
	CreatedAt time.Time
}

type Message struct {
	ID            string
	ChannelID     ID
	SenderID      user.ID
	SenderNameEnc string
	Body          string
	SentAt        time.Time
}

var (
	ErrNotFound     = errors.New("not found")
	ErrInvalidInput = errors.New("invalid input")
	ErrForbidden    = errors.New("forbidden")
)

type Repository interface {
	CreateChannel(ctx context.Context, ch Channel) error
	GetChannel(ctx context.Context, id ID) (Channel, error)
	ListChannels(ctx context.Context) ([]Channel, error)
	UpdateChannelName(ctx context.Context, id ID, nameEnc string) error
	DeleteChannel(ctx context.Context, id ID) error
	SaveMessage(ctx context.Context, msg Message) error
	ListRecentMessages(ctx context.Context, channelID ID, limit int) ([]Message, error)
}
